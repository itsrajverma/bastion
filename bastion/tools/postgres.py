"""PostgreSQL tools.

Data minimisation (invariant 10): these tools return query *text* and metadata
from ``pg_stat_activity`` only. No tool here can read rows from user tables.
Protection (invariant 5): the cancel/terminate guards are baked into the SQL
``WHERE`` clause, so the LLM cannot talk its way around them.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from bastion.core.errors import ProtectedTarget, ToolExecutionError
from bastion.tools import tool
from bastion.tools._context import require_postgres_dsn
from bastion.tools._types import Pid, QueryLimit

STATEMENT_TIMEOUT_MS = 10_000

ACTIVE_QUERIES_SQL = """
SELECT pid,
       usename,
       state,
       wait_event_type,
       date_trunc('second', now() - query_start) AS age,
       left(regexp_replace(query, '\\s+', ' ', 'g'), 300) AS query
FROM pg_stat_activity
WHERE backend_type = 'client backend'
  AND pid <> pg_backend_pid()
  AND state <> 'idle'
ORDER BY query_start NULLS LAST
LIMIT %s
""".strip()

LOCKS_SQL = """
SELECT a.pid,
       a.usename,
       a.state,
       a.wait_event_type,
       pg_blocking_pids(a.pid) AS blocked_by,
       date_trunc('second', now() - a.query_start) AS age,
       left(regexp_replace(a.query, '\\s+', ' ', 'g'), 300) AS query
FROM pg_stat_activity a
WHERE cardinality(pg_blocking_pids(a.pid)) > 0
   OR a.pid IN (SELECT unnest(pg_blocking_pids(b.pid)) FROM pg_stat_activity b)
ORDER BY a.query_start NULLS LAST
LIMIT 50
""".strip()


def _connect() -> Any:
    dsn = require_postgres_dsn()
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - depends on extras
        raise ToolExecutionError("psycopg is not installed; install bastion[executor]") from exc
    try:
        return psycopg.connect(
            dsn,
            connect_timeout=5,
            application_name="bastion",
            options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
            autocommit=True,
        )
    except psycopg.Error as exc:
        raise ToolExecutionError(f"postgres connection failed: {exc.__class__.__name__}") from exc


def query(sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
    """Run one read-only statement and return its rows. Tests monkeypatch this."""
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(sql, tuple(params))
            if cur.description is None:
                return []
            return [tuple(row) for row in cur.fetchall()]
    except ToolExecutionError:
        raise
    except Exception as exc:  # psycopg errors; never leak connection details
        raise ToolExecutionError(f"postgres query failed: {exc.__class__.__name__}") from exc


def _render(rows: list[tuple[Any, ...]], headers: Sequence[str]) -> str:
    if not rows:
        return "(no rows)"
    out = ["  ".join(headers)]
    for row in rows:
        out.append("  ".join(str(c) if c is not None else "-" for c in row))
    return "\n".join(out)


@tool(risk="read", plan=lambda limit: ACTIVE_QUERIES_SQL.replace("%s", str(limit)))
def db_active_queries(limit: QueryLimit = 10) -> str:
    """List non-idle PostgreSQL backends: pid, user, state, wait event, age, and query text.

    Returns query text only, never result rows. Use the pid with db_cancel_query.

    Args:
        limit: max backends to show (1-20).
    """
    rows = query(ACTIVE_QUERIES_SQL, (limit,))
    return _render(rows, ["pid", "user", "state", "wait", "age", "query"])


@tool(risk="read", plan=lambda: LOCKS_SQL)
def db_locks() -> str:
    """Show PostgreSQL lock chains: which backends are blocked and by whom (pg_blocking_pids)."""
    rows = query(LOCKS_SQL)
    return _render(rows, ["pid", "user", "state", "wait", "blocked_by", "age", "query"])


# Guards live in the WHERE clause (invariant 5): only client backends, never
# replication users, never our own connection. If the guard filters the row out,
# nothing is signalled and the tool reports a protected target.
_SIGNAL_SQL = r"""
SELECT {func}(a.pid) AS done, a.pid, a.usename, a.state,
       left(regexp_replace(a.query, '\s+', ' ', 'g'), 120) AS query
FROM pg_stat_activity a
WHERE a.pid = %s
  AND a.backend_type = 'client backend'
  AND a.pid <> pg_backend_pid()
  AND a.usename IS NOT NULL
  AND a.usename NOT IN (SELECT rolname FROM pg_roles WHERE rolreplication)
""".strip()

CANCEL_SQL = _SIGNAL_SQL.format(func="pg_cancel_backend")
TERMINATE_SQL = _SIGNAL_SQL.format(func="pg_terminate_backend")


def _signal_backend(sql: str, pid: int, verb: str) -> str:
    rows = query(sql, (pid,))
    if not rows:
        raise ProtectedTarget(
            f"backend {pid} was not {verb}: it does not exist, is not a client backend, "
            "or belongs to a replication user"
        )
    done, bpid, user, state, text = rows[0][:5]
    return f"{verb}: {done}\npid: {bpid}  user: {user}  state: {state}\nquery: {text}"


@tool(
    risk="write",
    approve=True,
    plan=lambda pid: CANCEL_SQL.replace("%s", str(pid)),
    verify_with="db_active_queries",
)
def db_cancel_query(pid: Pid) -> str:
    """Cancel the running statement of one PostgreSQL backend (pg_cancel_backend).

    The connection stays open; only the current query is interrupted. Gentlest DB
    fix. Refuses non-client backends and replication users. Requires approval.

    Args:
        pid: backend pid from db_active_queries or db_locks.
    """
    return _signal_backend(CANCEL_SQL, pid, "cancelled")


@tool(
    risk="admin",
    approve=True,
    plan=lambda pid: TERMINATE_SQL.replace("%s", str(pid)),
    verify_with="db_active_queries",
)
def db_terminate_query(pid: Pid) -> str:
    """Terminate one PostgreSQL client backend (pg_terminate_backend), closing its connection.

    Use only when db_cancel_query did not help. Refuses non-client backends and
    replication users. Admin role and approval required.

    Args:
        pid: backend pid from db_active_queries or db_locks.
    """
    return _signal_backend(TERMINATE_SQL, pid, "terminated")
