"""The executor: a small FastAPI app that is the only thing allowed to touch the host.

Endpoints
    GET  /health            liveness (no auth)
    GET  /tools             tools visible to the caller (role x enabled_risks)
    POST /plan              render the exact command/SQL; never executes
    POST /run               validate, guard, execute, redact, audit
    GET  /audit?n=20        tail of the hash-chained audit log
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from bastion import __version__
from bastion.core import policy
from bastion.core.audit import AuditLog, sha256_hex
from bastion.core.errors import (
    BastionError,
    PolicyDenied,
    ToolNotFound,
    ValidationFailed,
    error_payload,
)
from bastion.core.redact import redact
from bastion.executor.auth import Principal, authenticate
from bastion.executor.config import ExecutorSettings, load_settings
from bastion.tools import REGISTRY, ToolSpec, tools_for
from bastion.tools._context import ToolContext, set_context

log = logging.getLogger("bastion.executor")

TOOL_NAME_PATTERN = r"^[a-z][a-z0-9_]{2,40}$"


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(pattern=TOOL_NAME_PATTERN)
    args: dict[str, Any] = Field(default_factory=dict)


class RunRequest(ToolRequest):
    #: For approval-gated tools the client must echo the SHA-256 of the plan it
    #: showed the operator. This proves the exact command was displayed and
    #: that nothing changed between /plan and /run.
    approved_plan_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


def create_app(settings: ExecutorSettings, audit: AuditLog | None = None) -> FastAPI:
    set_context(
        ToolContext(postgres_dsn=settings.postgres_dsn, certbot_email=settings.certbot_email)
    )
    audit_log = audit or AuditLog(settings.audit_path)
    app = FastAPI(title="bastion-executor", version=__version__, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.audit = audit_log

    # -- errors: structured JSON, never a traceback ---------------------------

    @app.exception_handler(BastionError)
    async def _bastion_error(_: Request, exc: BastionError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content=exc.to_payload())

    @app.exception_handler(RequestValidationError)
    async def _request_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [
            {"loc": ".".join(str(p) for p in e.get("loc", ())), "msg": str(e.get("msg", ""))}
            for e in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_failed",
                "message": "invalid request",
                "detail": {"errors": problems},
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error: %s", exc.__class__.__name__)
        return JSONResponse(status_code=500, content=error_payload(exc))

    # -- auth -----------------------------------------------------------------

    def principal(request: Request) -> Principal:
        return authenticate(settings, request.headers.get("authorization"))

    # -- helpers --------------------------------------------------------------

    def resolve(name: str, who: Principal) -> ToolSpec:
        spec = REGISTRY.get(name)
        if spec is None:
            raise ToolNotFound(f"unknown tool {name!r}")
        decision = policy.check(who.role, spec.risk, settings.enabled_risks)
        if not decision:
            raise PolicyDenied(decision.reason)
        if who.role not in spec.roles:
            raise PolicyDenied(f"role {who.role!r} may not call {name}")
        return spec

    # -- routes ---------------------------------------------------------------

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "enabled_risks": list(settings.enabled_risks),
        }

    @app.get("/tools")
    def list_tools(who: Principal = Depends(principal)) -> dict[str, Any]:  # noqa: B008
        visible = tools_for(who.role, settings.enabled_risks)
        return {
            "user": who.name,
            "role": who.role,
            "enabled_risks": list(settings.enabled_risks),
            "tools": [spec.describe() for spec in visible],
        }

    @app.post("/plan")
    def plan(req: ToolRequest, who: Principal = Depends(principal)) -> dict[str, Any]:  # noqa: B008
        spec = resolve(req.tool, who)
        rendered = spec.plan(req.args)
        return {
            "tool": spec.name,
            "risk": spec.risk,
            "approve": spec.approve,
            "plan": rendered,
            "plan_hash": sha256_hex(rendered),
        }

    @app.post("/run")
    def run_tool(req: RunRequest, who: Principal = Depends(principal)) -> dict[str, Any]:  # noqa: B008
        spec = resolve(req.tool, who)
        if spec.virtual:
            raise ValidationFailed(f"{spec.name} is answered by the CLI, not executed here")
        kwargs = spec.validate(req.args)
        rendered = spec.plan(kwargs)
        if spec.approve:
            expected = sha256_hex(rendered)
            if req.approved_plan_hash != expected:
                raise PolicyDenied(
                    f"{spec.name} requires approval: call /plan, show the plan to the "
                    "operator, and echo its plan_hash as approved_plan_hash"
                )
        started = time.monotonic()
        try:
            raw = spec.run(kwargs)
        except BastionError as exc:
            audit_log.append(
                user=who.name,
                tool=spec.name,
                args=_jsonable(kwargs),
                plan=rendered,
                result=f"{exc.code}: {exc.message}",
                status="error",
            )
            raise
        except Exception as exc:
            audit_log.append(
                user=who.name,
                tool=spec.name,
                args=_jsonable(kwargs),
                plan=rendered,
                result=f"internal_error: {exc.__class__.__name__}",
                status="error",
            )
            raise
        elapsed_ms = int((time.monotonic() - started) * 1000)
        result = redact(raw)
        if len(result) > settings.max_result_chars:
            result = result[: settings.max_result_chars] + "\n...[truncated]"
        record = audit_log.append(
            user=who.name,
            tool=spec.name,
            args=_jsonable(kwargs),
            plan=rendered,
            result=result,
        )
        return {
            "tool": spec.name,
            "risk": spec.risk,
            "plan": rendered,
            "result": result,
            "result_hash": record.result_hash,
            "audit_hash": record.hash,
            "elapsed_ms": elapsed_ms,
        }

    @app.get("/audit")
    def audit_tail(
        n: int = Query(default=20, ge=1, le=1000),
        who: Principal = Depends(principal),  # noqa: B008
    ) -> dict[str, Any]:
        verification = audit_log.verify()
        return {
            "user": who.name,
            "records": audit_log.tail(n),
            "verified": verification.ok,
            "verify_reason": verification.reason,
            "total": verification.records,
        }

    return app


def _jsonable(kwargs: Mapping[str, Any]) -> dict[str, Any]:
    return {
        k: (v if isinstance(v, str | int | float | bool | None) else str(v))
        for k, v in kwargs.items()
    }


def run() -> None:
    """``bastion-executor`` entry point."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    settings = load_settings()
    app = create_app(settings)
    log.info(
        "bastion-executor %s listening on %s (enabled_risks=%s, users=%d)",
        __version__,
        settings.bind,
        ",".join(settings.enabled_risks),
        len(settings.tokens),
    )
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        server_header=False,
        date_header=False,
        access_log=False,
    )
