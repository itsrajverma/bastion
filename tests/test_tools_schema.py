"""Every tool is typed, documented, planned, and safely named (invariants 1, 3, 4)."""

from __future__ import annotations

import json
import re

import pytest

from bastion.core.errors import ValidationFailed
from bastion.core.policy import RISKS, ROLE_RISKS
from bastion.tools import FORBIDDEN_NAME_RE, REGISTRY, ToolSpec, tool, tools_for

FORBIDDEN_IN_NAME = re.compile(r"(^|_)(rm|delete|drop|truncate|exec|shell|command)(_|$)", re.I)

EXPECTED_READ = {
    "load_avg",
    "top_processes",
    "process_detail",
    "disk_usage",
    "memory",
    "io_top",
    "connections",
    "service_status",
    "service_logs",
    "nginx_test",
    "db_active_queries",
    "db_locks",
    "ask_user",
}


def test_registry_has_read_tools() -> None:
    assert EXPECTED_READ <= set(REGISTRY)


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_tool_is_complete(name: str) -> None:
    spec = REGISTRY[name]
    assert isinstance(spec, ToolSpec)
    assert spec.risk in RISKS
    assert spec.description and len(spec.description) > 10
    assert spec.roles, "tool must grant at least one role"
    for role in spec.roles:
        assert spec.risk in ROLE_RISKS[role]
    if spec.risk != "read":
        assert spec.approve, f"{name}: non-read tools must require approval"
    schema = spec.input_schema()
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert "properties" in schema
    json.dumps(schema)  # must be serialisable for providers
    described = spec.describe()
    assert described["name"] == name
    assert described["input_schema"] == schema


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_tool_name_is_safe(name: str) -> None:
    assert not FORBIDDEN_IN_NAME.search(name), name
    assert not FORBIDDEN_NAME_RE.search(name), name
    assert re.match(r"^[a-z][a-z0-9_]+$", name)


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_tool_has_plan(name: str) -> None:
    spec = REGISTRY[name]
    assert spec.plan_fn is not None, f"{name}: every tool must render an explicit plan"
    if name in EXPECTED_READ and not spec.input_schema()["properties"]:
        plan = spec.plan({})
        assert plan.strip()


def test_no_destructive_tools() -> None:
    """Invariant 3: nothing in the registry can delete, drop, truncate, or kill -9."""
    banned = re.compile(r"(rm -rf|rm -f|drop table|truncate|kill -9|docker rm|delete from)", re.I)
    for spec in REGISTRY.values():
        text = spec.description + " " + spec.name
        assert not banned.search(text), f"{spec.name} mentions a destructive action: {text[:80]}"


def test_no_generic_command_tool() -> None:
    for banned in ("run_command", "bash", "exec", "shell", "command", "sh"):
        assert banned not in REGISTRY


def test_extra_args_rejected() -> None:
    with pytest.raises(ValidationFailed):
        REGISTRY["load_avg"].validate({"extra": 1})


def test_limit_bounds() -> None:
    spec = REGISTRY["top_processes"]
    assert spec.validate({"limit": 25}) == {"limit": 25}
    with pytest.raises(ValidationFailed):
        spec.validate({"limit": 26})
    with pytest.raises(ValidationFailed):
        spec.validate({"limit": 0})
    assert spec.validate({}) == {"limit": 10}
    logs = REGISTRY["service_logs"]
    with pytest.raises(ValidationFailed):
        logs.validate({"service": "nginx", "lines": 501})
    with pytest.raises(ValidationFailed):
        REGISTRY["db_active_queries"].validate({"limit": 21})


def test_service_enum() -> None:
    spec = REGISTRY["service_status"]
    assert spec.validate({"service": "nginx"}) == {"service": "nginx"}
    for bad in ("sshd", "nginx; rm -rf /", "", "NGINX", "../etc"):
        with pytest.raises(ValidationFailed):
            spec.validate({"service": bad})
    enum = spec.input_schema()["properties"]["service"]["enum"]
    assert set(enum) == {"nginx", "gunicorn", "celery", "postgresql"}


def test_pid_validation_rejects_garbage() -> None:
    spec = REGISTRY["process_detail"]
    for bad in (-1, 0, "abc", 1e12, None, "1; kill -9 1"):
        with pytest.raises(ValidationFailed):
            spec.validate({"pid": bad})


def test_pid_must_exist() -> None:
    spec = REGISTRY["process_detail"]
    with pytest.raises(ValidationFailed, match="no process"):
        spec.validate({"pid": 4_194_303})


def test_plan_renders_exact_command() -> None:
    assert REGISTRY["service_logs"].plan({"service": "nginx", "lines": 50}) == (
        "journalctl -u nginx -n 50 --no-pager -o short-iso"
    )
    assert (
        REGISTRY["service_status"]
        .plan({"service": "celery"})
        .startswith("systemctl is-active celery")
    )
    assert REGISTRY["nginx_test"].plan({}) == "sudo nginx -t"
    assert "LIMIT 5" in REGISTRY["db_active_queries"].plan({"limit": 5})


def test_virtual_tool_cannot_run() -> None:
    spec = REGISTRY["ask_user"]
    assert spec.virtual
    with pytest.raises(ValidationFailed):
        spec.run({"question": "which pid?"})


def test_tools_for_default_deny() -> None:
    names = {s.name for s in tools_for("admin", ("read",))}
    assert names == {s.name for s in REGISTRY.values() if s.risk == "read"}
    assert all(s.risk == "read" for s in tools_for("viewer", ("read", "write", "admin")))
    assert tools_for("viewer", ("write",)) == []


def test_decorator_rejects_bad_definitions() -> None:
    with pytest.raises(ValueError, match="forbidden"):

        @tool(risk="read", plan="x")
        def rm_files() -> str:
            """Remove files."""
            return ""

    with pytest.raises(ValueError, match="forbidden"):

        @tool(risk="read", plan="x")
        def exec_something() -> str:
            """Run things."""
            return ""

    with pytest.raises(ValueError, match="approve"):

        @tool(risk="write", plan="x")
        def bump_thing() -> str:
            """Write without approval is not allowed."""
            return ""

    with pytest.raises(ValueError, match="docstring"):

        @tool(risk="read", plan="x")
        def undocumented() -> str:
            return ""

    with pytest.raises(ValueError, match="cannot be granted"):

        @tool(risk="admin", approve=True, roles=["viewer"], plan="x")
        def too_generous() -> str:
            """Viewer must never get admin."""
            return ""

    with pytest.raises(TypeError, match="annotation"):

        @tool(risk="read", plan="x")
        def untyped(x) -> str:  # type: ignore[no-untyped-def]
            """Untyped parameter."""
            return ""

    for junk in ("rm_files", "exec_something", "bump_thing", "undocumented", "too_generous"):
        assert junk not in REGISTRY


def test_docstring_param_descriptions_reach_schema() -> None:
    props = REGISTRY["service_logs"].input_schema()["properties"]
    assert "lines" in props["lines"]["description"].lower() or props["lines"]["description"]
    assert props["service"]["description"]


def test_docs_generation_is_deterministic() -> None:
    from bastion.tools.__main__ import render_docs

    a = render_docs()
    b = render_docs()
    assert a == b
    assert "## `load_avg`" in a
    for name in REGISTRY:
        assert f"`{name}`" in a
