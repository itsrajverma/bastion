"""Tool registry.

Every action Bastion can take is a *named tool* registered here with a typed
schema, a risk level, and a ``plan()`` that renders the exact command or SQL it
will run. There is deliberately no generic command runner (invariant 1).

Usage::

    @tool(risk="write", approve=True, plan="sudo systemctl restart {service}")
    def restart_service(service: Service) -> str:
        \"\"\"Restart a systemd service.\"\"\"
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, get_type_hints

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model

from bastion.core.errors import ValidationFailed
from bastion.core.policy import RISK_ORDER, RISKS, ROLE_RISKS, ROLES, Risk, Role

__all__ = [
    "FORBIDDEN_NAME_RE",
    "REGISTRY",
    "ToolSpec",
    "get_tool",
    "tool",
    "tools_for",
]

REGISTRY: dict[str, ToolSpec] = {}

#: Tool names must never suggest generic or destructive capability. Segments are
#: matched between underscores so that e.g. ``db_terminate_query`` (which merely
#: contains the letters "rm") is fine, while ``rm_files`` or ``exec_cmd`` is not.
FORBIDDEN_NAME_RE = re.compile(
    r"(^|_)(rm|delete|drop|truncate|exec|shell|command|cmd|bash|sh|sudo|eval|purge|wipe|"
    r"format|destroy|remove|unlink|erase)(_|$)",
    re.IGNORECASE,
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,40}$")

_DEFAULT_ROLES: dict[str, tuple[Role, ...]] = {
    "read": ("viewer", "operator", "admin"),
    "write": ("operator", "admin"),
    "admin": ("admin",),
}

PlanFn = Callable[..., str]
Validator = Callable[[Mapping[str, Any]], None]


def _parse_docstring(doc: str | None) -> tuple[str, dict[str, str]]:
    """Return (description, {param: description}) from a Google-style docstring."""
    if not doc:
        return "", {}
    text = inspect.cleandoc(doc)
    head, _, rest = text.partition("\nArgs:")
    if not rest and text.startswith("Args:"):
        head, rest = "", text[len("Args:") :]
    params: dict[str, str] = {}
    current: str | None = None
    for raw in rest.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if re.match(r"^(Returns|Raises|Example|Examples|Note|Notes):", line.strip()):
            current = None
            continue
        m = re.match(r"^\s{0,8}(\w+)(?:\s*\([^)]*\))?:\s*(.*)$", line)
        if m and not line.startswith(" " * 9):
            current = m.group(1)
            params[current] = m.group(2).strip()
        elif current and line.startswith(" "):
            params[current] = (params[current] + " " + line.strip()).strip()
    description = " ".join(part.strip() for part in head.strip().splitlines() if part.strip())
    return description, params


def _strip_titles(schema: Any) -> Any:
    if isinstance(schema, dict):
        return {k: _strip_titles(v) for k, v in schema.items() if k != "title"}
    if isinstance(schema, list):
        return [_strip_titles(v) for v in schema]
    return schema


@dataclass
class ToolSpec:
    """A registered tool: metadata + validation + plan + run."""

    name: str
    risk: Risk
    approve: bool
    roles: tuple[Role, ...]
    description: str
    fn: Callable[..., str]
    model: type[BaseModel]
    plan_fn: PlanFn | None = None
    virtual: bool = False
    verify_with: str | None = None
    validators: list[Validator] = field(default_factory=list)

    # -- schema ------------------------------------------------------------

    def input_schema(self) -> dict[str, Any]:
        raw = self.model.model_json_schema()
        schema = _strip_titles(raw)
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})
        schema["additionalProperties"] = False
        return dict(schema)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "risk": self.risk,
            "approve": self.approve,
            "roles": list(self.roles),
            "virtual": self.virtual,
            "verify_with": self.verify_with,
            "input_schema": self.input_schema(),
        }

    # -- validation ----------------------------------------------------------

    def validate(self, args: Mapping[str, Any] | None) -> dict[str, Any]:
        """Validate untrusted arguments (invariant 4). Returns plain kwargs."""
        data = dict(args or {})
        try:
            parsed = self.model.model_validate(data)
        except ValidationError as exc:
            problems = [
                {"loc": ".".join(str(p) for p in e["loc"]), "msg": e["msg"]} for e in exc.errors()
            ]
            raise ValidationFailed(
                f"invalid arguments for {self.name}", detail={"errors": problems}
            ) from None
        kwargs = parsed.model_dump()
        for check in self.validators:
            check(kwargs)
        return kwargs

    def validator(self, fn: Validator) -> Validator:
        """Register an extra validator run after pydantic (e.g. PID existence)."""
        self.validators.append(fn)
        return fn

    # -- plan / run ------------------------------------------------------------

    def planner(self, fn: PlanFn) -> PlanFn:
        """Attach a plan function ``(**kwargs) -> str``."""
        self.plan_fn = fn
        return fn

    def plan(self, args: Mapping[str, Any] | None = None) -> str:
        kwargs = self.validate(args)
        if self.plan_fn is None:
            return f"{self.name}({', '.join(f'{k}={v!r}' for k, v in kwargs.items())})"
        return self.plan_fn(**kwargs)

    def run(self, args: Mapping[str, Any] | None = None) -> str:
        if self.virtual:
            raise ValidationFailed(f"{self.name} is a virtual tool and cannot be executed")
        kwargs = self.validate(args)
        return self.fn(**kwargs)

    def __call__(self, **kwargs: Any) -> str:
        return self.run(kwargs)


def _build_model(name: str, fn: Callable[..., Any], param_docs: dict[str, str]) -> type[BaseModel]:
    sig = inspect.signature(fn)
    hints = get_type_hints(fn, include_extras=True)
    fields: dict[str, Any] = {}
    for pname, param in sig.parameters.items():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            raise TypeError(f"tool {name}: *args/**kwargs are not allowed")
        if pname not in hints:
            raise TypeError(f"tool {name}: parameter {pname!r} needs a type annotation")
        annotation = hints[pname]
        default = ... if param.default is inspect.Parameter.empty else param.default
        fields[pname] = (
            annotation,
            Field(default, description=param_docs.get(pname, "")),
        )
    model_name = "".join(part.capitalize() for part in name.split("_")) + "Input"
    return create_model(
        model_name,
        __config__=ConfigDict(extra="forbid", strict=False),
        **fields,
    )


def tool(
    *,
    risk: Risk,
    approve: bool = False,
    roles: Iterable[str] | None = None,
    plan: str | PlanFn | None = None,
    verify_with: str | None = None,
    virtual: bool = False,
    name: str | None = None,
) -> Callable[[Callable[..., str]], ToolSpec]:
    """Register a function as a Bastion tool.

    Args:
        risk: ``read`` | ``write`` | ``admin``. Anything above ``read`` requires
            ``approve=True``.
        approve: whether a human must approve each call.
        roles: roles that may call it. Defaults to every role whose ceiling covers ``risk``.
        plan: a format string (``"sudo systemctl restart {service}"``) or a callable
            ``(**kwargs) -> str`` rendering the exact command/SQL.
        verify_with: name of a read tool the CLI re-runs after this tool succeeds.
        virtual: the tool is handled by the CLI (e.g. ``ask_user``) and never executed
            by the executor.
        name: override the registered name (defaults to the function name).
    """
    if risk not in RISKS:
        raise ValueError(f"unknown risk {risk!r}; expected one of {RISKS}")
    if risk != "read" and not approve:
        raise ValueError(f"{risk} tools must set approve=True")
    resolved_roles: tuple[Role, ...] = (
        tuple(r for r in ROLES if r in set(roles)) if roles is not None else _DEFAULT_ROLES[risk]
    )
    if roles is not None:
        unknown = set(roles) - set(ROLES)
        if unknown:
            raise ValueError(f"unknown roles {sorted(unknown)}; expected {ROLES}")
    for role in resolved_roles:
        if risk not in ROLE_RISKS[role]:
            raise ValueError(f"role {role!r} cannot be granted a {risk!r} tool")

    def decorator(fn: Callable[..., str]) -> ToolSpec:
        tool_name = name or fn.__name__
        if not _NAME_RE.match(tool_name):
            raise ValueError(f"invalid tool name {tool_name!r}")
        if FORBIDDEN_NAME_RE.search(tool_name):
            raise ValueError(f"tool name {tool_name!r} suggests a forbidden capability")
        if tool_name in REGISTRY:
            raise ValueError(f"tool {tool_name!r} is already registered")
        description, param_docs = _parse_docstring(fn.__doc__)
        if not description:
            raise ValueError(f"tool {tool_name!r} needs a docstring")
        model = _build_model(tool_name, fn, param_docs)
        plan_fn: PlanFn | None
        if isinstance(plan, str):
            template = plan

            def plan_fn(**kwargs: Any) -> str:
                return template.format(**kwargs)

        else:
            plan_fn = plan
        spec = ToolSpec(
            name=tool_name,
            risk=risk,
            approve=approve,
            roles=resolved_roles,
            description=description,
            fn=fn,
            model=model,
            plan_fn=plan_fn,
            virtual=virtual,
            verify_with=verify_with,
        )
        REGISTRY[tool_name] = spec
        return spec

    return decorator


def get_tool(name: str) -> ToolSpec | None:
    return REGISTRY.get(name)


def tools_for(role: str, enabled_risks: Iterable[str]) -> list[ToolSpec]:
    """Tools visible to ``role`` on an executor with ``enabled_risks`` (default deny)."""
    enabled = set(enabled_risks)
    out = [
        spec
        for spec in REGISTRY.values()
        if spec.risk in enabled and role in spec.roles and spec.risk in ROLE_RISKS.get(role, ())
    ]
    return sorted(out, key=lambda s: (RISK_ORDER[s.risk], s.name))


def sorted_registry() -> list[ToolSpec]:
    return sorted(REGISTRY.values(), key=lambda s: (RISK_ORDER[s.risk], s.name))


# Import tool modules so that importing ``bastion.tools`` populates REGISTRY.
from bastion.tools import (  # noqa: E402  (registration side effects)
    postgres,
    process,
    services,
    system,
    virtual,
    web,
)

__all__ += ["postgres", "process", "services", "sorted_registry", "system", "virtual", "web"]
