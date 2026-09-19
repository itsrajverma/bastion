"""HTTP client for the executor API (the laptop side of the trust boundary)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from bastion.core.errors import ExecutorError

DEFAULT_TIMEOUT = 90.0
#: ``/run`` may block on a long action (package installs take minutes), so reads
#: get a longer budget; the executor still enforces per-command timeouts.
RUN_TIMEOUT = 900.0


@dataclass(frozen=True, slots=True)
class RemoteTool:
    name: str
    description: str
    risk: str
    approve: bool
    virtual: bool
    verify_with: str | None
    input_schema: dict[str, Any]
    roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlanInfo:
    tool: str
    risk: str
    approve: bool
    plan: str
    plan_hash: str


@dataclass(frozen=True, slots=True)
class RunInfo:
    tool: str
    risk: str
    plan: str
    result: str
    result_hash: str
    audit_hash: str
    elapsed_ms: int


@dataclass(frozen=True, slots=True)
class ToolCatalog:
    user: str
    role: str
    enabled_risks: tuple[str, ...]
    tools: list[RemoteTool] = field(default_factory=list)

    def get(self, name: str) -> RemoteTool | None:
        for t in self.tools:
            if t.name == name:
                return t
        return None


class ExecutorClient:
    def __init__(
        self,
        url: str,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        http: httpx.Client | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self._http = http or httpx.Client(timeout=httpx.Timeout(timeout, read=RUN_TIMEOUT))

    # -- plumbing -------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"authorization": f"Bearer {self._token}", "accept": "application/json"}

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._http.request(
                method, f"{self.url}{path}", headers=self._headers(), **kwargs
            )
        except httpx.HTTPError as exc:
            raise ExecutorError(
                f"cannot reach executor at {self.url} ({exc.__class__.__name__}); "
                "is the SSH tunnel up? (ssh -L 8710:localhost:8710 user@server)",
                status=0,
            ) from None
        try:
            data = response.json()
        except ValueError:
            raise ExecutorError(
                f"executor returned non-JSON (HTTP {response.status_code})",
                status=response.status_code,
            ) from None
        if response.status_code >= 400:
            code = str(data.get("error", "executor_error")) if isinstance(data, dict) else "error"
            message = str(data.get("message", "")) if isinstance(data, dict) else str(data)[:200]
            detail = data.get("detail") if isinstance(data, dict) else None
            raise ExecutorError(
                message or code,
                status=response.status_code,
                remote_code=code,
                detail=detail if isinstance(detail, dict) else None,
            )
        if not isinstance(data, dict):
            raise ExecutorError(
                "executor returned an unexpected payload", status=response.status_code
            )
        return data

    # -- API ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def tools(self) -> ToolCatalog:
        data = self._request("GET", "/tools")
        tools = [
            RemoteTool(
                name=str(t["name"]),
                description=str(t.get("description", "")),
                risk=str(t.get("risk", "read")),
                approve=bool(t.get("approve", False)),
                virtual=bool(t.get("virtual", False)),
                verify_with=t.get("verify_with"),
                input_schema=dict(t.get("input_schema") or {}),
                roles=tuple(t.get("roles") or ()),
            )
            for t in data.get("tools", [])
            if isinstance(t, dict) and "name" in t
        ]
        return ToolCatalog(
            user=str(data.get("user", "")),
            role=str(data.get("role", "")),
            enabled_risks=tuple(data.get("enabled_risks") or ()),
            tools=tools,
        )

    def plan(self, tool: str, args: dict[str, Any]) -> PlanInfo:
        data = self._request("POST", "/plan", json={"tool": tool, "args": args})
        return PlanInfo(
            tool=str(data["tool"]),
            risk=str(data["risk"]),
            approve=bool(data["approve"]),
            plan=str(data["plan"]),
            plan_hash=str(data["plan_hash"]),
        )

    def run(
        self, tool: str, args: dict[str, Any], *, approved_plan_hash: str | None = None
    ) -> RunInfo:
        body: dict[str, Any] = {"tool": tool, "args": args}
        if approved_plan_hash:
            body["approved_plan_hash"] = approved_plan_hash
        data = self._request("POST", "/run", json=body)
        return RunInfo(
            tool=str(data["tool"]),
            risk=str(data["risk"]),
            plan=str(data.get("plan", "")),
            result=str(data.get("result", "")),
            result_hash=str(data.get("result_hash", "")),
            audit_hash=str(data.get("audit_hash", "")),
            elapsed_ms=int(data.get("elapsed_ms", 0)),
        )

    def audit(self, n: int = 20) -> dict[str, Any]:
        return self._request("GET", "/audit", params={"n": n})
