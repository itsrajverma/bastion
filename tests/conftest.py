"""Shared test helpers: recorded providers, fake/real executors, recording UI."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from bastion.agent.client import ExecutorClient, PlanInfo, RemoteTool, RunInfo, ToolCatalog
from bastion.agent.loop import CallRecord, Decision, Verification
from bastion.agent.providers.base import (
    Completion,
    Message,
    ToolCall,
    ToolDef,
    ToolResultMessage,
)
from bastion.core.audit import sha256_hex
from bastion.core.errors import ExecutorError
from bastion.executor.config import ExecutorSettings, settings_from_dict
from bastion.executor.main import create_app

FIXTURES = Path(__file__).parent / "fixtures"

VIEWER_TOKEN = "viewer-token-" + "v" * 32
OPERATOR_TOKEN = "operator-token-" + "o" * 32
ADMIN_TOKEN = "admin-token-" + "a" * 32


# -- providers ----------------------------------------------------------------------


class ScriptedProvider:
    """Replays recorded completions turn by turn (no live API, invariant: CI offline).

    Each turn is ``{"text": str, "tool_calls": [{"name": str, "args": {...}}]}``.
    Records every request so tests can assert what the model was shown.
    """

    name = "scripted"
    model = "recorded"

    def __init__(self, turns: Sequence[dict[str, Any]]) -> None:
        self.turns = list(turns)
        self.requests: list[dict[str, Any]] = []
        self._i = 0

    @classmethod
    def from_fixture(cls, name: str) -> ScriptedProvider:
        data = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
        return cls(data["turns"])

    def complete(
        self, system: str, messages: Sequence[Message], tools: Sequence[ToolDef]
    ) -> Completion:
        self.requests.append(
            {"system": system, "messages": list(messages), "tools": [t.name for t in tools]}
        )
        if self._i >= len(self.turns):
            return Completion(text="(script exhausted)", tool_calls=[], stop_reason="end_turn")
        turn = self.turns[self._i]
        self._i += 1
        calls = [
            ToolCall(id=f"call_{self._i}_{j}", name=tc["name"], args=dict(tc.get("args") or {}))
            for j, tc in enumerate(turn.get("tool_calls") or [])
        ]
        return Completion(
            text=str(turn.get("text", "")),
            tool_calls=calls,
            stop_reason="tool_use" if calls else "end_turn",
        )

    def last_tool_results(self) -> list[str]:
        out: list[str] = []
        for req in self.requests:
            for m in req["messages"]:
                if isinstance(m, ToolResultMessage):
                    out.extend(r.content for r in m.results)
        return out


# -- executors ------------------------------------------------------------------------


def make_settings(tmp_path: Path, **overrides: Any) -> ExecutorSettings:
    raw: dict[str, Any] = {
        "bind": "127.0.0.1:8710",
        "enabled_risks": ["read"],
        "tokens": {
            "vera": {"token": VIEWER_TOKEN, "role": "viewer"},
            "oscar": {"token": OPERATOR_TOKEN, "role": "operator"},
            "ada": {"token": ADMIN_TOKEN, "role": "admin"},
        },
        "audit_path": str(tmp_path / "audit.jsonl"),
    }
    raw.update(overrides)
    return settings_from_dict(raw)


def real_executor(
    tmp_path: Path, token: str = ADMIN_TOKEN, **overrides: Any
) -> tuple[ExecutorClient, TestClient]:
    """An ExecutorClient talking to the real FastAPI app in-process."""
    app = create_app(make_settings(tmp_path, **overrides))
    http = TestClient(app, raise_server_exceptions=False)
    return ExecutorClient("http://testserver", token, http=http), http


@pytest.fixture
def executor_read_only(tmp_path: Path) -> Iterator[ExecutorClient]:
    client, http = real_executor(tmp_path)
    with http:
        yield client


@pytest.fixture
def executor_full(tmp_path: Path) -> Iterator[ExecutorClient]:
    client, http = real_executor(tmp_path, enabled_risks=["read", "write", "admin"])
    with http:
        yield client


class FakeExecutor(ExecutorClient):
    """In-memory executor for loop unit tests. Tools are plain dicts of behaviour."""

    def __init__(self, tools: dict[str, dict[str, Any]], role: str = "operator") -> None:
        self.url = "fake://executor"
        self._token = "fake"
        self._tools = tools
        self.role = role
        self.ran: list[tuple[str, dict[str, Any], str | None]] = []
        self.planned: list[tuple[str, dict[str, Any]]] = []

    def health(self) -> dict[str, Any]:
        return {"status": "ok"}

    def tools(self) -> ToolCatalog:
        out = [
            RemoteTool(
                name=name,
                description=spec.get("description", f"{name} tool"),
                risk=spec.get("risk", "read"),
                approve=spec.get("approve", spec.get("risk", "read") != "read"),
                virtual=spec.get("virtual", False),
                verify_with=spec.get("verify_with"),
                input_schema=spec.get(
                    "input_schema",
                    {"type": "object", "properties": {}, "additionalProperties": False},
                ),
            )
            for name, spec in self._tools.items()
        ]
        return ToolCatalog(
            user="tester", role=self.role, enabled_risks=("read", "write"), tools=out
        )

    def _plan_text(self, tool: str, args: dict[str, Any]) -> str:
        spec = self._tools[tool]
        plan = spec.get("plan", f"{tool}({args})")
        return plan(**args) if callable(plan) else str(plan)

    def plan(self, tool: str, args: dict[str, Any]) -> PlanInfo:
        if tool not in self._tools:
            raise ExecutorError("unknown tool", status=404, remote_code="tool_not_found")
        self.planned.append((tool, dict(args)))
        text = self._plan_text(tool, args)
        spec = self._tools[tool]
        return PlanInfo(
            tool, spec.get("risk", "read"), spec.get("approve", False), text, sha256_hex(text)
        )

    def run(
        self, tool: str, args: dict[str, Any], *, approved_plan_hash: str | None = None
    ) -> RunInfo:
        if tool not in self._tools:
            raise ExecutorError("unknown tool", status=404, remote_code="tool_not_found")
        spec = self._tools[tool]
        if spec.get("approve") and approved_plan_hash != sha256_hex(self._plan_text(tool, args)):
            raise ExecutorError("approval required", status=403, remote_code="policy_denied")
        self.ran.append((tool, dict(args), approved_plan_hash))
        if "error" in spec:
            err = spec["error"]
            raise ExecutorError(
                err.get("message", "boom"),
                status=err.get("status", 500),
                remote_code=err.get("code", "tool_execution_error"),
            )
        result = spec.get("result", "")
        text = result(**args) if callable(result) else str(result)
        if "results" in spec:  # sequence of results for successive calls
            seq = spec["results"]
            text = seq.pop(0) if seq else text
        plan = self._plan_text(tool, args)
        return RunInfo(tool, spec.get("risk", "read"), plan, text, sha256_hex(text), "a" * 64, 1)

    def audit(self, n: int = 20) -> dict[str, Any]:
        return {"records": [], "verified": True}


# -- UI ---------------------------------------------------------------------------------


class RecordingUI:
    def __init__(self, decisions: Sequence[Decision] = (), answers: Sequence[str] = ()) -> None:
        self.decisions = list(decisions)
        self.answers = list(answers)
        self.events: list[tuple[str, Any]] = []

    def on_start(self, catalog: ToolCatalog) -> None:
        self.events.append(("start", [t.name for t in catalog.tools]))

    def on_text(self, text: str) -> None:
        self.events.append(("text", text))

    def on_tool_start(self, call: ToolCall, tool: RemoteTool | None) -> None:
        self.events.append(("tool_start", call.name))

    def on_tool_end(self, record: CallRecord) -> None:
        self.events.append(("tool_end", (record.name, record.status)))

    def approve(self, call: ToolCall, plan: PlanInfo) -> Decision:
        self.events.append(("approve", plan.plan))
        return self.decisions.pop(0) if self.decisions else "n"

    def on_explanation(self, text: str) -> None:
        self.events.append(("explain", text))

    def ask_user(self, question: str) -> str:
        self.events.append(("ask", question))
        return self.answers.pop(0) if self.answers else "no answer"

    def on_verify(self, verification: Verification) -> None:
        self.events.append(("verify", verification.summary))

    def on_stop(self, reason: str, message: str) -> None:
        self.events.append(("stop", reason))

    def kinds(self) -> list[str]:
        return [k for k, _ in self.events]
