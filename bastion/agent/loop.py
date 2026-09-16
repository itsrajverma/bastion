"""The tool-use loop (invariants 7, 11, 12).

fetch tools -> LLM -> for each tool call:
    policy/catalog check -> (approval: /plan -> y/N/explain) -> /run
    -> redact + fence -> back to the LLM
stop on final text, max calls, wall time, or user cancel.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from bastion.agent.client import ExecutorClient, PlanInfo, RemoteTool, RunInfo, ToolCatalog
from bastion.agent.prompts import SYSTEM_PROMPT, declined_result, dry_run_result, explain_prompt
from bastion.agent.providers.base import (
    Message,
    Provider,
    ToolCall,
    ToolDef,
    ToolResult,
    ToolResultMessage,
    UserMessage,
)
from bastion.core.errors import BastionError, ExecutorError, UserCancelled
from bastion.core.redact import sanitize_tool_output

Decision = Literal["y", "n", "explain"]
CallStatus = Literal["ok", "error", "declined", "dry_run", "denied", "unknown", "answered"]

MAX_CALLS_HARD_CEILING = 50
MAX_SECONDS_HARD_CEILING = 900


@dataclass(frozen=True, slots=True)
class LoopConfig:
    max_calls: int = 10
    max_seconds: float = 120.0
    dry_run: bool = False

    def __post_init__(self) -> None:
        # Configurable, not removable (invariant 12).
        if not (1 <= self.max_calls <= MAX_CALLS_HARD_CEILING):
            raise ValueError(f"max_calls must be between 1 and {MAX_CALLS_HARD_CEILING}")
        if not (5 <= self.max_seconds <= MAX_SECONDS_HARD_CEILING):
            raise ValueError(f"max_seconds must be between 5 and {MAX_SECONDS_HARD_CEILING}")


@dataclass(slots=True)
class CallRecord:
    name: str
    args: dict[str, Any]
    status: CallStatus
    risk: str = "read"
    plan: str = ""
    result: str = ""
    elapsed: float = 0.0


@dataclass(slots=True)
class AskResult:
    text: str
    calls: list[CallRecord] = field(default_factory=list)
    stop_reason: str = "final"
    elapsed: float = 0.0
    turns: int = 0

    @property
    def tools_called(self) -> list[str]:
        return [c.name for c in self.calls]


@dataclass(frozen=True, slots=True)
class Verification:
    tool: str
    before: str
    after: str
    summary: str


class LoopUI(Protocol):
    """Callbacks the CLI (Rich or JSON) implements. Every method must be cheap."""

    def on_start(self, catalog: ToolCatalog) -> None: ...
    def on_text(self, text: str) -> None: ...
    def on_tool_start(self, call: ToolCall, tool: RemoteTool | None) -> None: ...
    def on_tool_end(self, record: CallRecord) -> None: ...
    def approve(self, call: ToolCall, plan: PlanInfo) -> Decision: ...
    def on_explanation(self, text: str) -> None: ...
    def ask_user(self, question: str) -> str: ...
    def on_verify(self, verification: Verification) -> None: ...
    def on_stop(self, reason: str, message: str) -> None: ...


class NullUI:
    """Approves nothing, answers nothing. Useful for tests and --dry-run pipelines."""

    def on_start(self, catalog: ToolCatalog) -> None:
        pass

    def on_text(self, text: str) -> None:
        pass

    def on_tool_start(self, call: ToolCall, tool: RemoteTool | None) -> None:
        pass

    def on_tool_end(self, record: CallRecord) -> None:
        pass

    def approve(self, call: ToolCall, plan: PlanInfo) -> Decision:
        return "n"

    def on_explanation(self, text: str) -> None:
        pass

    def ask_user(self, question: str) -> str:
        return "The operator is not available to answer; proceed with read-only investigation."

    def on_verify(self, verification: Verification) -> None:
        pass

    def on_stop(self, reason: str, message: str) -> None:
        pass


def to_tool_defs(catalog: ToolCatalog) -> list[ToolDef]:
    return [
        ToolDef(name=t.name, description=t.description, input_schema=t.input_schema)
        for t in catalog.tools
    ]


_LOAD_RE = re.compile(r"1m=(\d+(?:\.\d+)?)")
_ACTIVE_RE = re.compile(r"is-active:\s*(\S+)")


def summarize_change(tool: str, before: str, after: str) -> str:
    """Render a `load 14.2 -> 3.1` style line for the CLI's checkmark."""
    if tool == "load_avg":
        b, a = _LOAD_RE.search(before or ""), _LOAD_RE.search(after or "")
        if a:
            return f"load {b.group(1) if b else '?'} -> {a.group(1)}"
    if tool == "service_status":
        b, a = _ACTIVE_RE.search(before or ""), _ACTIVE_RE.search(after or "")
        if a:
            return f"service {b.group(1) if b else '?'} -> {a.group(1)}"
    if tool == "nginx_test":
        ok = (
            "syntax is ok" in (after or "").lower()
            and "test is successful" in (after or "").lower()
        )
        return "nginx config test " + ("passed" if ok else "failed")
    first = (after or "").strip().splitlines()
    return f"{tool}: {first[0][:80]}" if first else f"{tool}: verified"


class AgentLoop:
    def __init__(
        self,
        provider: Provider,
        executor: ExecutorClient,
        ui: LoopUI | None = None,
        config: LoopConfig | None = None,
        *,
        system_prompt: str = SYSTEM_PROMPT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.provider = provider
        self.executor = executor
        self.ui: LoopUI = ui or NullUI()
        self.config = config or LoopConfig()
        self.system_prompt = system_prompt
        self._clock = clock
        self.messages: list[Message] = []
        self.calls: list[CallRecord] = []
        self._last_results: dict[str, str] = {}

    # -- public -------------------------------------------------------------------

    def run(self, prompt: str) -> AskResult:
        started = self._clock()
        catalog = self.executor.tools()
        self.ui.on_start(catalog)
        tool_defs = to_tool_defs(catalog)
        self.messages = [UserMessage(prompt)]
        turns = 0
        final_text = ""
        stop_reason = "final"

        while True:
            if self._clock() - started > self.config.max_seconds:
                stop_reason = "wall_time"
                final_text = self._stop(
                    stop_reason, f"stopped after {self.config.max_seconds:.0f}s"
                )
                break
            turns += 1
            completion = self.provider.complete(self.system_prompt, self.messages, tool_defs)
            self.messages.append(completion.as_message(self.provider.name))
            if not completion.tool_calls:
                final_text = completion.text
                break
            if completion.text:
                self.ui.on_text(completion.text)  # intermediate narration only

            results: list[ToolResult] = []
            aborted = False
            for call in completion.tool_calls:
                if len(self.calls) >= self.config.max_calls:
                    stop_reason = "max_calls"
                    final_text = self._stop(
                        stop_reason, f"reached the limit of {self.config.max_calls} tool calls"
                    )
                    aborted = True
                    break
                if self._clock() - started > self.config.max_seconds:
                    stop_reason = "wall_time"
                    final_text = self._stop(
                        stop_reason, f"stopped after {self.config.max_seconds:.0f}s"
                    )
                    aborted = True
                    break
                try:
                    results.append(self._handle_call(call, catalog))
                except UserCancelled as exc:
                    stop_reason = "cancelled"
                    final_text = self._stop(stop_reason, exc.message)
                    aborted = True
                    break
            if aborted:
                break
            self.messages.append(ToolResultMessage(results))

        return AskResult(
            text=final_text or "",
            calls=list(self.calls),
            stop_reason=stop_reason,
            elapsed=self._clock() - started,
            turns=turns,
        )

    # -- internals --------------------------------------------------------------

    def _stop(self, reason: str, message: str) -> str:
        self.ui.on_stop(reason, message)
        return f"Stopped: {message}."

    def _record(self, record: CallRecord) -> CallRecord:
        self.calls.append(record)
        self.ui.on_tool_end(record)
        return record

    def _handle_call(self, call: ToolCall, catalog: ToolCatalog) -> ToolResult:
        tool = catalog.get(call.name)
        self.ui.on_tool_start(call, tool)
        started = self._clock()

        if tool is None:
            record = self._record(
                CallRecord(
                    call.name,
                    dict(call.args),
                    "unknown",
                    result=f"tool {call.name!r} is not available on this executor",
                )
            )
            return ToolResult(call.id, call.name, record.result, is_error=True)

        if tool.virtual:
            question = str(call.args.get("question", "")).strip() or "(no question given)"
            answer = self.ui.ask_user(question)
            record = self._record(
                CallRecord(call.name, dict(call.args), "answered", result=answer, plan=question)
            )
            return ToolResult(call.id, call.name, sanitize_tool_output(answer, source="operator"))

        plan: PlanInfo | None = None
        approved_hash: str | None = None
        if tool.approve:
            try:
                plan = self.executor.plan(call.name, call.args)
            except BastionError as exc:
                return self._error_result(call, tool, exc, started)
            if self.config.dry_run:
                text = dry_run_result(call.name, plan.plan)
                self._record(
                    CallRecord(
                        call.name,
                        dict(call.args),
                        "dry_run",
                        risk=tool.risk,
                        plan=plan.plan,
                        result=text,
                        elapsed=self._clock() - started,
                    )
                )
                return ToolResult(call.id, call.name, text)
            decision = self._ask_approval(call, plan)
            if decision != "y":
                text = declined_result(call.name)
                self._record(
                    CallRecord(
                        call.name,
                        dict(call.args),
                        "declined",
                        risk=tool.risk,
                        plan=plan.plan,
                        result=text,
                        elapsed=self._clock() - started,
                    )
                )
                return ToolResult(call.id, call.name, text)
            approved_hash = plan.plan_hash

        try:
            run: RunInfo = self.executor.run(call.name, call.args, approved_plan_hash=approved_hash)
        except BastionError as exc:
            return self._error_result(call, tool, exc, started)

        self._last_results[call.name] = run.result
        content = sanitize_tool_output(run.result, source=call.name)
        self._record(
            CallRecord(
                call.name,
                dict(call.args),
                "ok",
                risk=tool.risk,
                plan=run.plan or (plan.plan if plan else ""),
                result=run.result,
                elapsed=self._clock() - started,
            )
        )
        if tool.approve and tool.verify_with:
            extra = self._verify(tool, call, catalog)
            if extra:
                content += "\n" + extra
        return ToolResult(call.id, call.name, content)

    def _ask_approval(self, call: ToolCall, plan: PlanInfo) -> Decision:
        while True:
            decision = self.ui.approve(call, plan)
            if decision != "explain":
                return decision
            explanation = self.provider.complete(
                self.system_prompt,
                [*self.messages, UserMessage(explain_prompt(call.name, plan.plan))],
                [],  # no tools: an explanation must not trigger actions
            )
            self.ui.on_explanation(explanation.text or "(no explanation given)")

    def _verify(self, tool: RemoteTool, call: ToolCall, catalog: ToolCatalog) -> str:
        """Re-run the tool's designated read tool after a successful fix."""
        verify_name = tool.verify_with or ""
        verify_tool = catalog.get(verify_name)
        if verify_tool is None or verify_tool.approve:
            return ""
        if len(self.calls) >= self.config.max_calls:
            return ""
        args = _verification_args(verify_tool, call.args)
        started = self._clock()
        try:
            run = self.executor.run(verify_name, args)
        except BastionError as exc:
            self._record(
                CallRecord(
                    verify_name, args, "error", result=exc.message, elapsed=self._clock() - started
                )
            )
            return ""
        before = self._last_results.get(verify_name, "")
        self._last_results[verify_name] = run.result
        self._record(
            CallRecord(
                verify_name,
                args,
                "ok",
                risk=verify_tool.risk,
                plan=run.plan,
                result=run.result,
                elapsed=self._clock() - started,
            )
        )
        summary = summarize_change(verify_name, before, run.result)
        self.ui.on_verify(Verification(verify_name, before, run.result, summary))
        return sanitize_tool_output(
            f"Verification via {verify_name} after {call.name}: {summary}\n{run.result}",
            source=verify_name,
        )

    def _error_result(
        self, call: ToolCall, tool: RemoteTool, exc: BastionError, started: float
    ) -> ToolResult:
        status: CallStatus = "error"
        if isinstance(exc, ExecutorError) and exc.remote_code in {
            "policy_denied",
            "protected_target",
        }:
            status = "denied"
        message = (
            f"{exc.code if not isinstance(exc, ExecutorError) else exc.remote_code}: {exc.message}"
        )
        self._record(
            CallRecord(
                call.name,
                dict(call.args),
                status,
                risk=tool.risk,
                result=message,
                elapsed=self._clock() - started,
            )
        )
        return ToolResult(
            call.id, call.name, sanitize_tool_output(message, source=call.name), is_error=True
        )


def _verification_args(verify_tool: RemoteTool, original_args: dict[str, Any]) -> dict[str, Any]:
    """Carry over arguments the verification tool accepts (e.g. ``service``)."""
    props = verify_tool.input_schema.get("properties", {})
    return {k: v for k, v in original_args.items() if k in props}


def run_ask(
    prompt: str,
    provider: Provider,
    executor: ExecutorClient,
    ui: LoopUI | None = None,
    config: LoopConfig | None = None,
    *,
    messages: Sequence[Message] | None = None,
) -> AskResult:
    loop = AgentLoop(provider, executor, ui, config)
    if messages:
        loop.messages = list(messages)
    return loop.run(prompt)
