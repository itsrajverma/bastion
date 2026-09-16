"""Rich UX (interactive) and JSON event stream (--json) for the agent loop."""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt
from rich.text import Text

from bastion.agent.client import PlanInfo, RemoteTool, ToolCatalog
from bastion.agent.loop import CallRecord, Decision, Verification
from bastion.agent.providers.base import ToolCall
from bastion.core.policy import RISK_COLORS

HEADER_MARK = "◆"  # ◆
CHECK = "✔"  # ✔
CROSS = "✘"  # ✘
BULLET = "•"  # •
ARROW = "→"  # →

STATUS_ICON: dict[str, str] = {
    "ok": CHECK,
    "answered": CHECK,
    "error": CROSS,
    "denied": CROSS,
    "unknown": CROSS,
    "declined": "-",
    "dry_run": "~",
}


def risk_style(risk: str) -> str:
    return RISK_COLORS.get(risk, "white")


def summarize_args(args: dict[str, Any]) -> str:
    if not args:
        return ""
    return ", ".join(f"{k}={v}" for k, v in args.items())


class RichUI:
    """Implements :class:`bastion.agent.loop.LoopUI` with Rich panels and prompts."""

    def __init__(self, server: str, model: str, console: Console | None = None) -> None:
        self.console = console or Console()
        self.server = server
        self.model = model
        self._progress: Progress | None = None
        self._task_id: int | None = None
        self._current_risk = "read"

    # -- header / text -------------------------------------------------------------

    def header(self) -> None:
        self.console.print(
            Text.assemble((HEADER_MARK, "bold"), " bastion · ", self.server, " · ", self.model)
        )

    def on_start(self, catalog: ToolCatalog) -> None:
        self.header()

    def on_text(self, text: str) -> None:
        self.console.print(Text(text, style="dim"))

    # -- tool calls ----------------------------------------------------------------

    def on_tool_start(self, call: ToolCall, tool: RemoteTool | None) -> None:
        self._current_risk = tool.risk if tool else "read"
        if tool is not None and tool.virtual:
            return
        label = Text.assemble(
            (BULLET + " ", risk_style(self._current_risk)),
            (call.name, "bold"),
            ("  " + summarize_args(call.args), "dim"),
        )
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
        self._progress.start()
        self._task_id = self._progress.add_task(label.markup, total=None)

    def on_tool_end(self, record: CallRecord) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None
            self._task_id = None
        if record.status == "answered":
            return
        if record.status == "dry_run":
            self.console.print(
                Panel(
                    Text(record.plan),
                    title="Proposed action (dry run)",
                    subtitle=f"risk: {record.risk.upper()} · not executed",
                    border_style=risk_style(record.risk),
                    subtitle_align="right",
                )
            )
        icon = STATUS_ICON.get(record.status, "?")
        style = risk_style(record.risk)
        summary = record.result.strip().splitlines()[0][:90] if record.result.strip() else ""
        if record.status in {"error", "denied", "unknown"}:
            style = "red"
        line = Text.assemble(
            (f"{BULLET} ", style),
            (record.name, "bold"),
            ("  " + summarize_args(record.args), "dim"),
            f"  {icon} ",
            (summary, "dim" if record.status == "ok" else "red"),
            (f"  ({record.elapsed:.1f}s)", "dim"),
        )
        self.console.print(line)

    # -- approval ------------------------------------------------------------------

    def approve(self, call: ToolCall, plan: PlanInfo) -> Decision:
        risk = plan.risk.upper()
        self.console.print(
            Panel(
                Text(plan.plan),
                title="Proposed action",
                subtitle=f"risk: {risk} · needs approval",
                border_style=risk_style(plan.risk),
                subtitle_align="right",
            )
        )
        while True:
            answer = Prompt.ask("Approve? [y/N/explain]", console=self.console, default="n")
            lowered = answer.strip().lower()
            if lowered in ("y", "yes"):
                return "y"
            if lowered in ("explain", "e", "?"):
                return "explain"
            if lowered in ("n", "no", ""):
                return "n"
            self.console.print("please answer y, n, or explain", style="yellow")

    def on_explanation(self, text: str) -> None:
        self.console.print(Panel(Markdown(text), title="Explanation", border_style="blue"))

    def ask_user(self, question: str) -> str:
        self.console.print(Panel(Text(question), title="Question", border_style="blue"))
        return Prompt.ask("Answer", console=self.console)

    # -- outcome -------------------------------------------------------------------

    def on_verify(self, verification: Verification) -> None:
        summary = verification.summary.replace("->", ARROW)
        self.console.print(Text(f"{CHECK} {summary}", style="green"))

    def on_stop(self, reason: str, message: str) -> None:
        self.console.print(Text(f"{CROSS} {message} ({reason})", style="yellow"))

    def diagnosis(self, text: str) -> None:
        body: Markdown | Text = Markdown(text) if text.strip() else Text("(no answer)")
        self.console.print(Panel(body, title="Diagnosis", border_style="green"))

    def error(self, message: str) -> None:
        self.console.print(Text(f"{CROSS} {message}", style="red"))


class JsonUI:
    """Emits one JSON object per line; no Rich output at all."""

    def __init__(self, server: str, model: str, stdin: Any = None, stdout: Any = None) -> None:
        self.server = server
        self.model = model
        self._in = stdin or sys.stdin
        self._out = stdout or sys.stdout

    def emit(self, event: str, **fields: Any) -> None:
        self._out.write(json.dumps({"event": event, **fields}, ensure_ascii=False) + "\n")
        self._out.flush()

    def _read_line(self) -> str:
        try:
            line = self._in.readline()
        except (OSError, ValueError):
            return ""
        return line.strip()

    def on_start(self, catalog: ToolCatalog) -> None:
        self.emit(
            "start",
            server=self.server,
            model=self.model,
            role=catalog.role,
            tools=[t.name for t in catalog.tools],
        )

    def on_text(self, text: str) -> None:
        self.emit("text", text=text)

    def on_tool_start(self, call: ToolCall, tool: RemoteTool | None) -> None:
        self.emit("tool_start", tool=call.name, args=call.args, risk=tool.risk if tool else None)

    def on_tool_end(self, record: CallRecord) -> None:
        self.emit(
            "tool_end",
            tool=record.name,
            args=record.args,
            status=record.status,
            risk=record.risk,
            plan=record.plan,
            result=record.result,
            elapsed=round(record.elapsed, 3),
        )

    def approve(self, call: ToolCall, plan: PlanInfo) -> Decision:
        self.emit(
            "approval_required",
            tool=plan.tool,
            args=call.args,
            risk=plan.risk,
            plan=plan.plan,
            plan_hash=plan.plan_hash,
            prompt="reply with y, n, or explain on stdin",
        )
        answer = self._read_line().lower()
        if answer in ("y", "yes"):
            return "y"
        if answer in ("explain", "e"):
            return "explain"
        return "n"

    def on_explanation(self, text: str) -> None:
        self.emit("explanation", text=text)

    def ask_user(self, question: str) -> str:
        self.emit("question", question=question)
        return self._read_line() or "(no answer)"

    def on_verify(self, verification: Verification) -> None:
        self.emit(
            "verify",
            tool=verification.tool,
            summary=verification.summary,
            before=verification.before,
            after=verification.after,
        )

    def on_stop(self, reason: str, message: str) -> None:
        self.emit("stop", reason=reason, message=message)

    def diagnosis(self, text: str) -> None:
        self.emit("final", text=text)

    def error(self, message: str) -> None:
        self.emit("error", message=message)
