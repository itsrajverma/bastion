"""Virtual tools are handled by the CLI, never executed by the executor."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from bastion.tools import tool

Question = Annotated[str, Field(min_length=3, max_length=500, description="The question")]


@tool(risk="read", virtual=True, plan="ask the operator: {question!r}")
def ask_user(question: str) -> str:
    """Ask the human operator a clarifying question when the request is ambiguous.

    Use this instead of guessing a pid, domain, service, or intent. The answer
    comes back as the tool result.

    Args:
        question: a short, specific question for the operator.
    """
    raise RuntimeError("ask_user is answered by the CLI, not executed")
