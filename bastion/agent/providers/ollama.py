"""Ollama (self-hosted) via its native /api/chat endpoint with tool calling."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from bastion.agent.providers.base import (
    Completion,
    HttpProvider,
    Message,
    ProviderConfig,
    ToolDef,
)
from bastion.agent.providers.openai import chat_messages, function_tool, parse_chat_message
from bastion.core.errors import ProviderError

DEFAULT_MODEL = "llama3.1"
DEFAULT_BASE_URL = "http://127.0.0.1:11434"


class OllamaProvider(HttpProvider):
    name = "ollama"

    def __init__(self, config: ProviderConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)
        self._base_url = (config.base_url or DEFAULT_BASE_URL).rstrip("/")

    def complete(
        self,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
    ) -> Completion:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": chat_messages(system, messages, with_ids=False),
            "stream": False,
            "options": {"num_predict": self.config.max_tokens},
        }
        if tools:
            body["tools"] = [function_tool(t) for t in tools]
        headers = {"content-type": "application/json"}
        if self.config.api_key:  # optional: Ollama behind an auth proxy
            headers["authorization"] = f"Bearer {self.config.api_key}"
        data = self._post(f"{self._base_url}/api/chat", headers=headers, body=body)
        message = data.get("message")
        if not isinstance(message, dict):
            raise ProviderError("ollama: response has no message")
        done_reason = str(data.get("done_reason") or "stop")
        return parse_chat_message(message, done_reason)
