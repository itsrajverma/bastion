"""Anthropic Messages API with native tool use (default provider)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from bastion.agent.providers.base import (
    AssistantMessage,
    Completion,
    HttpProvider,
    Message,
    ProviderConfig,
    ToolCall,
    ToolDef,
    ToolResultMessage,
    UserMessage,
    parse_args,
)
from bastion.core.errors import ProviderError

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_BASE_URL = "https://api.anthropic.com"
API_VERSION = "2023-06-01"


class AnthropicProvider(HttpProvider):
    name = "anthropic"

    def __init__(self, config: ProviderConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)
        if not config.api_key:
            raise ProviderError("anthropic: API key is not set (check api_key_env in config)")
        self._base_url = (config.base_url or DEFAULT_BASE_URL).rstrip("/")

    # -- wire format ------------------------------------------------------------

    @staticmethod
    def tool_schema(tool: ToolDef) -> dict[str, Any]:
        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
        }

    def to_wire(self, messages: Sequence[Message]) -> list[dict[str, Any]]:
        wire: list[dict[str, Any]] = []
        for msg in messages:
            if isinstance(msg, UserMessage):
                wire.append({"role": "user", "content": msg.text})
            elif isinstance(msg, AssistantMessage):
                if msg.raw is not None and msg.provider == self.name:
                    content: Any = msg.raw
                else:
                    blocks: list[dict[str, Any]] = []
                    if msg.text:
                        blocks.append({"type": "text", "text": msg.text})
                    for call in msg.tool_calls:
                        blocks.append(
                            {
                                "type": "tool_use",
                                "id": call.id,
                                "name": call.name,
                                "input": call.args,
                            }
                        )
                    content = blocks or [{"type": "text", "text": "(no content)"}]
                wire.append({"role": "assistant", "content": content})
            elif isinstance(msg, ToolResultMessage):
                wire.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": r.call_id,
                                "content": r.content,
                                **({"is_error": True} if r.is_error else {}),
                            }
                            for r in msg.results
                        ],
                    }
                )
        return wire

    def complete(
        self,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
    ) -> Completion:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.config.max_tokens,
            "system": system,
            "messages": self.to_wire(messages),
        }
        if tools:
            body["tools"] = [self.tool_schema(t) for t in tools]
        headers = {
            "x-api-key": self.config.api_key or "",
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        data = self._post(f"{self._base_url}/v1/messages", headers=headers, body=body)
        return self.parse_response(data)

    @staticmethod
    def parse_response(data: dict[str, Any]) -> Completion:
        content = data.get("content")
        if not isinstance(content, list):
            raise ProviderError("anthropic: response has no content list")
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                text_parts.append(str(block.get("text", "")))
            elif kind == "tool_use":
                calls.append(
                    ToolCall(
                        id=str(block.get("id", "")),
                        name=str(block.get("name", "")),
                        args=parse_args(block.get("input")),
                    )
                )
        stop_reason = str(data.get("stop_reason") or "end_turn")
        if stop_reason == "refusal" and not text_parts:
            text_parts.append("The model declined to answer this request.")
        usage_raw = data.get("usage") or {}
        usage = {k: int(v) for k, v in usage_raw.items() if isinstance(v, int)}
        return Completion(
            text="\n".join(p for p in text_parts if p).strip(),
            tool_calls=calls,
            stop_reason=stop_reason,
            raw=content,
            usage=usage,
        )
