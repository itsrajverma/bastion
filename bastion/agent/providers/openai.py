"""OpenAI Chat Completions with function calling."""

from __future__ import annotations

import json
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

DEFAULT_MODEL = "gpt-4o"
DEFAULT_BASE_URL = "https://api.openai.com/v1"


def function_tool(tool: ToolDef) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        },
    }


def chat_messages(
    system: str, messages: Sequence[Message], *, with_ids: bool = True
) -> list[dict[str, Any]]:
    """Convert neutral messages to the OpenAI/Ollama chat shape."""
    wire: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for msg in messages:
        if isinstance(msg, UserMessage):
            wire.append({"role": "user", "content": msg.text})
        elif isinstance(msg, AssistantMessage):
            entry: dict[str, Any] = {"role": "assistant", "content": msg.text or None}
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.name, "arguments": json.dumps(call.args)},
                    }
                    for call in msg.tool_calls
                ]
            wire.append(entry)
        elif isinstance(msg, ToolResultMessage):
            for r in msg.results:
                item: dict[str, Any] = {"role": "tool", "content": r.content}
                if with_ids:
                    item["tool_call_id"] = r.call_id
                else:
                    item["tool_name"] = r.name
                wire.append(item)
    return wire


def parse_chat_message(message: dict[str, Any], stop_reason: str) -> Completion:
    text = message.get("content") or ""
    if not isinstance(text, str):
        text = str(text)
    calls: list[ToolCall] = []
    for i, tc in enumerate(message.get("tool_calls") or []):
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        calls.append(
            ToolCall(
                id=str(tc.get("id") or f"call_{i}"),
                name=str(fn.get("name", "")),
                args=parse_args(fn.get("arguments")),
            )
        )
    return Completion(text=text.strip(), tool_calls=calls, stop_reason=stop_reason, raw=message)


class OpenAIProvider(HttpProvider):
    name = "openai"

    def __init__(self, config: ProviderConfig, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)
        if not config.api_key:
            raise ProviderError("openai: API key is not set (check api_key_env in config)")
        self._base_url = (config.base_url or DEFAULT_BASE_URL).rstrip("/")

    def complete(
        self,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
    ) -> Completion:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": chat_messages(system, messages),
            "max_tokens": self.config.max_tokens,
        }
        if tools:
            body["tools"] = [function_tool(t) for t in tools]
            body["tool_choice"] = "auto"
        headers = {
            "authorization": f"Bearer {self.config.api_key}",
            "content-type": "application/json",
        }
        data = self._post(f"{self._base_url}/chat/completions", headers=headers, body=body)
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderError("openai: response has no choices")
        first = choices[0] if isinstance(choices[0], dict) else {}
        message = first.get("message") or {}
        if not isinstance(message, dict):
            raise ProviderError("openai: malformed message")
        usage_raw = data.get("usage") or {}
        completion = parse_chat_message(message, str(first.get("finish_reason") or "stop"))
        return Completion(
            text=completion.text,
            tool_calls=completion.tool_calls,
            stop_reason=completion.stop_reason,
            raw=message,
            usage={k: int(v) for k, v in usage_raw.items() if isinstance(v, int)},
        )
