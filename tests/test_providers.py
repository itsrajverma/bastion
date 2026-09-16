"""Provider wire formats, tested offline with httpx.MockTransport."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from bastion.agent.providers import make_provider
from bastion.agent.providers.anthropic import AnthropicProvider
from bastion.agent.providers.base import (
    AssistantMessage,
    ProviderConfig,
    ToolCall,
    ToolDef,
    ToolResult,
    ToolResultMessage,
    UserMessage,
    parse_args,
)
from bastion.agent.providers.ollama import OllamaProvider
from bastion.agent.providers.openai import OpenAIProvider
from bastion.core.errors import ConfigError, ProviderError

TOOLS = [
    ToolDef(
        "load_avg",
        "Show load",
        {"type": "object", "properties": {}, "additionalProperties": False},
    )
]

HISTORY = [
    UserMessage("server is slow"),
    AssistantMessage(text="checking", tool_calls=[ToolCall("t1", "load_avg", {})]),
    ToolResultMessage([ToolResult("t1", "load_avg", "load: 1m=9.00")]),
]


def mock_http(
    handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[httpx.Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return httpx.Client(transport=httpx.MockTransport(wrapped)), seen


def body_of(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content.decode())


# -- anthropic ----------------------------------------------------------------------


def test_anthropic_request_and_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "Load is high."},
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "top_processes",
                        "input": {"limit": 5},
                    },
                ],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )

    http, seen = mock_http(handler)
    provider = AnthropicProvider(
        ProviderConfig("anthropic", "claude-sonnet-4-6", api_key="sk-ant-test"), http=http
    )
    completion = provider.complete("SYS", HISTORY, TOOLS)

    req = seen[0]
    assert req.url == "https://api.anthropic.com/v1/messages"
    assert req.headers["x-api-key"] == "sk-ant-test"
    assert req.headers["anthropic-version"] == "2023-06-01"
    body = body_of(req)
    assert body["model"] == "claude-sonnet-4-6"
    assert body["system"] == "SYS"
    assert body["tools"] == [
        {"name": "load_avg", "description": "Show load", "input_schema": TOOLS[0].input_schema}
    ]
    assert body["messages"][0] == {"role": "user", "content": "server is slow"}
    assert body["messages"][1]["role"] == "assistant"
    assert body["messages"][1]["content"] == [
        {"type": "text", "text": "checking"},
        {"type": "tool_use", "id": "t1", "name": "load_avg", "input": {}},
    ]
    assert body["messages"][2] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "load: 1m=9.00"}],
    }
    assert completion.text == "Load is high."
    assert completion.tool_calls == [ToolCall("toolu_1", "top_processes", {"limit": 5})]
    assert completion.stop_reason == "tool_use"
    assert completion.usage["input_tokens"] == 10


def test_anthropic_replays_raw_content_and_error_flags() -> None:
    raw = [
        {"type": "text", "text": "hi"},
        {"type": "tool_use", "id": "x", "name": "load_avg", "input": {}},
    ]
    history = [
        UserMessage("q"),
        AssistantMessage(
            text="hi", tool_calls=[ToolCall("x", "load_avg", {})], raw=raw, provider="anthropic"
        ),
        ToolResultMessage([ToolResult("x", "load_avg", "nope", is_error=True)]),
    ]
    http, seen = mock_http(
        lambda r: httpx.Response(200, json={"content": [], "stop_reason": "end_turn"})
    )
    provider = AnthropicProvider(ProviderConfig("anthropic", "m", api_key="k"), http=http)
    provider.complete("S", history, [])
    body = body_of(seen[0])
    assert body["messages"][1]["content"] is not raw
    assert body["messages"][1]["content"] == raw
    assert body["messages"][2]["content"][0]["is_error"] is True
    assert "tools" not in body


def test_anthropic_refusal_and_missing_key() -> None:
    http, _ = mock_http(
        lambda r: httpx.Response(200, json={"content": [], "stop_reason": "refusal"})
    )
    provider = AnthropicProvider(ProviderConfig("anthropic", "m", api_key="k"), http=http)
    c = provider.complete("S", [UserMessage("x")], [])
    assert "declined" in c.text
    with pytest.raises(ProviderError, match="API key"):
        AnthropicProvider(ProviderConfig("anthropic", "m", api_key=None), http=http)


# -- openai ---------------------------------------------------------------------------


def test_openai_request_and_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_9",
                                    "type": "function",
                                    "function": {
                                        "name": "top_processes",
                                        "arguments": '{"limit": 3}',
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2},
            },
        )

    http, seen = mock_http(handler)
    provider = OpenAIProvider(ProviderConfig("openai", "gpt-4o", api_key="sk-x"), http=http)
    completion = provider.complete("SYS", HISTORY, TOOLS)
    req = seen[0]
    assert req.url == "https://api.openai.com/v1/chat/completions"
    assert req.headers["authorization"] == "Bearer sk-x"
    body = body_of(req)
    assert body["messages"][0] == {"role": "system", "content": "SYS"}
    assert body["messages"][2]["tool_calls"][0]["function"] == {
        "name": "load_avg",
        "arguments": "{}",
    }
    assert body["messages"][3] == {"role": "tool", "content": "load: 1m=9.00", "tool_call_id": "t1"}
    assert body["tools"][0]["type"] == "function"
    assert body["tools"][0]["function"]["parameters"] == TOOLS[0].input_schema
    assert body["tool_choice"] == "auto"
    assert completion.tool_calls == [ToolCall("call_9", "top_processes", {"limit": 3})]
    assert completion.stop_reason == "tool_calls"


def test_openai_bad_json_arguments_rejected() -> None:
    http, _ = mock_http(
        lambda r: httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {"id": "c", "function": {"name": "x", "arguments": "{oops"}}
                            ]
                        }
                    }
                ]
            },
        )
    )
    provider = OpenAIProvider(ProviderConfig("openai", "m", api_key="k"), http=http)
    with pytest.raises(ProviderError, match="not valid JSON"):
        provider.complete("S", [UserMessage("x")], TOOLS)


# -- ollama -----------------------------------------------------------------------------


def test_ollama_request_and_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"function": {"name": "load_avg", "arguments": {}}}],
                },
                "done_reason": "stop",
            },
        )

    http, seen = mock_http(handler)
    provider = OllamaProvider(ProviderConfig("ollama", "llama3.1"), http=http)
    completion = provider.complete("SYS", HISTORY, TOOLS)
    req = seen[0]
    assert req.url == "http://127.0.0.1:11434/api/chat"
    body = body_of(req)
    assert body["stream"] is False
    assert body["messages"][3] == {
        "role": "tool",
        "content": "load: 1m=9.00",
        "tool_name": "load_avg",
    }
    assert completion.tool_calls[0].name == "load_avg"
    assert completion.tool_calls[0].id  # synthesised


# -- shared http behaviour ------------------------------------------------------------------


def test_retries_then_succeeds_and_never_leaks_key() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) < 3:
            return httpx.Response(
                429, json={"error": {"message": "slow down"}}, headers={"retry-after": "1"}
            )
        return httpx.Response(
            200, json={"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"}
        )

    sleeps: list[float] = []
    http, _ = mock_http(handler)
    provider = AnthropicProvider(
        ProviderConfig("anthropic", "m", api_key="sk-ant-SECRET"), http=http, sleep=sleeps.append
    )
    assert provider.complete("S", [UserMessage("x")], []).text == "ok"
    assert len(attempts) == 3
    assert sleeps == [1.0, 1.0]


def test_http_error_is_sanitised() -> None:
    http, _ = mock_http(
        lambda r: httpx.Response(
            400, json={"error": {"type": "invalid_request_error", "message": "bad model"}}
        )
    )
    provider = AnthropicProvider(
        ProviderConfig("anthropic", "m", api_key="sk-ant-SECRET"), http=http
    )
    with pytest.raises(ProviderError) as info:
        provider.complete("S", [UserMessage("x")], [])
    assert "400" in info.value.message and "bad model" in info.value.message
    assert "SECRET" not in info.value.message


def test_network_error_becomes_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    http, _ = mock_http(handler)
    provider = OllamaProvider(ProviderConfig("ollama", "m"), http=http, sleep=lambda s: None)
    with pytest.raises(ProviderError, match="network error"):
        provider.complete("S", [UserMessage("x")], [])


def test_parse_args() -> None:
    assert parse_args(None) == {}
    assert parse_args("") == {}
    assert parse_args({"a": 1}) == {"a": 1}
    assert parse_args('{"a": 1}') == {"a": 1}
    with pytest.raises(ProviderError):
        parse_args("[1,2]")
    with pytest.raises(ProviderError):
        parse_args(42)


def test_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_KEY", "sk-ant-abc")
    p = make_provider("anthropic", api_key_env="MY_KEY")
    assert p.name == "anthropic" and p.model == "claude-sonnet-4-6"
    p2 = make_provider("ollama", model="qwen2.5")
    assert p2.model == "qwen2.5"
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ProviderError, match="API key"):
        make_provider("openai")
    with pytest.raises(ConfigError):
        make_provider("gemini")
