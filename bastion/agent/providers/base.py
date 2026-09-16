"""Provider-neutral message types and the LLM ``Provider`` protocol.

The agent loop only ever sees these types. Each provider converts them to and
from its own wire format. All providers speak plain HTTPS via ``httpx``; there
is no SDK dependency and no telemetry (invariant 13).
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from bastion.core.errors import ProviderError


@dataclass(frozen=True, slots=True)
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToolResult:
    call_id: str
    name: str
    content: str
    is_error: bool = False


@dataclass(slots=True)
class UserMessage:
    text: str


@dataclass(slots=True)
class AssistantMessage:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    #: Provider-native content, replayed verbatim when talking to the same provider.
    raw: Any = None
    provider: str = ""


@dataclass(slots=True)
class ToolResultMessage:
    results: list[ToolResult]


Message = UserMessage | AssistantMessage | ToolResultMessage


@dataclass(frozen=True, slots=True)
class Completion:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    raw: Any = None
    usage: dict[str, int] = field(default_factory=dict)

    def as_message(self, provider: str) -> AssistantMessage:
        return AssistantMessage(
            text=self.text, tool_calls=list(self.tool_calls), raw=self.raw, provider=provider
        )


class Provider(Protocol):
    """What the agent loop needs from an LLM backend."""

    name: str
    model: str

    def complete(
        self,
        system: str,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
    ) -> Completion: ...


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    provider: str
    model: str
    api_key: str | None = None
    base_url: str | None = None
    max_tokens: int = 4096
    timeout: float = 120.0


def parse_args(raw: Any) -> dict[str, Any]:
    """Tool arguments may arrive as a dict or as a JSON string; never trust either."""
    if raw is None or raw == "":
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProviderError(f"tool arguments are not valid JSON: {exc.msg}") from None
        if isinstance(parsed, dict):
            return parsed
        raise ProviderError("tool arguments must be a JSON object")
    raise ProviderError(f"unsupported tool argument type {type(raw).__name__}")


class HttpProvider:
    """Shared HTTP plumbing: one client, bounded retries, sanitised errors."""

    name = "http"
    RETRY_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504})

    def __init__(
        self,
        config: ProviderConfig,
        *,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 2,
    ) -> None:
        self.config = config
        self.model = config.model
        self._http = http or httpx.Client(timeout=config.timeout)
        self._sleep = sleep
        self._max_retries = max_retries

    def _post(self, url: str, *, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        attempt = 0
        while True:
            try:
                response = self._http.post(url, headers=headers, json=body)
            except httpx.HTTPError as exc:
                if attempt < self._max_retries:
                    attempt += 1
                    self._sleep(min(2**attempt, 8))
                    continue
                raise ProviderError(
                    f"{self.name}: network error ({exc.__class__.__name__})"
                ) from None
            if response.status_code in self.RETRY_STATUSES and attempt < self._max_retries:
                attempt += 1
                retry_after = response.headers.get("retry-after")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 2**attempt
                self._sleep(min(delay, 30))
                continue
            if response.status_code >= 400:
                raise ProviderError(
                    f"{self.name}: HTTP {response.status_code}: {_error_summary(response)}"
                )
            try:
                data = response.json()
            except ValueError:
                raise ProviderError(f"{self.name}: response is not JSON") from None
            if not isinstance(data, dict):
                raise ProviderError(f"{self.name}: unexpected response shape")
            return data


def _error_summary(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err.get("type") or "error")[:300]
        if isinstance(err, str):
            return err[:300]
        if "message" in data:
            return str(data["message"])[:300]
    return str(data)[:200]
