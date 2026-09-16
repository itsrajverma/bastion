"""Data minimisation (invariant 10) and prompt-injection posture (invariant 11).

``redact`` strips secrets and personal identifiers from tool output before it
reaches the model. ``wrap_untrusted`` fences tool output so the system prompt
can instruct the model to treat it as data, never as instructions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

UNTRUSTED_OPEN = "<untrusted_tool_output>"
UNTRUSTED_CLOSE = "</untrusted_tool_output>"


@dataclass(frozen=True, slots=True)
class Pattern:
    kind: str
    regex: re.Pattern[str]
    group: int = 0  # which group to replace (0 = whole match)


def _p(kind: str, pattern: str, flags: int = 0, group: int = 0) -> Pattern:
    return Pattern(kind, re.compile(pattern, flags), group)


# Order matters: specific token formats first, then generic key=value secrets,
# then personal identifiers.
PATTERNS: tuple[Pattern, ...] = (
    _p(
        "private_key_block",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    _p("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    _p("bearer", r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*"),
    _p("aws_access_key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"),
    _p(
        "aws_secret_key",
        r"(?i)(aws_?secret_?access_?key|aws_?secret)\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
        group=2,
    ),
    _p("anthropic_key", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
    _p("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"),
    _p("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
    _p("slack_token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    _p("stripe_key", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    _p(
        "kv_secret",
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
        r"authorization|credentials?|client[_-]?secret|private[_-]?key)"
        r"\s*[=:]\s*[\"']?(?!\[REDACTED:)([^\s\"',;&]{6,})[\"']?",
        group=2,
    ),
    _p("url_credentials", r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", group=3),
    _p("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    # Indian PAN: 5 letters, 4 digits, 1 letter.
    _p("pan", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    # 16-digit card-like numbers with optional space/dash separators.
    _p("card_number", r"\b(?:\d[ -]?){15}\d\b"),
    # Aadhaar-like: 12 digits, optionally grouped in 4s.
    _p("aadhaar", r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
)


def _replace(text: str, pattern: Pattern) -> tuple[str, int]:
    count = 0

    def sub(m: re.Match[str]) -> str:
        nonlocal count
        count += 1
        marker = f"[REDACTED:{pattern.kind}]"
        if pattern.group == 0:
            return marker
        whole = m.group(0)
        start, end = m.span(pattern.group)
        return whole[: start - m.start()] + marker + whole[end - m.start() :]

    return pattern.regex.sub(sub, text), count


def redact(text: str) -> str:
    """Return ``text`` with secrets and PII replaced by ``[REDACTED:<kind>]`` markers."""
    if not text:
        return text
    out = text
    for pattern in PATTERNS:
        out, _ = _replace(out, pattern)
    return out


def redact_report(text: str) -> dict[str, int]:
    """Like :func:`redact` but returns a count per kind (for tests and audit)."""
    counts: dict[str, int] = {}
    out = text
    for pattern in PATTERNS:
        out, n = _replace(out, pattern)
        if n:
            counts[pattern.kind] = counts.get(pattern.kind, 0) + n
    return counts


_CLOSE_TAG_RE = re.compile(r"</\s*untrusted_tool_output\s*>", re.IGNORECASE)
_OPEN_TAG_RE = re.compile(r"<\s*untrusted_tool_output\b[^>]*>", re.IGNORECASE)


def wrap_untrusted(text: str, *, source: str = "") -> str:
    """Fence tool output. Any literal fence tags inside the payload are neutralised
    so the payload cannot break out of the fence."""
    body = _CLOSE_TAG_RE.sub("[tag removed]", text)
    body = _OPEN_TAG_RE.sub("[tag removed]", body)
    safe_source = re.sub(r"[^A-Za-z0-9_.-]", "", source)
    attr = f' source="{safe_source}"' if safe_source else ""
    return f"{UNTRUSTED_OPEN[:-1]}{attr}>\n{body}\n{UNTRUSTED_CLOSE}"


def sanitize_tool_output(text: str, *, source: str = "", max_chars: int = 20_000) -> str:
    """Redact, truncate, and fence in one step. This is the only path by which
    tool output may reach the model."""
    clipped = text
    if len(clipped) > max_chars:
        clipped = clipped[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"
    return wrap_untrusted(redact(clipped), source=source)
