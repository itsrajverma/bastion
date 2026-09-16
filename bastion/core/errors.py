"""Structured errors. Every error that can cross the executor boundary maps to a
stable machine-readable ``code`` and an HTTP status. Tracebacks never leak."""

from __future__ import annotations

from typing import Any


class BastionError(Exception):
    """Base class for all Bastion errors."""

    code: str = "bastion_error"
    status: int = 400

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.detail:
            payload["detail"] = self.detail
        return payload


class ConfigError(BastionError):
    code = "config_error"
    status = 500


class AuthError(BastionError):
    code = "unauthorized"
    status = 401


class PolicyDenied(BastionError):
    """The role or the enabled_risks setting does not permit this tool."""

    code = "policy_denied"
    status = 403


class ProtectedTarget(BastionError):
    """The target (process, backend, file) is on a protected list."""

    code = "protected_target"
    status = 403


class ToolNotFound(BastionError):
    code = "tool_not_found"
    status = 404


class ValidationFailed(BastionError):
    code = "validation_failed"
    status = 422


class ToolExecutionError(BastionError):
    """The tool ran but the underlying command/query failed."""

    code = "tool_execution_error"
    status = 500


class LoopLimitExceeded(BastionError):
    """The agent loop hit its call or wall-time budget."""

    code = "loop_limit_exceeded"
    status = 429


class ProviderError(BastionError):
    """The LLM provider returned an error or an unusable response."""

    code = "provider_error"
    status = 502


class UserCancelled(BastionError):
    code = "user_cancelled"
    status = 499


def error_payload(exc: BaseException) -> dict[str, Any]:
    """Convert any exception into a structured payload without leaking internals."""
    if isinstance(exc, BastionError):
        return exc.to_payload()
    return {"error": "internal_error", "message": "internal error"}


class ExecutorError(BastionError):
    """The executor refused or failed a request (client-side view)."""

    code = "executor_error"
    status = 502

    def __init__(
        self,
        message: str,
        *,
        status: int = 502,
        remote_code: str = "executor_error",
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, detail=detail)
        self.status = status
        self.remote_code = remote_code
