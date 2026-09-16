"""Provider factory. Users bring their own API key via an environment variable."""

from __future__ import annotations

import os
from typing import Any

from bastion.agent.providers.base import Provider, ProviderConfig
from bastion.core.errors import ConfigError

PROVIDERS: tuple[str, ...] = ("anthropic", "openai", "ollama")

DEFAULT_MODELS: dict[str, str] = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
    "ollama": "llama3.1",
}

DEFAULT_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "ollama": "",
}


def make_provider(
    provider: str,
    model: str | None = None,
    *,
    api_key_env: str | None = None,
    base_url: str | None = None,
    **kwargs: Any,
) -> Provider:
    if provider not in PROVIDERS:
        raise ConfigError(f"unknown provider {provider!r}; expected one of {PROVIDERS}")
    env_name = api_key_env if api_key_env is not None else DEFAULT_KEY_ENV[provider]
    api_key = os.environ.get(env_name) if env_name else None
    config = ProviderConfig(
        provider=provider,
        model=model or DEFAULT_MODELS[provider],
        api_key=api_key or None,
        base_url=base_url,
    )
    if provider == "anthropic":
        from bastion.agent.providers.anthropic import AnthropicProvider

        return AnthropicProvider(config, **kwargs)
    if provider == "openai":
        from bastion.agent.providers.openai import OpenAIProvider

        return OpenAIProvider(config, **kwargs)
    from bastion.agent.providers.ollama import OllamaProvider

    return OllamaProvider(config, **kwargs)


__all__ = ["DEFAULT_KEY_ENV", "DEFAULT_MODELS", "PROVIDERS", "Provider", "make_provider"]
