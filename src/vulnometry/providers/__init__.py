"""Provider registry and model-spec parsing. A spec is provider:model."""

from __future__ import annotations

from ..config import settings
from .base import ChatResponse, Message, Provider, ProviderError, ToolCall
from .openai_compat import AzureFoundryProvider, OllamaProvider, OpenAICompatProvider

PROVIDERS = {
    "ollama": "Local models through Ollama (OpenAI-compatible endpoint)",
    "onprem": "Any OpenAI-compatible server: vLLM, llama.cpp, LM Studio, TGI, Jan",
    "openai": "OpenAI API, and OpenAI-compatible gateways (OpenRouter, Groq, Together...)",
    "codex": "Alias for openai, for Codex-family models",
    "azure": "Azure AI Foundry / Azure OpenAI",
    "foundry": "Alias for azure",
    "bedrock": "AWS Bedrock via the Converse API (Claude, Nova, Llama, Mistral...)",
    "anthropic": "Anthropic Messages API",
    "gemini": "Google Gemini",
}

DEFAULT_MODELS = {
    "ollama": "qwen3:8b",
    "onprem": "local-model",
    "openai": "gpt-4o-mini",
    "codex": "gpt-4o-mini",
    "azure": "",
    "foundry": "",
    "bedrock": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "anthropic": "claude-sonnet-4-6",
    "gemini": "gemini-2.0-flash",
}


def parse_spec(spec: str) -> tuple[str, str]:
    """'bedrock:us.anthropic.claude-x:0' -> ('bedrock', 'us.anthropic.claude-x:0')"""
    spec = (spec or "").strip()
    if not spec:
        raise ProviderError("registry", "no model specified", "pass --model or set VULNOMETRY_MODEL")
    provider, _, model = spec.partition(":")
    provider = provider.lower()
    if provider not in PROVIDERS:
        return "ollama", spec
    return provider, (model or DEFAULT_MODELS.get(provider, ""))


def get_provider(spec: str | None = None) -> Provider:
    cfg = settings()
    spec = spec or cfg.default_model
    if not spec:
        raise ProviderError(
            "registry",
            "no model configured",
            "try --model ollama:qwen3 , or set VULNOMETRY_MODEL. Run `vulnometry providers` to see what is reachable.",
        )

    provider, model = parse_spec(spec)

    if provider == "ollama":
        return OllamaProvider(model=model or DEFAULT_MODELS["ollama"])

    if provider == "onprem":
        return OpenAICompatProvider(
            model=model, base_url=cfg.onprem_base_url, api_key=cfg.onprem_api_key, name="onprem"
        )

    if provider in ("openai", "codex"):
        return OpenAICompatProvider(
            model=model or DEFAULT_MODELS["openai"],
            base_url=cfg.openai_base_url,
            api_key=cfg.openai_api_key or "not-needed",
            name="openai",
        )

    if provider in ("azure", "foundry"):
        return AzureFoundryProvider(model=model or (cfg.azure_deployment or ""))

    if provider == "bedrock":
        from .bedrock import BedrockProvider

        return BedrockProvider(model=model or DEFAULT_MODELS["bedrock"])

    if provider == "anthropic":
        from .anthropic import AnthropicProvider

        return AnthropicProvider(model=model or DEFAULT_MODELS["anthropic"])

    if provider == "gemini":
        from .gemini import GeminiProvider

        return GeminiProvider(model=model or DEFAULT_MODELS["gemini"])

    raise ProviderError("registry", f"unknown provider {provider!r}", f"known: {', '.join(PROVIDERS)}")


def configured_providers() -> dict[str, dict]:
    """What looks usable right now, based purely on configuration."""
    cfg = settings()
    return {
        "ollama": {
            "description": PROVIDERS["ollama"],
            "configured": True,
            "detail": cfg.ollama_host,
            "example": "--model ollama:qwen3",
        },
        "onprem": {
            "description": PROVIDERS["onprem"],
            "configured": True,
            "detail": cfg.onprem_base_url,
            "example": "--model onprem:my-model",
        },
        "openai": {
            "description": PROVIDERS["openai"],
            "configured": bool(cfg.openai_api_key),
            "detail": cfg.openai_base_url,
            "example": "--model openai:gpt-4o-mini",
            "needs": "OPENAI_API_KEY",
        },
        "azure": {
            "description": PROVIDERS["azure"],
            "configured": bool(cfg.azure_endpoint and cfg.azure_api_key),
            "detail": cfg.azure_endpoint or "(unset)",
            "example": "--model azure:<deployment-name>",
            "needs": "AZURE_AI_ENDPOINT + AZURE_AI_API_KEY",
        },
        "bedrock": {
            "description": PROVIDERS["bedrock"],
            "configured": _boto3_available(),
            "detail": cfg.aws_region or "(no region set)",
            "example": "--model bedrock:us.anthropic.claude-sonnet-4-20250514-v1:0",
            "needs": "pip install 'vulnometry-cve[bedrock]' + AWS credentials",
        },
        "anthropic": {
            "description": PROVIDERS["anthropic"],
            "configured": bool(cfg.anthropic_api_key),
            "detail": cfg.anthropic_base_url,
            "example": "--model anthropic:claude-sonnet-4-6",
            "needs": "ANTHROPIC_API_KEY",
        },
        "gemini": {
            "description": PROVIDERS["gemini"],
            "configured": bool(cfg.google_api_key),
            "detail": "generativelanguage.googleapis.com",
            "example": "--model gemini:gemini-2.0-flash",
            "needs": "GOOGLE_API_KEY",
        },
    }


def _boto3_available() -> bool:
    try:
        import boto3  # noqa: F401,PLC0415

        return True
    except ImportError:
        return False


__all__ = [
    "ChatResponse",
    "Message",
    "Provider",
    "ProviderError",
    "ToolCall",
    "PROVIDERS",
    "parse_spec",
    "get_provider",
    "configured_providers",
]
