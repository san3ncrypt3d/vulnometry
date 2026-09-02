"""Export the action registry in each vendor's dialect."""

from __future__ import annotations

from ..providers.anthropic import to_anthropic_tools
from ..providers.bedrock import to_bedrock_tools
from ..providers.gemini import to_gemini_tools
from ..providers.openai_compat import to_openai_tools
from ..registry import action_specs, invoke


def openai_actions() -> list[dict]:
    """OpenAI, Codex, Ollama, vLLM, Azure, OpenRouter, Groq, Together."""
    return to_openai_tools(action_specs())


def anthropic_actions() -> list[dict]:
    return to_anthropic_tools(action_specs())


def bedrock_actions() -> dict:
    return to_bedrock_tools(action_specs())


def gemini_actions() -> list[dict]:
    return to_gemini_tools(action_specs())


def neutral_actions() -> list[dict]:
    return action_specs()


async def run_action(name: str, arguments) -> dict:
    return await invoke(name, arguments)


DIALECTS = {
    "openai": openai_actions,
    "anthropic": anthropic_actions,
    "bedrock": bedrock_actions,
    "gemini": gemini_actions,
    "neutral": neutral_actions,
}
