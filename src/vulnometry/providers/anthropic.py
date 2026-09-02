"""Anthropic Messages API (native, not via Bedrock)."""

from __future__ import annotations

import httpx

from ..config import settings
from .base import ChatResponse, Message, ProviderError, ToolCall, parse_arguments

API_VERSION = "2023-06-01"


def to_anthropic_tools(specs: list[dict]) -> list[dict]:
    return [
        {"name": s["name"], "description": s["description"], "input_schema": s["input_schema"]}
        for s in specs
    ]


def _to_wire(messages: list[Message]) -> tuple[str, list[dict]]:
    system_parts: list[str] = []
    wire: list[dict] = []

    for msg in messages:
        if msg.role == "system":
            system_parts.append(msg.content)
        elif msg.role == "tool":
            block = {
                "type": "tool_result",
                "tool_use_id": msg.tool_call_id,
                "content": msg.content,
            }
            if wire and wire[-1]["role"] == "user" and isinstance(wire[-1]["content"], list) \
                    and wire[-1]["content"] and wire[-1]["content"][0].get("type") == "tool_result":
                wire[-1]["content"].append(block)
            else:
                wire.append({"role": "user", "content": [block]})
        elif msg.role == "assistant":
            content: list[dict] = []
            if msg.content:
                content.append({"type": "text", "text": msg.content})
            for call in msg.tool_calls:
                content.append(
                    {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}
                )
            wire.append({"role": "assistant", "content": content or [{"type": "text", "text": ""}]})
        else:
            wire.append({"role": "user", "content": msg.content})

    return "\n\n".join(p for p in system_parts if p), wire


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, api_key: str | None = None, base_url: str | None = None):
        cfg = settings()
        self.model = model
        self.api_key = api_key or cfg.anthropic_api_key or ""
        self.base_url = (base_url or cfg.anthropic_base_url).rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(settings().timeout * 4))
        return self._client

    async def aclose(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def chat(self, messages: list[Message], tools: list[dict] | None = None, **kwargs) -> ChatResponse:
        if not self.api_key:
            raise ProviderError(self.name, "no API key", "set ANTHROPIC_API_KEY")

        cfg = settings()
        system, wire = _to_wire(messages)
        body: dict = {
            "model": self.model,
            "messages": wire,
            "max_tokens": kwargs.get("max_tokens", cfg.max_tokens),
            "temperature": kwargs.get("temperature", cfg.temperature),
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = to_anthropic_tools(tools)

        client = await self._http()
        try:
            resp = await client.post(
                f"{self.base_url}/v1/messages",
                json=body,
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": API_VERSION,
                    "content-type": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise ProviderError(self.name, f"request failed: {exc}") from exc

        if resp.status_code >= 400:
            raise ProviderError(self.name, f"HTTP {resp.status_code}: {resp.text[:400]}")

        payload = resp.json()
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in payload.get("content", []) or []:
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                calls.append(
                    ToolCall(
                        id=block.get("id", ""),
                        name=block.get("name", ""),
                        arguments=parse_arguments(block.get("input")),
                    )
                )

        return ChatResponse(
            text="".join(text_parts),
            tool_calls=calls,
            finish_reason=payload.get("stop_reason", ""),
            raw=payload,
            usage=payload.get("usage", {}) or {},
        )

    async def check(self) -> dict:
        if not self.api_key:
            return {"ok": False, "detail": "ANTHROPIC_API_KEY not set"}
        try:
            await self.chat([Message(role="user", content="ping")], max_tokens=5)
            return {"ok": True, "model": self.model}
        except ProviderError as exc:
            return {"ok": False, "detail": str(exc)}
