"""Google Gemini (AI Studio endpoint). Vertex works by changing base_url."""

from __future__ import annotations

import httpx

from ..config import settings
from .base import ChatResponse, Message, ProviderError, ToolCall

BASE = "https://generativelanguage.googleapis.com/v1beta"

_ALLOWED = {"type", "description", "enum", "properties", "required", "items", "nullable"}


def _sanitise(schema: dict) -> dict:
    out = {}
    for key, value in (schema or {}).items():
        if key not in _ALLOWED:
            continue
        if key == "properties" and isinstance(value, dict):
            out[key] = {k: _sanitise(v) for k, v in value.items()}
        elif key == "items" and isinstance(value, dict):
            out[key] = _sanitise(value)
        else:
            out[key] = value
    out.setdefault("type", "object")
    return out


def to_gemini_tools(specs: list[dict]) -> list[dict]:
    return [
        {
            "function_declarations": [
                {
                    "name": s["name"],
                    "description": s["description"],
                    "parameters": _sanitise(s["input_schema"]),
                }
                for s in specs
            ]
        }
    ]


def _to_wire(messages: list[Message]) -> tuple[dict | None, list[dict]]:
    system = None
    contents: list[dict] = []
    for msg in messages:
        if msg.role == "system":
            system = {"parts": [{"text": msg.content}]}
        elif msg.role == "tool":
            contents.append(
                {
                    "role": "user",
                    "parts": [{"functionResponse": {"name": msg.name or msg.tool_call_id, "response": {"result": msg.content}}}],
                }
            )
        elif msg.role == "assistant":
            parts: list[dict] = []
            if msg.content:
                parts.append({"text": msg.content})
            for call in msg.tool_calls:
                parts.append({"functionCall": {"name": call.name, "args": call.arguments}})
            contents.append({"role": "model", "parts": parts or [{"text": ""}]})
        else:
            contents.append({"role": "user", "parts": [{"text": msg.content}]})
    return system, contents


class GeminiProvider:
    name = "gemini"

    def __init__(self, model: str, api_key: str | None = None, base_url: str = BASE):
        self.model = model
        self.api_key = api_key or settings().google_api_key or ""
        self.base_url = base_url.rstrip("/")
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
            raise ProviderError(self.name, "no API key", "set GOOGLE_API_KEY or GEMINI_API_KEY")

        cfg = settings()
        system, contents = _to_wire(messages)
        body: dict = {
            "contents": contents,
            "generationConfig": {
                "temperature": kwargs.get("temperature", cfg.temperature),
                "maxOutputTokens": kwargs.get("max_tokens", cfg.max_tokens),
            },
        }
        if system:
            body["systemInstruction"] = system
        if tools:
            body["tools"] = to_gemini_tools(tools)

        client = await self._http()
        url = f"{self.base_url}/models/{self.model}:generateContent"
        try:
            resp = await client.post(url, json=body, params={"key": self.api_key})
        except httpx.HTTPError as exc:
            raise ProviderError(self.name, f"request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise ProviderError(self.name, f"HTTP {resp.status_code}: {resp.text[:400]}")

        payload = resp.json()
        candidates = payload.get("candidates") or []
        if not candidates:
            raise ProviderError(self.name, "no candidates returned (possibly a safety block)")

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for index, part in enumerate((candidates[0].get("content", {}) or {}).get("parts", []) or []):
            if "text" in part:
                text_parts.append(part["text"])
            elif "functionCall" in part:
                fn = part["functionCall"]
                calls.append(
                    ToolCall(id=f"{fn.get('name', 'call')}_{index}", name=fn.get("name", ""), arguments=fn.get("args") or {})
                )

        return ChatResponse(
            text="".join(text_parts),
            tool_calls=calls,
            finish_reason=candidates[0].get("finishReason", ""),
            raw=payload,
            usage=payload.get("usageMetadata", {}) or {},
        )

    async def check(self) -> dict:
        if not self.api_key:
            return {"ok": False, "detail": "GOOGLE_API_KEY not set"}
        try:
            await self.chat([Message(role="user", content="ping")], max_tokens=5)
            return {"ok": True, "model": self.model}
        except ProviderError as exc:
            return {"ok": False, "detail": str(exc)}
