"""Every OpenAI-shaped /chat/completions endpoint, local or hosted."""

from __future__ import annotations

from typing import Any

import httpx

from ..config import settings
from .base import ChatResponse, Message, ProviderError, ToolCall, parse_arguments


def _to_wire(messages: list[Message]) -> list[dict]:
    wire: list[dict] = []
    for msg in messages:
        if msg.role == "tool":
            wire.append({"role": "tool", "tool_call_id": msg.tool_call_id, "content": msg.content})
            continue
        entry: dict = {"role": msg.role, "content": msg.content or ""}
        if msg.tool_calls:
            entry["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": _dump(tc.arguments)},
                }
                for tc in msg.tool_calls
            ]
            entry["content"] = msg.content or ""
        wire.append(entry)
    return wire


def _dump(value: Any) -> str:
    import json

    return json.dumps(value or {})


def to_openai_tools(specs: list[dict]) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": spec["name"],
                "description": spec["description"],
                "parameters": spec["input_schema"],
            },
        }
        for spec in specs
    ]


class OpenAICompatProvider:
    """Any server speaking POST {base_url}/chat/completions."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str = "not-needed",
        name: str = "openai-compat",
        extra_headers: dict | None = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.name = name
        self.extra_headers = extra_headers or {}
        self._client: httpx.AsyncClient | None = None


    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key and self.api_key != "not-needed":
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _params(self) -> dict:
        return {}

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(settings().timeout * 4))
        return self._client

    async def aclose(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()


    async def chat(self, messages: list[Message], tools: list[dict] | None = None, **kwargs) -> ChatResponse:
        cfg = settings()
        body: dict = {
            "model": self.model,
            "messages": _to_wire(messages),
            "temperature": kwargs.get("temperature", cfg.temperature),
            "max_tokens": kwargs.get("max_tokens", cfg.max_tokens),
        }
        if tools:
            body["tools"] = to_openai_tools(tools)
            body["tool_choice"] = kwargs.get("tool_choice", "auto")

        client = await self._http()
        try:
            resp = await client.post(self._url(), json=body, headers=self._headers(), params=self._params())
        except httpx.HTTPError as exc:
            raise ProviderError(self.name, f"could not reach {self._url()}: {exc}", self._connect_hint()) from exc

        if resp.status_code >= 400:
            raise ProviderError(self.name, f"HTTP {resp.status_code}: {resp.text[:400]}", self._error_hint(resp.status_code))

        payload = resp.json()
        choices = payload.get("choices") or []
        if not choices:
            raise ProviderError(self.name, "response contained no choices")
        message = choices[0].get("message", {}) or {}

        calls = []
        for index, call in enumerate(message.get("tool_calls") or []):
            function = call.get("function", {}) or {}
            calls.append(
                ToolCall(
                    id=call.get("id") or f"call_{index}",
                    name=function.get("name", ""),
                    arguments=parse_arguments(function.get("arguments")),
                )
            )

        return ChatResponse(
            text=message.get("content") or "",
            tool_calls=calls,
            finish_reason=choices[0].get("finish_reason", ""),
            raw=payload,
            usage=payload.get("usage", {}) or {},
        )

    async def check(self) -> dict:
        client = await self._http()
        try:
            resp = await client.get(f"{self.base_url}/models", headers=self._headers(), params=self._params(), timeout=8.0)
            if resp.status_code >= 400:
                return {"ok": False, "detail": f"HTTP {resp.status_code}", "hint": self._error_hint(resp.status_code)}
            names = [m.get("id", "") for m in (resp.json().get("data") or [])]
            ok = (not names) or (self.model in names)
            return {
                "ok": True,
                "endpoint": self.base_url,
                "model": self.model,
                "model_available": ok,
                "models_seen": len(names),
                "detail": "" if ok else f"{self.model!r} not in the server's model list",
            }
        except httpx.HTTPError as exc:
            return {"ok": False, "detail": str(exc), "hint": self._connect_hint()}


    def _connect_hint(self) -> str:
        return f"is the server at {self.base_url} running?"

    def _error_hint(self, status: int) -> str:
        if status in (401, 403):
            return "check the API key for this provider"
        if status == 404:
            return f"the model {self.model!r} may not exist on this endpoint"
        if status == 429:
            return "rate limited, slow down or raise your quota"
        return ""


class OllamaProvider(OpenAICompatProvider):
    """Ollama via its OpenAI-compatible endpoint. Needs a tool-calling model."""

    def __init__(self, model: str, host: str | None = None):
        host = (host or settings().ollama_host).rstrip("/")
        super().__init__(model=model, base_url=f"{host}/v1", api_key="ollama", name="ollama")
        self.host = host

    def _connect_hint(self) -> str:
        return f"start Ollama with `ollama serve`, then `ollama pull {self.model}`"

    def _error_hint(self, status: int) -> str:
        if status == 404:
            return f"run `ollama pull {self.model}`"
        return super()._error_hint(status)


class AzureFoundryProvider(OpenAICompatProvider):
    """Azure AI Foundry and Azure OpenAI. Endpoint shape is auto-detected."""

    def __init__(self, model: str, endpoint: str | None = None, api_key: str | None = None, api_version: str | None = None):
        cfg = settings()
        endpoint = (endpoint or cfg.azure_endpoint or "").rstrip("/")
        if not endpoint:
            raise ProviderError("azure", "no endpoint configured", "set AZURE_AI_ENDPOINT or AZURE_OPENAI_ENDPOINT")
        self.api_version = api_version or cfg.azure_api_version
        self.is_foundry = "services.ai.azure.com" in endpoint or "/models" in endpoint
        super().__init__(
            model=model,
            base_url=endpoint,
            api_key=api_key or cfg.azure_api_key or "",
            name="azure",
        )

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            if self.api_key.startswith("ey") and self.api_key.count(".") == 2:
                headers["Authorization"] = f"Bearer {self.api_key}"
            else:
                headers["api-key"] = self.api_key
        return headers

    def _url(self) -> str:
        if self.is_foundry:
            return f"{self.base_url}/models/chat/completions"
        return f"{self.base_url}/openai/deployments/{self.model}/chat/completions"

    def _params(self) -> dict:
        return {"api-version": self.api_version}

    async def check(self) -> dict:
        try:
            await self.chat([Message(role="user", content="ping")], max_tokens=5)
            return {"ok": True, "endpoint": self.base_url, "model": self.model, "flavour": "foundry" if self.is_foundry else "azure-openai"}
        except ProviderError as exc:
            return {"ok": False, "detail": str(exc), "hint": "check AZURE_AI_ENDPOINT, AZURE_AI_API_KEY and the deployment name"}

    def _error_hint(self, status: int) -> str:
        if status == 404:
            return f"deployment {self.model!r} not found, check the deployment name and api-version ({self.api_version})"
        if status in (401, 403):
            return "set AZURE_AI_API_KEY, or pass an Entra ID bearer token"
        return super()._error_hint(status)
