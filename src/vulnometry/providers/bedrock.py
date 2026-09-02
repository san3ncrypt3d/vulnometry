"""AWS Bedrock via the Converse API. boto3 runs in a worker thread."""

from __future__ import annotations

import asyncio
from typing import Any

from ..config import settings
from .base import ChatResponse, Message, ProviderError, ToolCall

_SUGGESTED = {
    "claude": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "nova": "us.amazon.nova-pro-v1:0",
    "llama": "us.meta.llama3-3-70b-instruct-v1:0",
    "mistral": "mistral.mistral-large-2407-v1:0",
}


def to_bedrock_tools(specs: list[dict]) -> dict:
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": s["name"],
                    "description": s["description"],
                    "inputSchema": {"json": s["input_schema"]},
                }
            }
            for s in specs
        ]
    }


def _to_wire(messages: list[Message]) -> tuple[list[dict], list[dict]]:
    system: list[dict] = []
    wire: list[dict] = []

    for msg in messages:
        if msg.role == "system":
            system.append({"text": msg.content})
        elif msg.role == "tool":
            block = {
                "toolResult": {
                    "toolUseId": msg.tool_call_id,
                    "content": [{"text": msg.content}],
                    "status": "success",
                }
            }
            if wire and wire[-1]["role"] == "user" and "toolResult" in (wire[-1]["content"][0] if wire[-1]["content"] else {}):
                wire[-1]["content"].append(block)
            else:
                wire.append({"role": "user", "content": [block]})
        elif msg.role == "assistant":
            content: list[dict] = []
            if msg.content:
                content.append({"text": msg.content})
            for call in msg.tool_calls:
                content.append(
                    {"toolUse": {"toolUseId": call.id, "name": call.name, "input": call.arguments}}
                )
            wire.append({"role": "assistant", "content": content or [{"text": ""}]})
        else:
            wire.append({"role": "user", "content": [{"text": msg.content}]})

    return system, wire


class BedrockProvider:
    name = "bedrock"

    def __init__(self, model: str, region: str | None = None, profile: str | None = None):
        cfg = settings()
        self.model = model or _SUGGESTED["claude"]
        self.region = region or cfg.aws_region or "us-east-1"
        self.profile = profile or cfg.aws_profile
        self._client = None

    def _boto(self):
        if self._client is None:
            try:
                import boto3  # noqa: PLC0415
            except ImportError as exc:
                raise ProviderError(
                    self.name, "boto3 is not installed", "pip install 'vulnometry[bedrock]'"
                ) from exc
            session_kwargs: dict[str, Any] = {"region_name": self.region}
            if self.profile:
                session_kwargs["profile_name"] = self.profile
            import boto3.session  # noqa: PLC0415

            session = boto3.session.Session(**session_kwargs)
            self._client = session.client("bedrock-runtime")
        return self._client

    async def aclose(self) -> None:
        self._client = None

    async def chat(self, messages: list[Message], tools: list[dict] | None = None, **kwargs) -> ChatResponse:
        cfg = settings()
        system, wire = _to_wire(messages)

        request: dict = {
            "modelId": self.model,
            "messages": wire,
            "inferenceConfig": {
                "maxTokens": kwargs.get("max_tokens", cfg.max_tokens),
                "temperature": kwargs.get("temperature", cfg.temperature),
            },
        }
        if system:
            request["system"] = system
        if tools:
            request["toolConfig"] = to_bedrock_tools(tools)

        client = self._boto()
        try:
            payload = await asyncio.to_thread(lambda: client.converse(**request))
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(self.name, str(exc), self._hint(exc)) from exc

        message = (payload.get("output", {}) or {}).get("message", {}) or {}
        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in message.get("content", []) or []:
            if "text" in block:
                text_parts.append(block["text"])
            elif "toolUse" in block:
                use = block["toolUse"]
                calls.append(
                    ToolCall(
                        id=use.get("toolUseId", ""),
                        name=use.get("name", ""),
                        arguments=use.get("input") or {},
                    )
                )

        return ChatResponse(
            text="".join(text_parts),
            tool_calls=calls,
            finish_reason=payload.get("stopReason", ""),
            raw=payload,
            usage=payload.get("usage", {}) or {},
        )

    async def check(self) -> dict:
        try:
            await self.chat([Message(role="user", content="ping")], max_tokens=5)
            return {"ok": True, "model": self.model, "region": self.region}
        except ProviderError as exc:
            return {"ok": False, "detail": str(exc)}

    def _hint(self, exc: Exception) -> str:
        text = str(exc)
        if "AccessDeniedException" in text:
            return f"request access to {self.model} in the Bedrock console for region {self.region}"
        if "ValidationException" in text and "model" in text.lower():
            return f"check the model id; cross-region profiles usually need a 'us.' / 'eu.' prefix. Try: {_SUGGESTED['claude']}"
        if "ExpiredToken" in text or "UnrecognizedClient" in text:
            return "refresh your AWS credentials (aws sso login)"
        if "ResourceNotFoundException" in text:
            return f"{self.model} is not available in {self.region}"
        return ""
