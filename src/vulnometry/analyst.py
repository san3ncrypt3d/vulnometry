"""Tool-calling loop, written once against the provider interface."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .config import settings
from .providers import Message, Provider, ProviderError, get_provider
from .registry import action_specs, invoke

BRIEF = """You are a vulnerability exposure analyst. Your actions reach NVD, FIRST EPSS, the CISA KEV catalogue, OSV and GitHub Security Advisories, and they know the organisation's own asset inventory.

How to work:
- Call actions for every fact. Never recall CVSS scores, EPSS values, KEV status or fixed versions from memory; they change daily and you will be wrong.
- Prefer measure_exposure for one CVE and measure_portfolio for several.
- Call read_inventory before you assume anything about the environment. If the user names a system, pass asset_name so the real profile is used.
- If the user mentions internet exposure, criticality, deployment status or regulatory scope, pass it in the asset argument. It changes the measurement, not just the wording.
- The Business Exposure Index and the verdict are computed deterministically. Report them and explain the three factors. Never invent a number or overrule one.
- Lead with the verdict: Contain, Remediate, Schedule or Accept. Then the reason. Then the fix and the date.
- Say what is unknown. A missing EPSS score or an asset that is not in the inventory is information, and low confidence should be stated plainly.
- Be brief. Somebody is reading this during an incident."""


@dataclass
class Step:
    kind: str
    name: str = ""
    data: Any = None


@dataclass
class Analysis:
    answer: str = ""
    steps: list[Step] = field(default_factory=list)
    turns: int = 0
    calls: int = 0
    usage: dict = field(default_factory=dict)
    provider: str = ""
    model: str = ""

    def actions_used(self) -> list[str]:
        return [s.name for s in self.steps if s.kind == "action"]


async def run_analysis(
    question: str,
    model: str | None = None,
    provider: Provider | None = None,
    brief: str = BRIEF,
    history: list[Message] | None = None,
    max_turns: int | None = None,
    on_step: Callable[[Step], None] | None = None,
    allowed_actions: list[str] | None = None,
) -> Analysis:
    cfg = settings()
    provider = provider or get_provider(model)
    max_turns = max_turns or cfg.max_turns

    specs = action_specs()
    if allowed_actions:
        specs = [s for s in specs if s["name"] in set(allowed_actions)]

    messages: list[Message] = [Message(role="system", content=brief)]
    messages.extend(history or [])
    messages.append(Message(role="user", content=question))

    run = Analysis(provider=getattr(provider, "name", "?"), model=getattr(provider, "model", "?"))

    def emit(step: Step) -> None:
        run.steps.append(step)
        if on_step:
            on_step(step)

    for turn in range(max_turns):
        run.turns = turn + 1
        try:
            response = await provider.chat(messages, tools=specs)
        except ProviderError as exc:
            emit(Step(kind="error", data=str(exc)))
            run.answer = f"Inference failed: {exc}"
            return run

        for key, value in (response.usage or {}).items():
            if isinstance(value, int):
                run.usage[key] = run.usage.get(key, 0) + value

        if not response.wants_tools:
            run.answer = response.text.strip()
            emit(Step(kind="answer", data=run.answer))
            return run

        messages.append(Message(role="assistant", content=response.text, tool_calls=response.tool_calls))

        for call in response.tool_calls:
            run.calls += 1
            emit(Step(kind="action", name=call.name, data=call.arguments))
            result = await invoke(call.name, call.arguments)
            emit(Step(kind="result", name=call.name, data=result))
            messages.append(
                Message(role="tool", name=call.name, tool_call_id=call.id, content=_pack(result))
            )

    messages.append(
        Message(role="user", content="Stop calling actions. Give your final answer from what you already have.")
    )
    try:
        final = await provider.chat(messages, tools=None)
        run.answer = final.text.strip()
    except ProviderError as exc:
        run.answer = f"Ran out of turns and the final call failed: {exc}"
    return run


def _pack(result: Any, limit: int = 20000) -> str:
    """Results go back as JSON text, truncated so small models do not drown."""
    try:
        text = json.dumps(result, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(result)
    if len(text) > limit:
        text = text[:limit] + f'... [truncated; {len(text)} chars total]'
    return text
