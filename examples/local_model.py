"""Run the analyst loop on a local model.

    ollama serve && ollama pull qwen3
    python local_model.py

Change MODEL and nothing else moves:
    bedrock:us.anthropic.claude-sonnet-4-20250514-v1:0
    azure:my-gpt4o-deployment
    openai:gpt-4o-mini
    onprem:Qwen2.5-72B-Instruct
"""

import asyncio

from vulnometry.analyst import run_analysis
from vulnometry.providers import get_provider

MODEL = "ollama:qwen3"

QUESTIONS = [
    "What do we run, and which of it is internet-facing?",
    "Is CVE-2021-44228 urgent for us? Check every asset, not just the worst one.",
    "What was added to the KEV catalogue in the last week, and does any of it touch us?",
]


async def main() -> None:
    provider = get_provider(MODEL)

    status = await provider.check()
    if not status.get("ok"):
        print(f"Cannot reach {MODEL}: {status.get('detail')}")
        print("Hint:", status.get("hint", ""))
        return

    for question in QUESTIONS:
        print("=" * 72)
        print("Q:", question, "\n")
        run = await run_analysis(
            question, provider=provider,
            on_step=lambda s: print(f"  -> {s.name}") if s.kind == "action" else None,
        )
        print("\n" + run.answer)
        print(f"\n[{run.calls} actions across {run.turns} turns]\n")

    await provider.aclose()


if __name__ == "__main__":
    asyncio.run(main())
