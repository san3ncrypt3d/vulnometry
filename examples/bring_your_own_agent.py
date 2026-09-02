"""Take the schemas and the dispatcher into an agent loop you already have.

Each helper returns tool definitions in one vendor's dialect, all built from the
same registry, so an action added once shows up in every one of them:

    openai_actions()     list, for client.chat.completions.create(tools=...)
                         also Ollama, vLLM, Azure, OpenRouter, Groq, Together
    anthropic_actions()  list, for client.messages.create(tools=...)
    bedrock_actions()    dict, for client.converse(toolConfig=...)
    gemini_actions()     list, for model.generate_content(tools=...)

run_action(name, arguments) dispatches a call and returns JSON-safe data. It
never raises; errors come back as an object the model can recover from.
"""

import asyncio
import json

from vulnometry.surfaces.schemas import (
    anthropic_actions,
    bedrock_actions,
    gemini_actions,
    openai_actions,
    run_action,
)


def tool_counts() -> dict[str, int]:
    return {
        "openai": len(openai_actions()),
        "anthropic": len(anthropic_actions()),
        "bedrock": len(bedrock_actions()["tools"]),
        "gemini": len(gemini_actions()[0]["function_declarations"]),
    }


async def main() -> None:
    for dialect, count in tool_counts().items():
        print(f"{dialect:<10} {count} tools")
    print()

    result = await run_action("measure_exposure", {
        "cve_id": "CVE-2021-44228",
        "asset": {
            "name": "checkout-api", "tier": 1, "internet_exposed": True, "deployed": True,
            "data_classification": "restricted", "regimes": ["pci-dss"],
        },
    })
    print(json.dumps(result["exposure"], indent=2))
    print("\nDirective:", result["directive"])


if __name__ == "__main__":
    asyncio.run(main())
