"""HTTP and OpenAPI surface, for everything that is not Python."""

from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The HTTP surface needs FastAPI. Install it with: pip install 'vulnometry[service]'"
    ) from exc

from .. import __version__
from ..assessment import assess_portfolio, portfolio_summary
from ..inventory import Inventory
from ..registry import action_specs, invoke
from ..schema import harvest_cve_ids
from .schemas import DIALECTS


class AssetIn(BaseModel):
    name: str = ""
    tier: int | None = None
    owner: str = ""
    business_unit: str = ""
    environment: str = ""
    internet_exposed: bool | None = None
    deployed: bool | None = None
    data_classification: str = ""
    regimes: list[str] = Field(default_factory=list)
    compensating_controls: list[str] = Field(default_factory=list)


class MeasureIn(BaseModel):
    cve_ids: list[str] = Field(default_factory=list)
    text: str = Field("", description="Free text to harvest CVE identifiers from.")
    lens: str = Field("full", description="signal | full | forensic")
    asset: AssetIn | None = None
    min_index: float = 0.0


class AskIn(BaseModel):
    question: str
    model: str | None = Field(None, description="ollama:qwen3, bedrock:us.anthropic..., azure:my-deployment, ...")


class ActionIn(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


def create_app() -> FastAPI:
    app = FastAPI(
        title="vulnometry",
        version=__version__,
        description=(
            "Measures what a vulnerability is worth to your business. Business Exposure "
            "Index = Threat x Reachability x Consequence, over NVD, EPSS, CISA KEV, OSV "
            "and GitHub Security Advisories."
        ),
    )
    state: dict = {"last": [], "summary": {}}

    @app.get("/health")
    async def health():
        return await invoke("diagnostics", {})

    @app.get("/inventory")
    async def inventory():
        return Inventory.discover().to_dict()

    @app.get("/actions")
    async def actions():
        return {"actions": action_specs()}

    @app.get("/actions/{dialect}")
    async def actions_in_dialect(dialect: str):
        if dialect not in DIALECTS:
            raise HTTPException(404, f"unknown dialect {dialect!r}; try: {', '.join(DIALECTS)}")
        return {"dialect": dialect, "actions": DIALECTS[dialect]()}

    @app.post("/actions/{name}")
    async def run_one(name: str, body: ActionIn):
        result = await invoke(name, body.arguments)
        if isinstance(result, dict) and str(result.get("error", "")).startswith("unknown action"):
            raise HTTPException(404, result["error"])
        return result

    @app.post("/measure")
    async def measure(body: MeasureIn):
        ids = list(body.cve_ids)
        if body.text:
            ids.extend(harvest_cve_ids(body.text))
        if not ids:
            raise HTTPException(400, "supply cve_ids, or text containing CVE identifiers")

        asset = body.asset.model_dump() if body.asset else None
        results = await assess_portfolio(
            ids[:250], inventory=Inventory.discover(), lens=body.lens, asset=asset
        )
        summary = portfolio_summary(results)
        kept = [r for r in results if r.exposure.index >= body.min_index]
        state["last"], state["summary"] = kept, summary
        return {"summary": summary, "findings": [r.to_dict() for r in kept]}

    @app.post("/ask")
    async def ask(body: AskIn):
        from ..analyst import run_analysis

        run = await run_analysis(body.question, model=body.model)
        return {
            "answer": run.answer,
            "provider": run.provider,
            "model": run.model,
            "actions_used": run.actions_used(),
            "turns": run.turns,
            "usage": run.usage,
        }

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        import tempfile
        from pathlib import Path

        from ..report import build_dashboard

        if not state["last"]:
            return HTMLResponse(
                "<h1>Nothing measured yet</h1><p>POST to <code>/measure</code> first.</p>", status_code=404
            )
        target = Path(tempfile.gettempdir()) / "vulnometry-dashboard.html"
        build_dashboard(state["last"], target, state["summary"])
        return HTMLResponse(target.read_text(encoding="utf-8"))

    return app


def main(host: str = "127.0.0.1", port: int = 8080) -> None:
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    main()
