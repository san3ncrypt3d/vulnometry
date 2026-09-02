"""The action registry, read by every surface."""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from .assessment import assess_finding, assess_portfolio, portfolio_summary
from .feeds import advisories as adv_feed
from .feeds import catalogue as kev_feed
from .feeds import probability as epss_feed
from .feeds import record as cve_feed
from .inventory import Inventory
from .schema import harvest_cve_ids

Handler = Callable[..., Awaitable[Any]]

_CVE = {"type": "string", "description": "CVE identifier, e.g. CVE-2021-44228"}

_ASSET_SCHEMA = {
    "type": "object",
    "description": (
        "The business context this CVE lives in. Supplying it is what separates a "
        "priority from a severity rating. Omit a field rather than guessing. Unknown "
        "is treated as uncertainty, which is safer than a confident wrong answer."
    ),
    "properties": {
        "name": {"type": "string"},
        "tier": {"type": "integer", "description": "1 mission-critical, 2 business-important, 3 supporting"},
        "owner": {"type": "string"},
        "business_unit": {"type": "string"},
        "environment": {"type": "string", "description": "production | staging | development"},
        "internet_exposed": {"type": "boolean"},
        "deployed": {"type": "boolean", "description": "false collapses exposure to zero"},
        "data_classification": {"type": "string", "description": "public | internal | confidential | restricted"},
        "regimes": {"type": "array", "items": {"type": "string"}, "description": "pci-dss, hipaa, sox, gdpr..."},
        "compensating_controls": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": False,
}


@dataclass
class Action:
    name: str
    description: str
    schema: dict
    handler: Handler

    def json_schema(self) -> dict:
        schema = dict(self.schema)
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})
        schema.setdefault("additionalProperties", False)
        return schema


def _inventory(path: str = "") -> Inventory:
    return Inventory.discover(path or None)


async def _measure(cve_id: str, asset: dict | None = None, asset_name: str = "", lens: str = "full") -> dict:
    result = await assess_finding(
        cve_id, asset=asset, inventory=_inventory(), asset_name=asset_name, lens=lens
    )
    return result.to_dict()


async def _measure_many(
    cve_ids: list[str] | None = None,
    text: str = "",
    asset: dict | None = None,
    lens: str = "signal",
    min_index: float = 0.0,
) -> dict:
    ids = list(cve_ids or [])
    if text:
        ids.extend(harvest_cve_ids(text))
    if not ids:
        return {"error": "no CVE identifiers supplied in cve_ids or found in text"}

    results = await assess_portfolio(ids[:250], inventory=_inventory(), lens=lens, asset=asset)
    kept = [r for r in results if r.exposure.index >= min_index]
    return {
        "summary": portfolio_summary(results),
        "findings": [
            {
                "cve": r.cve_id,
                "bei": r.exposure.index,
                "verdict": r.exposure.verdict,
                "threat": r.exposure.threat,
                "reachability": r.exposure.reachability,
                "consequence": r.exposure.consequence,
                "asset": r.asset,
                "owner": r.owner,
                "due_by": r.due_by,
                "directive": r.directive,
                "fixes": r.fixes[:3],
                "confidence": r.exposure.confidence,
            }
            for r in kept
        ],
    }


async def _compare_contexts(cve_id: str, contexts: list[dict]) -> dict:
    """Same CVE, several places you run it."""
    if not contexts:
        return {"error": "provide at least one context in 'contexts'"}
    results = []
    for context in contexts[:12]:
        assessment = await assess_finding(cve_id, asset=context, lens="full")
        results.append({
            "asset": assessment.asset or context.get("name", "(unnamed)"),
            "bei": assessment.exposure.index,
            "verdict": assessment.exposure.verdict,
            "reachability": assessment.exposure.reachability,
            "consequence": assessment.exposure.consequence,
            "due_by": assessment.due_by,
            "directive": assessment.directive,
        })
    results.sort(key=lambda r: r["bei"], reverse=True)
    spread = results[0]["bei"] - results[-1]["bei"] if len(results) > 1 else 0.0
    return {
        "cve": cve_id.upper(),
        "threat_is_constant": results[0].get("bei") is not None,
        "spread": round(spread, 1),
        "note": (
            "Threat is identical everywhere; the difference is entirely reachability and "
            "consequence. That spread is the value of knowing your own environment."
        ),
        "by_context": results,
    }


async def _cve_record(cve_id: str) -> dict:
    return (await cve_feed.fetch(cve_id)).to_dict()


async def _find_cves(keyword: str = "", cpe_name: str = "", limit: int = 15, changed_within_days: int | None = None) -> dict:
    records = await cve_feed.search(
        keyword=keyword, cpe_name=cpe_name, limit=limit, changed_within_days=changed_within_days
    )
    return {
        "count": len(records),
        "results": [
            {
                "cve": r.cve_id,
                "published": r.published,
                "cvss": (r.primary_severity().base_score if r.primary_severity() else None),
                "summary": r.summary[:280],
            }
            for r in records
        ],
    }


async def _probabilities(cve_ids: list[str]) -> dict:
    scores = await epss_feed.fetch_many(cve_ids)
    return {cve: score.to_dict() for cve, score in scores.items()}


async def _rising_threats(limit: int = 20, above: float = 0.5) -> dict:
    return {"results": [p.to_dict() for p in await epss_feed.highest(limit=limit, above=above)]}


async def _confirmed(cve_ids: list[str]) -> dict:
    entries = await kev_feed.fetch_many(cve_ids)
    return {
        "confirmed_exploited": [c for c, e in entries.items() if e.confirmed],
        "not_listed": [c for c, e in entries.items() if not e.confirmed],
        "detail": {c: e.to_dict() for c, e in entries.items() if e.confirmed},
    }


async def _kev_new(days: int = 14) -> dict:
    entries = await kev_feed.added_since(days=days)
    return {"days": days, "count": len(entries), "entries": [e.to_dict() for e in entries]}


async def _kev_late() -> dict:
    entries = await kev_feed.past_deadline()
    return {"count": len(entries), "entries": [e.to_dict() for e in entries[:100]]}


async def _component_risk(name: str, ecosystem: str = "", version: str = "") -> dict:
    bulletins = await adv_feed.osv_for_package(name=name, ecosystem=ecosystem, version=version)
    return {
        "component": {"name": name, "ecosystem": ecosystem, "version": version},
        "count": len(bulletins),
        "advisories": [b.to_dict() for b in bulletins[:40]],
    }


async def _sweep_components(components: list[dict]) -> dict:
    findings = await adv_feed.osv_batch(components)
    return {
        "checked": len(components),
        "vulnerable": len(findings),
        "findings": findings,
        "next_step": "Pass the returned CVE ids to measure_portfolio to prioritise them against your inventory.",
    }


async def _remediation(cve_id: str) -> dict:
    ghsa = await adv_feed.ghsa_for_cve(cve_id)
    osv = await adv_feed.osv_for_cve(cve_id)
    bulletins = ghsa + osv
    fixes = []
    for bulletin in bulletins:
        for remedy in bulletin.remedies:
            if remedy.fixed_in:
                fixes.append(f"{remedy.component} {remedy.fixed_in}".strip())
    return {
        "cve": cve_id.upper(),
        "fixed_versions": sorted(set(fixes)),
        "advisories": [b.to_dict() for b in bulletins],
    }


async def _exploit_evidence(cve_id: str, limit: int = 6) -> dict:
    artifacts = await adv_feed.exploit_artifacts(cve_id, limit=limit)
    return {
        "cve": cve_id.upper(),
        "count": len(artifacts),
        "artifacts": [a.to_dict() for a in artifacts],
        "caveat": "Heuristic GitHub search. A match means public code claims to exploit this, not that it works.",
    }


async def _read_inventory(path: str = "") -> dict:
    inventory = _inventory(path)
    return inventory.to_dict()


async def _pull_cve_ids(text: str) -> dict:
    ids = harvest_cve_ids(text)
    return {"count": len(ids), "cve_ids": ids}


async def _diagnostics() -> dict:
    from .config import settings
    from .exposure import MODEL_VERSION
    from .net import FeedError

    checks: dict[str, Any] = {}

    async def probe(label, coro):
        try:
            await coro
            checks[label] = "ok"
        except FeedError as exc:
            checks[label] = f"failed: {exc}"
        except Exception as exc:  # noqa: BLE001
            checks[label] = f"failed: {exc}"

    await probe("nvd", cve_feed.fetch("CVE-2021-44228"))
    await probe("epss", epss_feed.fetch("CVE-2021-44228"))
    await probe("cisa-kev", kev_feed.fetch("CVE-2021-44228"))
    await probe("osv", adv_feed.osv_for_cve("CVE-2021-44228"))
    await probe("ghsa", adv_feed.ghsa_for_cve("CVE-2021-44228"))

    cfg = settings()
    inventory = _inventory()
    return {
        "feeds": checks,
        "exposure_model": MODEL_VERSION,
        "inventory": inventory.coverage,
        "nvd_api_key": bool(cfg.nvd_api_key),
        "github_token": bool(cfg.github_token),
        "state_dir": str(cfg.state_dir),
        "offline": cfg.offline,
        "github_budget": await adv_feed.github_budget(),
    }


ACTIONS: list[Action] = [
    Action(
        name="measure_exposure",
        description=(
            "PRIMARY ACTION. Measure what one CVE is worth to the business in one specific "
            "place. Pulls NVD, EPSS, CISA KEV, OSV and GitHub advisories concurrently, then "
            "computes the Business Exposure Index (Threat x Reachability x Consequence, 0-1000) "
            "and a verdict: Contain, Remediate, Schedule or Accept. Always pass 'asset' when "
            "the user has said anything about their environment, because it changes the answer."
        ),
        schema={
            "type": "object",
            "properties": {
                "cve_id": _CVE,
                "asset": _ASSET_SCHEMA,
                "asset_name": {"type": "string", "description": "Look this asset up in the loaded inventory instead of describing it inline."},
                "lens": {
                    "type": "string",
                    "enum": ["signal", "full", "forensic"],
                    "default": "full",
                    "description": "signal = record+EPSS+KEV; full adds fix versions; forensic adds exploit-artifact discovery.",
                },
            },
            "required": ["cve_id"],
        },
        handler=_measure,
    ),
    Action(
        name="measure_portfolio",
        description=(
            "Measure many CVEs at once and return them ranked, with an executive summary "
            "covering what to contain now, workload per owner, and exposure per business unit. "
            "Accepts a list of ids or free text (a scanner export, an email, release notes)."
        ),
        schema={
            "type": "object",
            "properties": {
                "cve_ids": {"type": "array", "items": {"type": "string"}, "description": "Up to 250 CVE identifiers."},
                "text": {"type": "string", "description": "Free text to harvest CVE identifiers from."},
                "asset": _ASSET_SCHEMA,
                "lens": {"type": "string", "enum": ["signal", "full", "forensic"], "default": "signal"},
                "min_index": {"type": "number", "default": 0, "description": "Drop findings below this BEI."},
            },
        },
        handler=_measure_many,
    ),
    Action(
        name="compare_contexts",
        description=(
            "Measure the same CVE across several environments at once and show how far apart "
            "the answers land. Use this when someone asks why a 'critical' CVE is not being "
            "patched everywhere at the same speed."
        ),
        schema={
            "type": "object",
            "properties": {
                "cve_id": _CVE,
                "contexts": {"type": "array", "items": _ASSET_SCHEMA, "description": "Up to 12 asset profiles."},
            },
            "required": ["cve_id", "contexts"],
        },
        handler=_compare_contexts,
    ),
    Action(
        name="get_cve_record",
        description="The raw public record for a CVE from NVD, falling back to the CVE Program record when NVD is unavailable.",
        schema={"type": "object", "properties": {"cve_id": _CVE}, "required": ["cve_id"]},
        handler=_cve_record,
    ),
    Action(
        name="find_cves",
        description="Search NVD by keyword, CPE name, or recent modification window. Use to discover CVEs affecting a product.",
        schema={
            "type": "object",
            "properties": {
                "keyword": {"type": "string"},
                "cpe_name": {"type": "string"},
                "limit": {"type": "integer", "default": 15, "maximum": 200},
                "changed_within_days": {"type": "integer", "description": "Only CVEs modified in the last N days (max 120)."},
            },
        },
        handler=_find_cves,
    ),
    Action(
        name="get_exploit_probability",
        description="FIRST EPSS probability of exploitation within 30 days, for one or more CVEs. Batched.",
        schema={"type": "object", "properties": {"cve_ids": {"type": "array", "items": {"type": "string"}}}, "required": ["cve_ids"]},
        handler=_probabilities,
    ),
    Action(
        name="rising_threats",
        description="CVEs with the highest exploitation probability right now. A useful daily watchlist.",
        schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20},
                "above": {"type": "number", "default": 0.5, "description": "Minimum EPSS probability, 0-1."},
            },
        },
        handler=_rising_threats,
    ),
    Action(
        name="check_confirmed_exploitation",
        description="Check CVEs against the CISA KEV catalogue. A listing means observed exploitation in the wild, not a prediction.",
        schema={"type": "object", "properties": {"cve_ids": {"type": "array", "items": {"type": "string"}}}, "required": ["cve_ids"]},
        handler=_confirmed,
    ),
    Action(
        name="newly_exploited",
        description="CVEs added to the CISA KEV catalogue in the last N days.",
        schema={"type": "object", "properties": {"days": {"type": "integer", "default": 14}}},
        handler=_kev_new,
    ),
    Action(
        name="past_federal_deadline",
        description="KEV entries whose CISA remediation deadline has already passed. Useful for compliance reporting.",
        schema={"type": "object", "properties": {}},
        handler=_kev_late,
    ),
    Action(
        name="component_risk",
        description="Known vulnerabilities for one open-source component via OSV. Supply a version to get only what actually affects you, plus the fix.",
        schema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Component name, e.g. 'requests' or 'log4j-core'."},
                "ecosystem": {"type": "string", "description": "PyPI, npm, Go, Maven, crates.io, RubyGems, NuGet, Debian, Alpine..."},
                "version": {"type": "string"},
            },
            "required": ["name"],
        },
        handler=_component_risk,
    ),
    Action(
        name="sweep_components",
        description="Batch-check a component list against OSV. Pass [{name, ecosystem, version}]; returns which are vulnerable and to what.",
        schema={
            "type": "object",
            "properties": {
                "components": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}, "ecosystem": {"type": "string"}, "version": {"type": "string"}},
                        "required": ["name"],
                    },
                }
            },
            "required": ["components"],
        },
        handler=_sweep_components,
    ),
    Action(
        name="get_remediation",
        description="Fixed versions and affected ranges for a CVE, from GitHub Security Advisories and OSV. This is the part an engineer can act on.",
        schema={"type": "object", "properties": {"cve_id": _CVE}, "required": ["cve_id"]},
        handler=_remediation,
    ),
    Action(
        name="find_exploit_evidence",
        description="Search public GitHub for exploit material for a CVE. Heuristic: treat matches as an urgency signal, not proof.",
        schema={"type": "object", "properties": {"cve_id": _CVE, "limit": {"type": "integer", "default": 6}}, "required": ["cve_id"]},
        handler=_exploit_evidence,
    ),
    Action(
        name="read_inventory",
        description="Show the loaded business inventory: assets, tiers, owners, coverage. Call this first to learn what environments exist before measuring anything.",
        schema={"type": "object", "properties": {"path": {"type": "string", "description": "Optional path to an inventory file."}}},
        handler=_read_inventory,
    ),
    Action(
        name="harvest_cve_ids",
        description="Pull every CVE identifier out of arbitrary text. Offline and instant.",
        schema={"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
        handler=_pull_cve_ids,
    ),
    Action(
        name="diagnostics",
        description="Probe every feed, report which credentials are configured and how much inventory is loaded. Run this first when something looks wrong.",
        schema={"type": "object", "properties": {}},
        handler=_diagnostics,
    ),
]

ACTIONS_BY_NAME: dict[str, Action] = {a.name: a for a in ACTIONS}


def action_specs() -> list[dict]:
    """Neutral specs. Surfaces translate these into their own dialect."""
    return [{"name": a.name, "description": a.description, "input_schema": a.json_schema()} for a in ACTIONS]


async def invoke(name: str, arguments: dict | str | None = None) -> dict:
    """Run an action. Never raises; errors come back as objects."""
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError:
            return {"error": f"arguments for {name} were not valid JSON"}
    arguments = dict(arguments or {})

    action = ACTIONS_BY_NAME.get(name)
    if action is None:
        return {"error": f"unknown action {name!r}", "available": sorted(ACTIONS_BY_NAME)}

    accepted = set(inspect.signature(action.handler).parameters)
    ignored = [k for k in arguments if k not in accepted]
    filtered = {k: v for k, v in arguments.items() if k in accepted}

    try:
        result = await action.handler(**filtered)
    except TypeError as exc:
        return {"error": f"bad arguments for {name}: {exc}", "expected": sorted(accepted)}
    except ValueError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{name} failed: {type(exc).__name__}: {exc}"}

    if ignored:
        result = dict(result) if isinstance(result, dict) else {"result": result}
        result["_warning"] = f"ignored unknown arguments: {', '.join(ignored)}"
    return result
