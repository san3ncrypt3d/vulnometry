"""Turn a CVE plus a business context into a verdict."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .exposure import directive_for, measure_exposure
from .feeds import advisories as adv_feed
from .feeds import catalogue as kev_feed
from .feeds import probability as epss_feed
from .feeds import record as cve_feed
from .inventory import UNKNOWN_ASSET, AssetProfile, Inventory
from .net import FeedError
from .schema import (
    Assessment,
    ConfirmedExploitation,
    ExploitProbability,
    Weakness,
    canonical_cve,
)

LENSES = ("signal", "full", "forensic")


async def _guarded(coro, fallback, gaps: list[str], label: str):
    try:
        return await coro
    except FeedError as exc:
        gaps.append(str(exc))
    except Exception as exc:  # noqa: BLE001
        gaps.append(f"[{label}] unexpected: {exc}")
    return fallback


def _dedupe(bulletins):
    seen, unique = set(), []
    for bulletin in bulletins:
        key = bulletin.ref or (bulletin.origin, bulletin.summary[:60])
        if key in seen:
            continue
        seen.add(key)
        unique.append(bulletin)
    return unique


def _fix_versions(bulletins) -> list[str]:
    fixes: list[str] = []
    for bulletin in bulletins:
        for remedy in bulletin.remedies:
            if remedy.fixed_in:
                label = f"{remedy.component} {remedy.fixed_in}" if remedy.component else remedy.fixed_in
                if label not in fixes:
                    fixes.append(label)
    return fixes


async def assess_finding(
    cve_id: str,
    asset: AssetProfile | dict | None = None,
    inventory: Inventory | None = None,
    asset_name: str = "",
    host: str = "",
    component: str = "",
    lens: str = "full",
) -> Assessment:
    """Assess one CVE against one place you run it."""
    cve_id = canonical_cve(cve_id)
    lens = lens if lens in LENSES else "full"

    if isinstance(asset, dict):
        known = set(AssetProfile.__dataclass_fields__)
        asset = AssetProfile(**{k: v for k, v in asset.items() if k in known})
    if asset is None:
        source = inventory or Inventory()
        asset = source.resolve(asset_name=asset_name, host=host, component=component)

    gaps: list[str] = []

    work = {
        "weakness": _guarded(cve_feed.fetch(cve_id), Weakness(cve_id=cve_id), gaps, "nvd"),
        "probability": _guarded(epss_feed.fetch(cve_id), ExploitProbability(cve_id=cve_id), gaps, "epss"),
        "exploitation": _guarded(kev_feed.fetch(cve_id), ConfirmedExploitation(cve_id=cve_id), gaps, "cisa-kev"),
    }
    if lens in ("full", "forensic"):
        work["osv"] = _guarded(adv_feed.osv_for_cve(cve_id), [], gaps, "osv")
        work["ghsa"] = _guarded(adv_feed.ghsa_for_cve(cve_id), [], gaps, "ghsa")
    if lens == "forensic":
        work["artifacts"] = _guarded(adv_feed.exploit_artifacts(cve_id), [], gaps, "github-search")

    resolved = dict(zip(work.keys(), await asyncio.gather(*work.values()), strict=False))

    weakness: Weakness = resolved["weakness"]
    probability: ExploitProbability = resolved["probability"]
    exploitation: ConfirmedExploitation = resolved["exploitation"]

    if not weakness.resolved:
        gaps.append(f"No CVE record retrieved: {weakness.state or 'not found'}")
    if not probability.resolved:
        gaps.append("No EPSS score retrieved")

    bulletins = _dedupe(list(resolved.get("ghsa") or []) + list(resolved.get("osv") or []))
    artifacts = list(resolved.get("artifacts") or [])
    artifacts.extend(adv_feed.citations_as_artifacts(weakness.citations))

    measure = measure_exposure(weakness, probability, exploitation, artifacts, asset)
    fixes = _fix_versions(bulletins)
    due_by = asset.due_date(measure.verdict)

    return Assessment(
        cve_id=cve_id,
        exposure=measure,
        weakness=weakness,
        probability=probability,
        exploitation=exploitation,
        bulletins=bulletins,
        artifacts=artifacts,
        fixes=fixes,
        asset=asset.name if asset.name != UNKNOWN_ASSET.name else "",
        owner=asset.owner,
        business_unit=asset.business_unit,
        environment=asset.environment,
        tier=asset.tier,
        internet_exposed=asset.internet_exposed,
        data_classification=asset.data_classification,
        due_by=due_by,
        sla_days=asset.sla_days(measure.verdict) or None,
        source_asset=asset_name,
        source_host=host,
        source_component=component,
        directive=directive_for(measure, exploitation, fixes, asset, due_by),
        gaps=gaps,
        lens=lens,
        measured_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


async def assess_portfolio(
    findings: list[dict] | list[str],
    inventory: Inventory | None = None,
    lens: str = "signal",
    asset: AssetProfile | dict | None = None,
    concurrency: int = 6,
) -> list[Assessment]:
    """Assess many findings, returned worst-first."""
    normalised: list[dict] = []
    seen: set[tuple] = set()
    for entry in findings:
        row = {"cve": entry} if isinstance(entry, str) else dict(entry)
        cve = (row.get("cve") or row.get("cve_id") or "").strip()
        if not cve:
            continue
        try:
            cve = canonical_cve(cve)
        except ValueError:
            continue
        key = (cve, row.get("asset", ""), row.get("host", ""), row.get("component", ""))
        if key in seen:
            continue
        seen.add(key)
        row["cve"] = cve
        normalised.append(row)

    gate = asyncio.Semaphore(max(1, concurrency))

    async def one(row: dict) -> Assessment:
        async with gate:
            return await assess_finding(
                row["cve"],
                asset=asset,
                inventory=inventory,
                asset_name=row.get("asset", ""),
                host=row.get("host", ""),
                component=row.get("component", ""),
                lens=lens,
            )

    results = await asyncio.gather(*(one(row) for row in normalised))
    return sorted(results, key=lambda a: a.exposure.index, reverse=True)


def portfolio_summary(assessments: list[Assessment]) -> dict:
    """Summary paragraph for the top of a report."""
    by_verdict: dict[str, int] = {}
    by_owner: dict[str, int] = {}
    by_unit: dict[str, float] = {}

    for item in assessments:
        by_verdict[item.exposure.verdict] = by_verdict.get(item.exposure.verdict, 0) + 1
        if item.exposure.verdict in ("Contain", "Remediate"):
            owner = item.owner or "unassigned"
            by_owner[owner] = by_owner.get(owner, 0) + 1
        unit = item.business_unit or "unattributed"
        by_unit[unit] = round(by_unit.get(unit, 0.0) + item.exposure.index, 1)

    actionable = [a for a in assessments if a.exposure.verdict in ("Contain", "Remediate")]
    not_deployed = [a for a in assessments if a.exposure.collapsed_by == "not-deployed"]
    unreachable = [a for a in assessments if a.exposure.collapsed_by == "reachability"]

    return {
        "assessed": len(assessments),
        "by_verdict": by_verdict,
        "contain_now": [a.cve_id for a in assessments if a.exposure.verdict == "Contain"][:50],
        "actionable": len(actionable),
        "deferrable": len(assessments) - len(actionable),
        "suppressed_by_context": len(not_deployed) + len(unreachable),
        "not_deployed": len(not_deployed),
        "unreachable_here": len(unreachable),
        "confirmed_exploited": [a.cve_id for a in assessments if a.exploitation.confirmed][:50],
        "load_by_owner": dict(sorted(by_owner.items(), key=lambda kv: -kv[1])),
        "exposure_by_business_unit": dict(sorted(by_unit.items(), key=lambda kv: -kv[1])),
        "unattributed": sum(1 for a in assessments if not a.asset),
        "top": [
            {
                "cve": a.cve_id,
                "index": a.exposure.index,
                "verdict": a.exposure.verdict,
                "asset": a.asset,
                "owner": a.owner,
                "due_by": a.due_by,
                "reason": (a.exposure.threat_basis or [""])[0],
            }
            for a in assessments[:15]
        ],
    }
