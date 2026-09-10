"""Turn a CVE plus a business context into a verdict."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from .config import settings
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
    scanner_severity: str = "",
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
        scanner_severity=scanner_severity,
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
                scanner_severity=str(row.get("raw_severity") or "").strip(),
            )

    results = await asyncio.gather(*(one(row) for row in normalised))
    return sorted(results, key=lambda a: a.exposure.index, reverse=True)


_VERSION_TAIL = re.compile(r"(?::\s*|@|\s+)v?\d[^\s]*$")


def _package(component: str) -> str:
    """'org.apache.tomcat.embed:tomcat-embed-core: 11.0.9' -> the package, without the version.

    One package on one asset is one upgrade, however many CVEs it carries.
    """
    text = (component or "").strip()
    if not text:
        return ""
    return _VERSION_TAIL.sub("", text).strip(" :@")


def _work_item(item: Assessment) -> tuple[str, str]:
    """The unit an engineer actually actions: one package, on one place you run it."""
    where = item.asset or item.scanner_ref() or "(unmatched)"
    return (where, _package(item.source_component) or item.cve_id)


SEVERITY_URGENT_FLOOR = 7.0   # CVSS High. What a severity-driven queue treats as urgent.

SEVERITY_BANDS = ("Critical", "High", "Medium", "Low")


def cvss_band(score: float) -> str:
    """CVSS v3 qualitative bands. 'None' when nothing was published."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def scanner_band(raw: str) -> str:
    """Normalise whatever the scanner called it onto the same four bands.

    Scanners spell it differently -- CRITICAL, critical, Moderate, Important --
    and some emit a number. Anything unrecognised is returned title-cased rather
    than forced into a band, so a surprise shows up instead of being hidden.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    aliases = {"critical": "Critical", "high": "High", "important": "High",
               "medium": "Medium", "moderate": "Medium", "low": "Low",
               "minor": "Low", "negligible": "Low", "info": "Low",
               "informational": "Low"}
    if lowered in aliases:
        return aliases[lowered]
    try:
        return cvss_band(float(text))
    except ValueError:
        return text.title()


def severity_crosstab(assessments: list[Assessment]) -> dict:
    """How each severity band was judged -- the question everyone asks first.

    'You accepted 27 Critical findings' is the challenge any report of this kind
    has to answer, so it is stated rather than left to be discovered. Reported on
    both axes because they disagree: the scanner's own rating is what a reader
    has already seen, CVSS is the independent public number, and neither is the
    verdict.
    """
    by_scanner: dict[str, dict[str, int]] = {}
    by_cvss: dict[str, dict[str, int]] = {}
    for item in assessments:
        verdict = item.exposure.verdict
        s = scanner_band(item.scanner_severity)
        if s:
            by_scanner.setdefault(s, {}).setdefault(verdict, 0)
            by_scanner[s][verdict] += 1
        c = cvss_band(_cvss(item))
        by_cvss.setdefault(c, {}).setdefault(verdict, 0)
        by_cvss[c][verdict] += 1

    def order(grid):
        keys = [b for b in SEVERITY_BANDS if b in grid]
        keys += sorted(k for k in grid if k not in SEVERITY_BANDS)
        return {k: grid[k] for k in keys}

    return {
        "by_scanner_severity": order(by_scanner),
        "by_cvss_band": order(by_cvss),
        "scanner_severity_available": bool(by_scanner),
    }


def _cvss(item: Assessment) -> float:
    severity = item.weakness.primary_severity()
    return (severity.base_score or 0.0) if severity else 0.0


def reduction_funnel(assessments: list[Assessment],
                     triage_minutes: tuple[float, float] | None = None) -> dict:
    """How much the analysis narrowed the pile, stage by stage.

    Two separate reductions, and it matters which one you quote.

    Scanners report one row per (CVE, project, manifest), so the row count is
    inflated by duplication before anyone has judged anything. Removing that is
    bookkeeping, not analysis.

    The reduction that *is* the analysis is against the counterfactual: how many
    of these a severity-driven programme would have queued as urgent (CVSS >= 7)
    versus how many the exposure model says to act on. That is the claim the tool
    has to stand behind, so it is reported against the severity queue, not
    against the raw row count.

    Last comes cost: one dependency bump closes every CVE that package carries,
    so distinct (asset, package) upgrades is what the work actually is.

    ``triage_minutes`` bounds the effort avoided. Triaging one finding by hand --
    read the CVE, work out where it runs, judge whether it matters here, write it
    up or close it -- runs anywhere from half an hour to two, so the answer is
    reported as a band with the assumption beside it. It is an assumption, not a
    measurement, and it never feeds a score.
    """
    cfg = settings()
    low, high = triage_minutes or (cfg.triage_minutes_low, cfg.triage_minutes_high)
    total = len(assessments)
    pairs = {(a.cve_id, a.asset or a.scanner_ref()) for a in assessments}
    urgent_on_severity = [a for a in assessments if _cvss(a) >= SEVERITY_URGENT_FLOOR]
    actionable = [a for a in assessments if a.exposure.verdict in ("Contain", "Remediate")]
    collapsed = [a for a in assessments if a.exposure.collapsed_by]

    work = {_work_item(a) for a in assessments}
    actionable_work = {_work_item(a) for a in actionable}

    def cut(part: int, whole: int) -> int:
        return round(100 * (1 - part / whole)) if whole else 0

    return {
        "findings_assessed": total,
        "unique_cves": len({a.cve_id for a in assessments}),
        "cve_asset_pairs": len(pairs),
        "urgent_on_severity_alone": len(urgent_on_severity),
        "actionable_findings": len(actionable),
        "collapsed_by_business_context": len(collapsed),
        "work_items": len(work),
        "actionable_work_items": len(actionable_work),
        "actionable_work_assets": len({where for where, _ in actionable_work}),
        "findings_per_work_item": round(total / len(work), 1) if work else 0.0,
        # bookkeeping: duplication the scanner introduced
        "deduplication_pct": cut(len(pairs), total),
        # the analysis: how much of the severity-driven queue the model removed
        "analysis_reduction_pct": cut(len(actionable), len(urgent_on_severity)),
        # cost: upgrades vs findings
        "effort_reduction_pct": cut(len(actionable_work), total),
        "severity_floor": SEVERITY_URGENT_FLOOR,
        # effort avoided: a band, because per-finding triage time genuinely varies
        "findings_not_triaged": max(0, len(urgent_on_severity) - len(actionable)),
        "triage_minutes_assumed": [round(low, 1), round(high, 1)],
        "analyst_hours_saved_low": round(
            max(0, len(urgent_on_severity) - len(actionable)) * low / 60, 1
        ),
        "analyst_hours_saved_high": round(
            max(0, len(urgent_on_severity) - len(actionable)) * high / 60, 1
        ),
    }


def portfolio_summary(assessments: list[Assessment],
                      triage_minutes: tuple[float, float] | None = None) -> dict:
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
        "reduction": reduction_funnel(assessments, triage_minutes),
        "severity_crosstab": severity_crosstab(assessments),
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
