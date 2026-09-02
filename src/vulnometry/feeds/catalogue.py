"""CISA Known Exploited Vulnerabilities, cached and indexed in memory."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from ..net import client
from ..schema import ConfirmedExploitation, canonical_cve

KEV_ENDPOINT = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse(entry: dict) -> ConfirmedExploitation:
    return ConfirmedExploitation(
        cve_id=entry.get("cveID", "").upper(),
        vendor=entry.get("vendorProject", ""),
        product=entry.get("product", ""),
        title=entry.get("vulnerabilityName", ""),
        catalogued=entry.get("dateAdded", ""),
        federal_deadline=entry.get("dueDate", ""),
        required_action=entry.get("requiredAction", ""),
        ransomware_linked=str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known",
        confirmed=True,
    )


async def document() -> dict:
    return await client().get_json(KEV_ENDPOINT, source="cisa-kev", ttl=6 * 3600) or {}


async def index() -> dict[str, ConfirmedExploitation]:
    payload = await document()
    return {e.get("cveID", "").upper(): _parse(e) for e in payload.get("vulnerabilities", []) or []}


async def fetch(cve_id: str) -> ConfirmedExploitation:
    cve_id = canonical_cve(cve_id)
    return (await index()).get(cve_id, ConfirmedExploitation(cve_id=cve_id, confirmed=False))


async def fetch_many(cve_ids: list[str]) -> dict[str, ConfirmedExploitation]:
    idx = await index()
    out = {}
    for raw in cve_ids:
        cve = canonical_cve(raw)
        out[cve] = idx.get(cve, ConfirmedExploitation(cve_id=cve, confirmed=False))
    return out


async def added_since(days: int = 14) -> list[ConfirmedExploitation]:
    cutoff = date.today() - timedelta(days=max(1, days))
    out = []
    for entry in (await index()).values():
        try:
            when = datetime.strptime(entry.catalogued, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            continue
        if when >= cutoff:
            out.append(entry)
    return sorted(out, key=lambda e: e.catalogued, reverse=True)


async def past_deadline() -> list[ConfirmedExploitation]:
    today = date.today()
    out = []
    for entry in (await index()).values():
        try:
            due = datetime.strptime(entry.federal_deadline, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            continue
        if due < today:
            out.append(entry)
    return sorted(out, key=lambda e: e.federal_deadline)
