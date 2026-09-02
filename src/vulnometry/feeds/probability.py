"""FIRST EPSS: modelled probability of exploitation within 30 days."""

from __future__ import annotations

from ..net import FeedError, client
from ..schema import ExploitProbability, canonical_cve

EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"


def _parse(entry: dict) -> ExploitProbability:
    def number(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    return ExploitProbability(
        cve_id=entry.get("cve", "").upper(),
        probability=number(entry.get("epss")),
        percentile=number(entry.get("percentile")),
        as_of=entry.get("date", ""),
        resolved=True,
    )


def _batches(items: list, size: int):
    for start in range(0, len(items), size):
        yield items[start : start + size]


async def fetch_many(cve_ids: list[str], as_of: str = "") -> dict[str, ExploitProbability]:
    ids = [canonical_cve(c) for c in cve_ids]
    results = {cve: ExploitProbability(cve_id=cve, resolved=False) for cve in ids}

    for batch in _batches(ids, 100):
        params: dict = {"cve": ",".join(batch)}
        if as_of:
            params["date"] = as_of
        try:
            payload = await client().get_json(EPSS_ENDPOINT, source="epss", params=params, ttl=12 * 3600)
        except FeedError:
            continue
        for entry in (payload or {}).get("data", []) or []:
            parsed = _parse(entry)
            if parsed.cve_id in results:
                results[parsed.cve_id] = parsed
    return results


async def fetch(cve_id: str, as_of: str = "") -> ExploitProbability:
    return (await fetch_many([cve_id], as_of=as_of))[canonical_cve(cve_id)]


async def highest(limit: int = 25, above: float = 0.5) -> list[ExploitProbability]:
    payload = await client().get_json(
        EPSS_ENDPOINT,
        source="epss",
        params={"order": "!epss", "limit": max(1, min(limit, 200)), "epss-gt": above},
        ttl=6 * 3600,
    )
    return [_parse(e) for e in (payload or {}).get("data", []) or []]
