"""CVE record from NVD, falling back to the CVE Program CNA record."""

from __future__ import annotations

from ..config import settings
from ..net import FeedError, client
from ..schema import Citation, Severity, Weakness, canonical_cve

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CNA_ENDPOINT = "https://cveawg.mitre.org/api/cve/{cve_id}"

_METRIC_FIELDS = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]


def _auth() -> dict[str, str]:
    key = settings().nvd_api_key
    return {"apiKey": key} if key else {}


def _severities(metrics: dict) -> list[Severity]:
    out: list[Severity] = []
    for field_name, version in _METRIC_FIELDS:
        for entry in metrics.get(field_name, []) or []:
            data = entry.get("cvssData", {}) or {}
            out.append(
                Severity(
                    version=str(data.get("version") or version),
                    base_score=data.get("baseScore"),
                    rating=(data.get("baseSeverity") or entry.get("baseSeverity") or "").upper(),
                    vector=data.get("vectorString", ""),
                    issuer=entry.get("source", ""),
                    attack_vector=data.get("attackVector") or data.get("accessVector") or "",
                    attack_complexity=data.get("attackComplexity") or data.get("accessComplexity") or "",
                    privileges_required=data.get("privilegesRequired", ""),
                    user_interaction=data.get("userInteraction", ""),
                    confidentiality=data.get("confidentialityImpact", ""),
                    integrity=data.get("integrityImpact", ""),
                    availability=data.get("availabilityImpact", ""),
                )
            )
    return out


def _platforms(configurations: list) -> list[str]:
    found: set[str] = set()
    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if match.get("vulnerable") and match.get("criteria"):
                    found.add(match["criteria"])
    return sorted(found)[:60]


def _from_nvd(item: dict) -> Weakness:
    cve = item.get("cve", item)
    descriptions = cve.get("descriptions", []) or []
    english = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    return Weakness(
        cve_id=cve.get("id", ""),
        summary=english,
        published=cve.get("published", ""),
        updated=cve.get("lastModified", ""),
        state=cve.get("vulnStatus", ""),
        severities=_severities(cve.get("metrics", {}) or {}),
        cwe_ids=cwes,
        citations=[
            Citation(url=r.get("url", ""), issuer=r.get("source", ""), labels=r.get("tags", []) or [])
            for r in (cve.get("references", []) or [])
        ],
        platforms=_platforms(cve.get("configurations", []) or []),
        issuer=cve.get("sourceIdentifier", ""),
        retrieved_from="nvd",
        resolved=True,
    )


def _from_cna(payload: dict) -> Weakness:
    meta = payload.get("cveMetadata", {}) or {}
    cna = (payload.get("containers", {}) or {}).get("cna", {}) or {}

    descriptions = cna.get("descriptions", []) or []
    english = next(
        (d.get("value", "") for d in descriptions if d.get("lang", "").startswith("en")),
        descriptions[0].get("value", "") if descriptions else "",
    )

    severities: list[Severity] = []
    for metric in cna.get("metrics", []) or []:
        for field_name, version in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0")):
            data = metric.get(field_name)
            if not data:
                continue
            severities.append(
                Severity(
                    version=version,
                    base_score=data.get("baseScore"),
                    rating=(data.get("baseSeverity") or "").upper(),
                    vector=data.get("vectorString", ""),
                    issuer="cna",
                    attack_vector=data.get("attackVector", ""),
                    attack_complexity=data.get("attackComplexity", ""),
                    privileges_required=data.get("privilegesRequired", ""),
                    user_interaction=data.get("userInteraction", ""),
                    confidentiality=data.get("confidentialityImpact", ""),
                    integrity=data.get("integrityImpact", ""),
                    availability=data.get("availabilityImpact", ""),
                )
            )

    cwes: list[str] = []
    for problem in cna.get("problemTypes", []) or []:
        for desc in problem.get("descriptions", []) or []:
            if desc.get("cweId") and desc["cweId"] not in cwes:
                cwes.append(desc["cweId"])

    return Weakness(
        cve_id=meta.get("cveId", ""),
        summary=english,
        published=meta.get("datePublished", ""),
        updated=meta.get("dateUpdated", ""),
        state=meta.get("state", ""),
        severities=severities,
        cwe_ids=cwes,
        citations=[
            Citation(url=r.get("url", ""), issuer=r.get("name", ""), labels=r.get("tags", []) or [])
            for r in (cna.get("references", []) or [])
        ],
        issuer=meta.get("assignerShortName", ""),
        retrieved_from="cve-program",
        resolved=True,
    )


async def fetch(cve_id: str) -> Weakness:
    cve_id = canonical_cve(cve_id)
    nvd_problem: str | None = None

    try:
        payload = await client().get_json(
            NVD_ENDPOINT, source="nvd", params={"cveId": cve_id}, headers=_auth(), ttl=6 * 3600
        )
        entries = (payload or {}).get("vulnerabilities") or []
        if entries:
            return _from_nvd(entries[0])
        nvd_problem = "no NVD entry"
    except FeedError as exc:
        nvd_problem = str(exc)

    try:
        payload = await client().get_json(
            CNA_ENDPOINT.format(cve_id=cve_id), source="cve-program", ttl=6 * 3600
        )
        if payload:
            weakness = _from_cna(payload)
            if nvd_problem:
                weakness.state = f"{weakness.state} (NVD unavailable: {nvd_problem})".strip()
            return weakness
    except FeedError:
        pass

    return Weakness(cve_id=cve_id, resolved=False, retrieved_from="none", state=nvd_problem or "not found")


async def search(
    keyword: str = "", cpe_name: str = "", limit: int = 20, changed_within_days: int | None = None
) -> list[Weakness]:
    params: dict = {"resultsPerPage": max(1, min(limit, 200))}
    if keyword:
        params["keywordSearch"] = keyword
    if cpe_name:
        params["cpeName"] = cpe_name
    if changed_within_days:
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc)
        start = end - timedelta(days=min(changed_within_days, 120))
        params["lastModStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["lastModEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")

    if len(params) == 1:
        raise ValueError("provide keyword, cpe_name, or changed_within_days")

    payload = await client().get_json(NVD_ENDPOINT, source="nvd", params=params, headers=_auth(), ttl=3600)
    return [_from_nvd(item) for item in (payload or {}).get("vulnerabilities", [])]
