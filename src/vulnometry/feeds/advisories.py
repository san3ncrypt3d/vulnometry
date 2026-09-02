"""OSV.dev and GitHub Security Advisories, plus exploit-artifact discovery."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..config import settings
from ..net import FeedError, client
from ..schema import Bulletin, ExploitArtifact, Remedy, canonical_cve

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{vuln_id}"
GH_ADVISORY = "https://api.github.com/advisories"
GH_SEARCH = "https://api.github.com/search/repositories"

ECOSYSTEMS = [
    "PyPI", "npm", "Go", "Maven", "crates.io", "RubyGems", "NuGet", "Packagist",
    "Hex", "Pub", "Debian", "Alpine", "Ubuntu", "Rocky Linux", "AlmaLinux", "GitHub Actions",
]

_INDEX_REPOS = re.compile(
    r"(poc-in-github|cve-?list|awesome|cve-?database|nomi-sec|trickest|vulnerability-?db|cvedb|cve-?feed)",
    re.IGNORECASE,
)

_WEAPONISED = re.compile(r"(metasploit|nuclei-template|msf-module|exploit-kit|weaponi[sz]ed)", re.IGNORECASE)


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = settings().github_token
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fixed_in(affected: dict) -> str:
    versions = []
    for rng in affected.get("ranges", []) or []:
        for event in rng.get("events", []) or []:
            if event.get("fixed"):
                versions.append(event["fixed"])
    return ", ".join(sorted(set(versions)))


def _affected_range(affected: dict) -> str:
    parts = []
    for rng in affected.get("ranges", []) or []:
        introduced = [e.get("introduced") for e in rng.get("events", []) or [] if e.get("introduced")]
        fixed = [e.get("fixed") for e in rng.get("events", []) or [] if e.get("fixed")]
        if introduced or fixed:
            low = introduced[0] if introduced else "0"
            high = f" < {fixed[0]}" if fixed else ""
            parts.append(f">= {low}{high}")
    return "; ".join(parts)


def _osv_bulletin(vuln: dict) -> Bulletin:
    remedies = []
    for affected in vuln.get("affected", []) or []:
        package = affected.get("package", {}) or {}
        remedies.append(
            Remedy(
                ecosystem=package.get("ecosystem", ""),
                component=package.get("name", ""),
                affected_range=_affected_range(affected),
                fixed_in=_fixed_in(affected),
            )
        )
    rating = ""
    for severity in vuln.get("severity", []) or []:
        if severity.get("score"):
            rating = str(severity["score"])
            break
    return Bulletin(
        ref=vuln.get("id", ""),
        origin="osv",
        summary=vuln.get("summary") or (vuln.get("details", "") or "")[:400],
        rating=rating,
        aliases=list(vuln.get("aliases", []) or []),
        published=vuln.get("published", ""),
        remedies=remedies,
        url=f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
    )


async def osv_for_cve(cve_id: str) -> list[Bulletin]:
    cve_id = canonical_cve(cve_id)
    try:
        payload = await client().get_json(OSV_VULN.format(vuln_id=cve_id), source="osv", ttl=12 * 3600)
    except FeedError:
        return []
    if payload:
        return [_osv_bulletin(payload)]
    try:
        payload = await client().post_json(
            OSV_QUERY, source="osv", json_body={"query": cve_id}, ttl=12 * 3600
        )
    except FeedError:
        return []
    return [_osv_bulletin(v) for v in (payload or {}).get("vulns", []) or []]


async def osv_for_package(name: str, ecosystem: str = "", version: str = "") -> list[Bulletin]:
    body: dict = {"package": {"name": name}}
    if ecosystem:
        body["package"]["ecosystem"] = ecosystem
    if version:
        body["version"] = version
    payload = await client().post_json(OSV_QUERY, source="osv", json_body=body, ttl=6 * 3600)
    return [_osv_bulletin(v) for v in (payload or {}).get("vulns", []) or []]


async def osv_batch(components: list[dict]) -> dict[str, list[str]]:
    """components = [{name, ecosystem, version}]  ->  {'eco/name@ver': [ids]}"""
    queries, labels = [], []
    for component in components:
        entry: dict = {"package": {"name": component["name"]}}
        if component.get("ecosystem"):
            entry["package"]["ecosystem"] = component["ecosystem"]
        if component.get("version"):
            entry["version"] = component["version"]
        queries.append(entry)
        labels.append(f"{component.get('ecosystem', '?')}/{component['name']}@{component.get('version', '*')}")

    findings: dict[str, list[str]] = {}
    for start in range(0, len(queries), 100):
        chunk, chunk_labels = queries[start : start + 100], labels[start : start + 100]
        payload = await client().post_json(
            OSV_BATCH, source="osv", json_body={"queries": chunk}, ttl=3600
        )
        for label, result in zip(chunk_labels, (payload or {}).get("results", []) or [], strict=False):
            ids = [v.get("id", "") for v in (result or {}).get("vulns", []) or []]
            if ids:
                findings[label] = ids
    return findings


def _ghsa_bulletin(item: dict) -> Bulletin:
    remedies = []
    for vuln in item.get("vulnerabilities", []) or []:
        package = vuln.get("package", {}) or {}
        patched = vuln.get("first_patched_version") or {}
        remedies.append(
            Remedy(
                ecosystem=package.get("ecosystem", ""),
                component=package.get("name", ""),
                affected_range=vuln.get("vulnerable_version_range", ""),
                fixed_in=patched.get("identifier", "") if isinstance(patched, dict) else str(patched or ""),
            )
        )
    cvss = item.get("cvss") or {}
    rating = (item.get("severity") or "").upper()
    if cvss.get("score"):
        rating = f"{rating} ({cvss['score']})".strip()
    return Bulletin(
        ref=item.get("ghsa_id", ""),
        origin="ghsa",
        summary=item.get("summary", ""),
        rating=rating,
        aliases=[item["cve_id"]] if item.get("cve_id") else [],
        published=item.get("published_at", ""),
        remedies=remedies,
        url=item.get("html_url", ""),
    )


async def ghsa_for_cve(cve_id: str) -> list[Bulletin]:
    cve_id = canonical_cve(cve_id)
    try:
        payload = await client().get_json(
            GH_ADVISORY, source="ghsa", params={"cve_id": cve_id, "per_page": 10},
            headers=_gh_headers(), ttl=12 * 3600,
        )
    except FeedError:
        return []
    return [_ghsa_bulletin(i) for i in payload] if isinstance(payload, list) else []


async def exploit_artifacts(cve_id: str, limit: int = 6) -> list[ExploitArtifact]:
    """Public exploit material on GitHub. Heuristic by nature."""
    cve_id = canonical_cve(cve_id)
    try:
        payload = await client().get_json(
            GH_SEARCH,
            source="github-search",
            params={"q": f"{cve_id} in:name,description,readme", "sort": "stars", "per_page": 20},
            headers=_gh_headers(),
            ttl=24 * 3600,
        )
    except FeedError:
        return []

    artifacts: list[ExploitArtifact] = []
    for repo in (payload or {}).get("items", []) or []:
        full_name = repo.get("full_name", "")
        if _INDEX_REPOS.search(full_name):
            continue
        blurb = f"{full_name} {repo.get('description') or ''}"
        maturity = "weaponised" if _WEAPONISED.search(blurb) else "proof-of-concept"
        artifacts.append(
            ExploitArtifact(
                maturity=maturity,
                url=repo.get("html_url", ""),
                label=full_name,
                popularity=repo.get("stargazers_count"),
                first_seen=repo.get("created_at", ""),
            )
        )
        if len(artifacts) >= limit:
            break
    return artifacts


def citations_as_artifacts(citations) -> list[ExploitArtifact]:
    """Exploit references already present in the NVD record."""
    out = []
    for citation in citations or []:
        labels = [label.lower() for label in (getattr(citation, "labels", None) or [])]
        if "exploit" in labels:
            out.append(
                ExploitArtifact(
                    maturity="referenced",
                    url=citation.url,
                    label="Reference labelled as exploit code in NVD",
                )
            )
    return out


async def github_budget() -> dict:
    try:
        payload = await client().get_json(
            "https://api.github.com/rate_limit", source="github", headers=_gh_headers(), ttl=60
        )
    except FeedError as exc:
        return {"error": str(exc)}
    core = ((payload or {}).get("resources", {}) or {}).get("core", {})
    reset = core.get("reset")
    return {
        "authenticated": bool(settings().github_token),
        "remaining": core.get("remaining"),
        "limit": core.get("limit"),
        "resets_at": datetime.fromtimestamp(reset, tz=timezone.utc).isoformat() if reset else "",
    }
