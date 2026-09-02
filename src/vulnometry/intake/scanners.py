"""Native JSON output from the common scanners."""

from __future__ import annotations

from ..schema import harvest_cve_ids


def sniff_scanner(data) -> str:
    """Identify the producing tool from the shape of the document."""
    if isinstance(data, dict):
        if "Results" in data and "ArtifactName" in data:
            return "trivy"
        if "matches" in data and "descriptor" in data:
            return "grype"
        if "vulnerabilities" in data and "projectName" in data:
            return "snyk"
        if "results" in data and isinstance(data.get("results"), list):
            first = (data["results"] or [{}])[0]
            if isinstance(first, dict) and ("packages" in first or "source" in first):
                return "osv-scanner"
        if isinstance(data.get("runs"), list) and (
            "sarif" in str(data.get("$schema", "")).lower() or "version" in data
        ):
            return "sarif"
        if "alerts" in data or ("security_advisory" in str(data)[:2000]):
            return "dependabot"
    if isinstance(data, list) and data and isinstance(data[0], dict):
        if "security_advisory" in data[0]:
            return "dependabot"
    return ""


def _trivy(data: dict) -> list[dict]:
    artifact = data.get("ArtifactName", "")
    findings = []
    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            cve = vuln.get("VulnerabilityID", "")
            if not cve.upper().startswith("CVE-"):
                continue
            findings.append({
                "cve": cve,
                "asset": artifact,
                "host": target,
                "component": vuln.get("PkgName", ""),
                "version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "raw_severity": vuln.get("Severity", ""),
                "source": "trivy",
            })
    return findings


def _grype(data: dict) -> list[dict]:
    source = ((data.get("source") or {}).get("target") or {})
    artifact = source.get("userInput", "") if isinstance(source, dict) else str(source)
    findings = []
    for match in data.get("matches", []) or []:
        vuln = match.get("vulnerability", {}) or {}
        artifact_info = match.get("artifact", {}) or {}
        cve = vuln.get("id", "")
        if not cve.upper().startswith("CVE-"):
            related = [r.get("id", "") for r in match.get("relatedVulnerabilities", []) or []]
            cve = next((r for r in related if r.upper().startswith("CVE-")), "")
        if not cve:
            continue
        findings.append({
            "cve": cve,
            "asset": artifact,
            "component": artifact_info.get("name", ""),
            "version": artifact_info.get("version", ""),
            "raw_severity": vuln.get("severity", ""),
            "source": "grype",
        })
    return findings


def _snyk(data: dict) -> list[dict]:
    project = data.get("projectName", "")
    findings = []
    for vuln in data.get("vulnerabilities", []) or []:
        for cve in vuln.get("identifiers", {}).get("CVE", []) or []:
            findings.append({
                "cve": cve,
                "asset": project,
                "component": vuln.get("packageName", ""),
                "version": vuln.get("version", ""),
                "raw_severity": vuln.get("severity", ""),
                "source": "snyk",
            })
    return findings


def _osv_scanner(data: dict) -> list[dict]:
    findings = []
    for result in data.get("results", []) or []:
        source_path = ((result.get("source") or {}).get("path")) or ""
        for package in result.get("packages", []) or []:
            info = package.get("package", {}) or {}
            for vuln in package.get("vulnerabilities", []) or []:
                aliases = [vuln.get("id", "")] + list(vuln.get("aliases", []) or [])
                cve = next((a for a in aliases if a.upper().startswith("CVE-")), "")
                if not cve:
                    continue
                findings.append({
                    "cve": cve,
                    "asset": source_path,
                    "component": info.get("name", ""),
                    "version": info.get("version", ""),
                    "source": "osv-scanner",
                })
    return findings


def _dependabot(data) -> list[dict]:
    alerts = data if isinstance(data, list) else (data.get("alerts") or [])
    findings = []
    for alert in alerts:
        advisory = alert.get("security_advisory", {}) or {}
        cve = advisory.get("cve_id", "")
        if not cve:
            continue
        dependency = alert.get("dependency", {}) or {}
        package = dependency.get("package", {}) or {}
        findings.append({
            "cve": cve,
            "asset": dependency.get("manifest_path", ""),
            "component": package.get("name", ""),
            "raw_severity": advisory.get("severity", ""),
            "source": "dependabot",
        })
    return findings


def _sarif(data: dict) -> list[dict]:
    findings = []
    for run in data.get("runs", []) or []:
        tool = (((run.get("tool") or {}).get("driver") or {}).get("name")) or "sarif"
        for result in run.get("results", []) or []:
            blob = str(result.get("message", {}).get("text", "")) + " " + str(result.get("ruleId", ""))
            for cve in harvest_cve_ids(blob):
                locations = result.get("locations", []) or []
                uri = ""
                if locations:
                    uri = (((locations[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")) or ""
                findings.append({"cve": cve, "asset": uri, "source": tool.lower()})
    return findings


PARSERS = {
    "trivy": _trivy,
    "grype": _grype,
    "snyk": _snyk,
    "osv-scanner": _osv_scanner,
    "dependabot": _dependabot,
    "sarif": _sarif,
}


def parse_scanner_json(data, flavour: str) -> list[dict]:
    parser = PARSERS.get(flavour)
    if not parser:
        return []
    try:
        return parser(data)
    except (AttributeError, TypeError, KeyError):
        import json

        return [{"cve": c, "source": flavour} for c in harvest_cve_ids(json.dumps(data)[:400000])]
