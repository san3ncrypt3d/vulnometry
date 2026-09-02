"""Synthetic upstream payloads, shaped exactly like the real APIs."""


def nvd(cve_id, score, vector_bits, summary="A vulnerability.", impacts=("HIGH", "HIGH", "HIGH")):
    av, ac, pr, ui = vector_bits
    return {"vulnerabilities": [{"cve": {
        "id": cve_id, "sourceIdentifier": "cna@example.com",
        "published": "2024-01-01T00:00:00.000", "lastModified": "2024-02-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": summary}],
        "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
            "version": "3.1", "vectorString": f"CVSS:3.1/AV:{av[0]}/AC:{ac[0]}/PR:{pr[0]}/UI:{ui[0]}",
            "attackVector": av, "attackComplexity": ac, "privilegesRequired": pr, "userInteraction": ui,
            "confidentialityImpact": impacts[0], "integrityImpact": impacts[1], "availabilityImpact": impacts[2],
            "baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "MEDIUM"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
        "references": [{"url": "https://example.com/advisory", "source": "x", "tags": ["Vendor Advisory"]}],
        "configurations": [],
    }}]}


def epss(cve_id, probability, percentile="0.5"):
    return {"status": "OK", "data": [
        {"cve": cve_id, "epss": str(probability), "percentile": percentile, "date": "2026-08-31"}
    ]}


KEV_DOCUMENT = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.09.01",
    "count": 1,
    "vulnerabilities": [{
        "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10", "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "notes": "",
    }],
}

OSV_LOG4SHELL = {
    "id": "GHSA-jfh8-c2jp-5v3q", "summary": "Remote code injection in Log4j",
    "aliases": ["CVE-2021-44228"], "published": "2021-12-10T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}],
    }],
}

GHSA_LOG4SHELL = [{
    "ghsa_id": "GHSA-jfh8-c2jp-5v3q", "cve_id": "CVE-2021-44228",
    "summary": "Remote code injection in Log4j", "severity": "critical",
    "published_at": "2021-12-10T00:00:00Z",
    "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
    "cvss": {"score": 10.0},
    "vulnerabilities": [{
        "package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
        "vulnerable_version_range": ">= 2.0-beta9, < 2.15.0",
        "first_patched_version": {"identifier": "2.15.0"},
    }],
}]

GITHUB_REPOS = {"items": [
    {"full_name": "redteam/log4shell-rce", "html_url": "https://github.com/redteam/log4shell-rce",
     "description": "Weaponised metasploit module", "stargazers_count": 2100,
     "created_at": "2021-12-11T00:00:00Z"},
    {"full_name": "nomi-sec/PoC-in-GitHub", "html_url": "https://github.com/nomi-sec/PoC-in-GitHub",
     "description": "index of everything", "stargazers_count": 9000,
     "created_at": "2020-01-01T00:00:00Z"},
]}
