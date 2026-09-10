"""Intake has to cope with real files, which are messy."""

import json

import pytest
from openpyxl import Workbook

from vulnometry.intake import load_findings, preview_columns
from vulnometry.intake.manifests import parse_manifest
from vulnometry.intake.scanners import parse_scanner_json, sniff_scanner
from vulnometry.intake.tabular import parse_tabular


def _messy_workbook(path):
    """A title block above the header, a decoy sheet, and a multi-CVE cell."""
    workbook = Workbook()
    decoy = workbook.active
    decoy.title = "Summary"
    decoy.append(["Total hosts", 3])

    sheet = workbook.create_sheet("Vulnerability Report")
    sheet.append(["Qualys VMDR Export"])
    sheet.append(["Generated 2026-09-01"])
    sheet.append([])
    sheet.append(["Plugin ID", "CVE ID", "Severity", "Host Name", "Application", "Installed Version", "Assignee"])
    sheet.append(["19506", "CVE-2021-44228", "Critical", "checkout-01", "checkout-api", "2.14.1", "pay@x.com"])
    sheet.append(["19510", "CVE-2024-50000, CVE-2023-40000", "High", "wiki-01", "internal-wiki", "1.0", "it@x.com"])
    sheet.append(["19511", "", "Info", "checkout-01", "checkout-api", "", ""])
    workbook.save(path)
    return path


def test_preview_finds_the_header_and_maps_columns(tmp_path):
    path = _messy_workbook(tmp_path / "export.xlsx")
    info = preview_columns(path)

    assert info["sheet"] == "Vulnerability Report", "must skip the decoy sheet"
    assert info["header_row"] == 4, "must find the header under the title block"
    assert info["cve_column_found"]
    assert info["detected"]["cve"] == "CVE ID"
    assert info["detected"]["host"] == "Host Name"
    assert info["detected"]["asset"] == "Application"
    assert info["detected"]["owner"] == "Assignee"
    assert "Plugin ID" in info["unmapped"]


def test_multi_cve_cells_become_separate_findings(tmp_path):
    path = _messy_workbook(tmp_path / "export.xlsx")
    findings, label = parse_tabular(path)

    assert len(findings) == 3, "one row with two CVEs becomes two findings; the empty row is dropped"
    assert {f["cve"] for f in findings} == {"CVE-2021-44228", "CVE-2024-50000", "CVE-2023-40000"}
    first = next(f for f in findings if f["cve"] == "CVE-2021-44228")
    assert first["asset"] == "checkout-api"
    assert first["host"] == "checkout-01"
    assert first["owner"] == "pay@x.com"
    assert "Excel" in label


def test_csv_with_semicolons_and_no_cve_column(tmp_path):
    path = tmp_path / "report.csv"
    path.write_text("host;finding;risk\nweb-01;Detected CVE-2021-44228 in log4j;High\nweb-02;Clean;Info\n")
    findings, _ = parse_tabular(path)
    assert len(findings) == 1, "falls back to scanning whole rows when there is no CVE column"
    assert findings[0]["cve"] == "CVE-2021-44228"


def test_trivy_report(tmp_path):
    report = {"ArtifactName": "myapp:1.0", "Results": [{
        "Target": "myapp:1.0 (alpine 3.18)",
        "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j", "InstalledVersion": "2.14.1",
             "FixedVersion": "2.15.0", "Severity": "CRITICAL"},
            {"VulnerabilityID": "GHSA-xxxx-yyyy", "PkgName": "other", "Severity": "LOW"},
        ]}]}
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(report))

    assert sniff_scanner(report) == "trivy"
    findings, label = load_findings(path)
    assert label == "trivy report"
    assert len(findings) == 1, "non-CVE advisory ids are dropped"
    assert findings[0]["component"] == "log4j"
    assert findings[0]["asset"] == "myapp:1.0"


def test_grype_report_uses_related_cve_when_primary_is_a_ghsa(tmp_path):
    report = {"descriptor": {"name": "grype"}, "source": {"target": {"userInput": "myimage"}},
              "matches": [{
                  "vulnerability": {"id": "GHSA-jfh8-c2jp-5v3q", "severity": "Critical"},
                  "relatedVulnerabilities": [{"id": "CVE-2021-44228"}],
                  "artifact": {"name": "log4j-core", "version": "2.14.1"},
              }]}
    path = tmp_path / "grype.json"
    path.write_text(json.dumps(report))

    findings, _ = load_findings(path)
    assert findings[0]["cve"] == "CVE-2021-44228"
    assert findings[0]["component"] == "log4j-core"


def test_sarif_report(tmp_path):
    report = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "CodeQL"}},
        "results": [{"ruleId": "CVE-2023-40000", "message": {"text": "Vulnerable dependency"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "pom.xml"}}}]}],
    }]}
    path = tmp_path / "results.sarif.json"
    path.write_text(json.dumps(report))
    findings, label = load_findings(path)
    assert findings[0]["cve"] == "CVE-2023-40000"
    assert findings[0]["asset"] == "pom.xml"


def test_malformed_scanner_report_degrades_to_id_scraping():
    broken = {"ArtifactName": "x", "Results": "not-a-list-at-all CVE-2021-44228"}
    findings = parse_scanner_json(broken, "trivy")
    assert findings and findings[0]["cve"] == "CVE-2021-44228"


@pytest.mark.parametrize("name,body,expected_name,expected_ecosystem", [
    ("requirements.txt", "requests==2.28.1\n# note\nflask==2.0.1\n-r other.txt\n", "requests", "PyPI"),
    ("go.mod", "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n", "github.com/gin-gonic/gin", "Go"),
    ("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.190"\n', "serde", "crates.io"),
    ("Gemfile.lock", "GEM\n  specs:\n    rails (7.0.4)\n", "rails", "RubyGems"),
])
def test_manifest_parsers(tmp_path, name, body, expected_name, expected_ecosystem):
    path = tmp_path / name
    path.write_text(body)
    components, _ = parse_manifest(path)
    assert components[0]["name"] == expected_name
    assert components[0]["ecosystem"] == expected_ecosystem


def test_cyclonedx_sbom(tmp_path):
    sbom = {"bomFormat": "CycloneDX", "components": [
        {"name": "log4j-core", "version": "2.14.1",
         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    ]}
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps(sbom))
    components, label = parse_manifest(path)
    assert components[0]["ecosystem"] == "Maven"
    assert components[0]["name"] == "org.apache.logging.log4j:log4j-core"


def test_plain_text_fallback(tmp_path):
    path = tmp_path / "email.txt"
    path.write_text("Please patch CVE-2021-44228 and cve-2023-40000 before Friday.")
    findings, label = load_findings(path)
    assert {f["cve"] for f in findings} == {"CVE-2021-44228", "CVE-2023-40000"}


def test_severity_column_is_the_findings_own_not_the_assets():
    """Regression: a Snyk export has ISSUE_SEVERITY and PROJECT_CRITICALITY.

    'criticality' used to be a raw_severity alias, and the longest-alias-first
    tiebreak made it beat 'severity', so every Snyk import silently recorded the
    project's business-criticality tag as the finding's severity.
    """
    from vulnometry.intake.tabular import _map_columns

    snyk = ["ISSUE_SEVERITY_RANK", "ISSUE_SEVERITY", "CVE", "PROJECT_NAME",
            "PROJECT_CRITICALITY", "PROJECT_ENVIRONMENT", "PACKAGE_NAME_AND_VERSION"]
    mapping = _map_columns(snyk)
    assert snyk[mapping["raw_severity"]] == "ISSUE_SEVERITY"

    # and where only an asset-criticality column exists, severity stays unmapped
    # rather than being filled with the wrong thing
    assert "raw_severity" not in _map_columns(["CVE", "Asset", "Criticality"])

    # the common spellings still resolve
    for headers, expected in (
        (["CVE", "Severity"], "Severity"),
        (["CVE", "Risk"], "Risk"),
        (["CVE", "Severity Level", "Criticality"], "Severity Level"),
        (["CVE", "CVSS Severity"], "CVSS Severity"),
    ):
        assert headers[_map_columns(headers)["raw_severity"]] == expected


def test_scanner_severity_reaches_the_assessment_and_the_crosstab():
    from vulnometry.assessment import cvss_band, scanner_band

    assert scanner_band("CRITICAL") == "Critical"
    assert scanner_band("moderate") == "Medium"      # Red Hat / GHSA spelling
    assert scanner_band("Important") == "High"       # Red Hat spelling
    assert scanner_band("9.8") == "Critical"         # numeric scanners
    assert scanner_band("") == ""
    assert scanner_band("Bizarre") == "Bizarre"      # surfaced, not forced into a band

    assert cvss_band(9.8) == "Critical"
    assert cvss_band(7.0) == "High"
    assert cvss_band(4.0) == "Medium"
    assert cvss_band(0.1) == "Low"
    assert cvss_band(0) == "None"
