"""End-to-end tests through the real code path.

Rather than mocking functions, we prime the SQLite feed cache with synthetic
upstream payloads. Cache keys, parsers, the exposure model, SLA policy and
rendering are all genuinely exercised. Only the socket is replaced.
"""

import asyncio

from vulnometry.assessment import assess_finding, assess_portfolio, portfolio_summary
from vulnometry.feeds import advisories as adv
from vulnometry.feeds import catalogue as kev
from vulnometry.feeds import probability as epss_feed
from vulnometry.feeds import record as rec
from vulnometry.inventory import Inventory
from vulnometry.net import _cache_key, cache

from . import fixtures as fx

REMOTE = ("NETWORK", "LOW", "NONE", "NONE")
LOCAL = ("LOCAL", "HIGH", "HIGH", "REQUIRED")

INVENTORY = Inventory.from_dict({"assets": [
    {"name": "checkout-api", "tier": 1, "owner": "pay@x.com", "business_unit": "Commerce",
     "environment": "production", "internet_exposed": True, "data_classification": "restricted",
     "regimes": ["pci-dss"], "hosts": ["checkout-*"], "components": ["org.apache.logging.log4j*"]},
    {"name": "internal-wiki", "tier": 3, "owner": "it@x.com", "business_unit": "Corporate",
     "environment": "production", "internet_exposed": False, "data_classification": "internal"},
    {"name": "ml-sandbox", "tier": 3, "environment": "development", "internet_exposed": False,
     "deployed": False, "data_classification": "public"},
]})


async def prime(entries):
    for method, url, params, body, payload in entries:
        await cache().set(_cache_key(method, url, params, body), payload, ttl=3600)


async def prime_all():
    await prime([
        ("GET", rec.NVD_ENDPOINT, {"cveId": "CVE-2021-44228"}, None,
         fx.nvd("CVE-2021-44228", 10.0, REMOTE, "Log4j JNDI remote code execution.")),
        ("GET", rec.NVD_ENDPOINT, {"cveId": "CVE-2023-40000"}, None,
         fx.nvd("CVE-2023-40000", 3.3, LOCAL, "Local denial of service.", ("NONE", "NONE", "LOW"))),
        ("GET", epss_feed.EPSS_ENDPOINT, {"cve": "CVE-2021-44228"}, None,
         fx.epss("CVE-2021-44228", "0.944400000", "0.999900000")),
        ("GET", epss_feed.EPSS_ENDPOINT, {"cve": "CVE-2023-40000"}, None,
         fx.epss("CVE-2023-40000", "0.000410000", "0.079000000")),
        ("GET", kev.KEV_ENDPOINT, None, None, fx.KEV_DOCUMENT),
        ("GET", adv.OSV_VULN.format(vuln_id="CVE-2021-44228"), None, None, fx.OSV_LOG4SHELL),
        ("GET", adv.OSV_VULN.format(vuln_id="CVE-2023-40000"), None, None, None),
        ("GET", adv.GH_ADVISORY, {"cve_id": "CVE-2021-44228", "per_page": 10}, None, fx.GHSA_LOG4SHELL),
        ("GET", adv.GH_ADVISORY, {"cve_id": "CVE-2023-40000", "per_page": 10}, None, []),
        ("GET", adv.GH_SEARCH,
         {"q": "CVE-2021-44228 in:name,description,readme", "sort": "stars", "per_page": 20},
         None, fx.GITHUB_REPOS),
    ])


def test_full_assessment_against_a_critical_asset():
    async def run():
        await prime_all()
        return await assess_finding("CVE-2021-44228", inventory=INVENTORY,
                                    asset_name="checkout-api", lens="forensic")

    result = asyncio.run(run())
    assert result.weakness.resolved
    assert result.weakness.primary_severity().base_score == 10.0
    assert result.exploitation.confirmed and result.exploitation.ransomware_linked
    assert result.exposure.verdict == "Contain"
    assert result.exposure.index > 800
    assert "2.15.0" in " ".join(result.fixes)
    assert result.owner == "pay@x.com"
    assert result.business_unit == "Commerce"
    assert result.due_by, "a Contain verdict on a tier-1 asset must carry a date"
    assert result.sla_days and result.sla_days <= 3
    assert not result.gaps


def test_aggregator_repositories_are_filtered_out():
    async def run():
        await prime_all()
        return await adv.exploit_artifacts("CVE-2021-44228")

    artifacts = asyncio.run(run())
    labels = [a.label for a in artifacts]
    assert "redteam/log4shell-rce" in labels
    assert not any("PoC-in-GitHub" in label for label in labels)
    assert artifacts[0].maturity == "weaponised", "a metasploit module is not a bare PoC"


def test_host_matching_attaches_the_right_asset():
    async def run():
        await prime_all()
        return await assess_finding("CVE-2021-44228", inventory=INVENTORY, host="checkout-07")

    result = asyncio.run(run())
    assert result.asset == "checkout-api"
    assert result.owner == "pay@x.com"


def test_component_matching_attaches_the_right_asset():
    async def run():
        await prime_all()
        return await assess_finding("CVE-2021-44228", inventory=INVENTORY,
                                    component="org.apache.logging.log4j:log4j-core")

    assert asyncio.run(run()).asset == "checkout-api"


def test_scanner_identifiers_are_kept_even_when_nothing_matches():
    async def run():
        await prime_all()
        return await assess_finding(
            "CVE-2021-44228", inventory=INVENTORY,
            asset_name="acme/mystery-service:pom.xml", host="mystery-01.example.com",
            component="com.example:unrelated-lib",
        )

    result = asyncio.run(run())
    assert result.asset == ""                                     # no inventory match
    assert result.source_asset == "acme/mystery-service:pom.xml"  # but the scan's label survives
    assert result.source_host == "mystery-01.example.com"
    assert result.scanner_ref() == "acme/mystery-service:pom.xml"
    assert result.where() == "acme/mystery-service:pom.xml"       # reports fall back to it


def test_matched_asset_still_records_what_the_scan_called_it():
    async def run():
        await prime_all()
        return await assess_finding("CVE-2021-44228", inventory=INVENTORY, host="checkout-07")

    result = asyncio.run(run())
    assert result.asset == "checkout-api"
    assert result.source_host == "checkout-07"
    assert result.where() == "checkout-api"


def test_one_cve_three_verdicts():
    async def run():
        await prime_all()
        return await assess_portfolio(
            [{"cve": "CVE-2021-44228", "asset": name}
             for name in ("checkout-api", "internal-wiki", "ml-sandbox")],
            inventory=INVENTORY, lens="full",
        )

    results = asyncio.run(run())
    verdicts = {r.asset: r.exposure.verdict for r in results}
    assert verdicts["checkout-api"] == "Contain"
    assert verdicts["ml-sandbox"] == "Accept"
    assert results[0].asset == "checkout-api", "results must be ranked worst-first"
    assert len({r.exposure.threat for r in results}) == 1


def test_portfolio_summary_attributes_work():
    async def run():
        await prime_all()
        return await assess_portfolio([
            {"cve": "CVE-2021-44228", "asset": "checkout-api"},
            {"cve": "CVE-2021-44228", "asset": "ml-sandbox"},
            {"cve": "CVE-2023-40000", "asset": "internal-wiki"},
        ], inventory=INVENTORY, lens="signal")

    results = asyncio.run(run())
    summary = portfolio_summary(results)
    assert summary["assessed"] == 3
    assert summary["contain_now"] == ["CVE-2021-44228"]
    assert summary["suppressed_by_context"] == 2
    assert summary["not_deployed"] == 1
    assert summary["unreachable_here"] == 1
    assert "pay@x.com" in summary["load_by_owner"]
    assert summary["exposure_by_business_unit"]["Commerce"] > 0


def test_nvd_falls_back_to_the_cve_program():
    async def run():
        await prime([
            ("GET", rec.NVD_ENDPOINT, {"cveId": "CVE-2024-11111"}, None, {"vulnerabilities": []}),
            ("GET", rec.CNA_ENDPOINT.format(cve_id="CVE-2024-11111"), None, None, {
                "cveMetadata": {"cveId": "CVE-2024-11111", "state": "PUBLISHED",
                                "datePublished": "2024-06-01T00:00:00", "assignerShortName": "acme"},
                "containers": {"cna": {
                    "descriptions": [{"lang": "en", "value": "Fallback description from the CNA."}],
                    "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH",
                                              "attackVector": "NETWORK", "attackComplexity": "LOW",
                                              "privilegesRequired": "NONE", "userInteraction": "NONE",
                                              "confidentialityImpact": "HIGH"}}],
                    "references": [], "problemTypes": [],
                }},
            }),
        ])
        return await rec.fetch("CVE-2024-11111")

    record = asyncio.run(run())
    assert record.resolved
    assert record.retrieved_from == "cve-program"
    assert record.primary_severity().base_score == 7.5


def test_partial_feed_failure_is_reported_not_fatal():
    async def run():
        await prime([
            ("GET", epss_feed.EPSS_ENDPOINT, {"cve": "CVE-2021-44228"}, None,
             fx.epss("CVE-2021-44228", "0.9444")),
            ("GET", kev.KEV_ENDPOINT, None, None, fx.KEV_DOCUMENT),
        ])
        from vulnometry import config

        config.settings().offline = True
        return await assess_finding("CVE-2021-44228", inventory=INVENTORY,
                                    asset_name="checkout-api", lens="signal")

    result = asyncio.run(run())
    assert result.exploitation.confirmed
    assert result.exposure.threat == 1.0, "threat survives losing the CVE record"
    assert any("record" in gap.lower() or "nvd" in gap.lower() for gap in result.gaps)
    assert result.exposure.confidence in ("low", "medium")
