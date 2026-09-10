"""End-to-end tests through the real code path.

Rather than mocking functions, we prime the SQLite feed cache with synthetic
upstream payloads. Cache keys, parsers, the exposure model, SLA policy and
rendering are all genuinely exercised. Only the socket is replaced.
"""

import asyncio

import pytest

_SELF_SIGNED_PEM = """\n-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIUEeR/dAhRrqt36vrmrWKK/h+USeMwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSdnVsbm9tZXRyeSB0ZXN0IENBMB4XDTI2MDkxMDE1MzA0
NFoXDTM2MDkwNzE1MzA0NFowHTEbMBkGA1UEAwwSdnVsbm9tZXRyeSB0ZXN0IENB
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoaOkJvz6LyOv0cmGjDf
xzvfFBaFbsGWNLMvr2+RtseSDz4UUKnQEdxEiU6z+W7AVNFS55hi6rED9JBNtSsE
2bOVjrBp7qslW+zW/5W901Nu+vwxLs97w4D4zqUkAMCC3dqNvzChZquUPzfPQ76h
cpmj6uc6oXQ8b0BAXLYbfR4Uimt39Dm7oEP3RllmXdd2NAdSSwV1vBECZmhjACmE
13XOrHBZFF+wNUOI3ZCjDXda98x7/NeMqyUol3BkkFreP/4y5zLZRbdBsxss/MZV
pgrP1bYa/P0RDFP3pe2jxByKcExPBJlMKQgp5pBeRVsn9E/Q0p712VO22YwQmgUH
HwIDAQABo1MwUTAdBgNVHQ4EFgQUQ6c/Gd6pZsvtJYvonflG2pyXhMswHwYDVR0j
BBgwFoAUQ6c/Gd6pZsvtJYvonflG2pyXhMswDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAEjZGOzpgcXNGIWzUownOjvUiLhS5dk64jcxV9zzrDbDI
V5RYH2QHuDhhI7wWkOZiMErGTk3Mjv2ZF42prGBxHYSKdIl5ZabPnzJovB7P74Jo
HyuJ/Hw4fkM+HwHQNzBFE65MAYdpA7GflK5aqlM6pFIbMXi8c4hRoewbcvpyryyI
DTNfG3kSK06F7RMShtAJUOXLHdvYxTPK77Z8bmVfnElxl5mMZqvRFLl3k0yhK1Jo
C4uElx3+HIn0O8A+se6KNeGZW3Pn8VQnr2huaeoSelN4juyc27c+qsbnTPsFM37a
Ag/novqp0ZFCavEBc2iKtY+1ZsLR6oYQk/rYM7KwLg==
-----END CERTIFICATE-----
"""


async def _no_sleep(_seconds):
    return None

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


def test_reduction_funnel_counts_upgrades_not_rows():
    """One package on one asset is one upgrade, however many CVEs it carries."""
    async def run():
        await prime_all()
        return await assess_portfolio([
            # same package, same asset, two CVEs -> one upgrade
            {"cve": "CVE-2021-44228", "asset": "checkout-api",
             "component": "org.apache.logging.log4j:log4j-core: 2.14.1"},
            {"cve": "CVE-2023-40000", "asset": "checkout-api",
             "component": "org.apache.logging.log4j:log4j-core: 2.14.1"},
            # same CVE, different asset -> a separate pair and a separate upgrade
            {"cve": "CVE-2021-44228", "asset": "internal-wiki",
             "component": "org.apache.logging.log4j:log4j-core: 2.14.1"},
        ], inventory=INVENTORY, lens="signal")

    results = asyncio.run(run())
    r = portfolio_summary(results)["reduction"]

    assert r["findings_assessed"] == 3
    assert r["unique_cves"] == 2
    assert r["cve_asset_pairs"] == 3
    # two assets x one package = two upgrades, from three findings
    assert r["work_items"] == 2
    assert r["findings_per_work_item"] == 1.5
    assert r["actionable_work_items"] <= r["work_items"]
    assert 0 <= r["effort_reduction_pct"] <= 100

    # the headline reduction is measured against the severity queue, not the row
    # count: a severity-driven programme would chase everything CVSS rates High+
    assert r["urgent_on_severity_alone"] >= r["actionable_findings"]
    assert r["analysis_reduction_pct"] == round(
        100 * (1 - r["actionable_findings"] / r["urgent_on_severity_alone"])
    )


def test_package_strips_the_version_however_it_is_written():
    from vulnometry.assessment import _package

    assert _package("org.apache.tomcat.embed:tomcat-embed-core: 11.0.9") == \
        "org.apache.tomcat.embed:tomcat-embed-core"
    assert _package("io.netty:netty-handler:4.1.100.Final") == "io.netty:netty-handler"
    assert _package("lodash@4.17.20") == "lodash"
    assert _package("requests 2.25.1") == "requests"
    assert _package("no-version-here") == "no-version-here"
    assert _package("") == ""


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


def test_system_trust_is_used_when_truststore_is_available(monkeypatch, tmp_path):
    """Corporate TLS proxies re-sign traffic with a root the OS trusts and
    certifi does not, so every feed fails on those networks. Verify through the
    OS instead, unless the operator has said otherwise."""
    import ssl

    from vulnometry.net import FeedError, _verification

    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "VULNOMETRY_SYSTEM_TRUST"):
        monkeypatch.delenv(name, raising=False)
    context = _verification()
    assert isinstance(context, ssl.SSLContext)
    assert type(context).__module__.startswith("truststore")

    # a named bundle is ADDED to the OS store, not swapped for it: a corporate
    # image that sets SSL_CERT_FILE must not lose the system roots, or the very
    # machines this exists for start failing again
    bundle = tmp_path / "extra.pem"
    bundle.write_text(_SELF_SIGNED_PEM)
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    layered = _verification()
    assert isinstance(layered, ssl.SSLContext)
    assert type(layered).__module__.startswith("truststore")
    monkeypatch.delenv("SSL_CERT_FILE")

    # an unreadable bundle is a configuration error worth surfacing
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "does-not-exist.pem"))
    with pytest.raises(FeedError, match="could not be read"):
        _verification()
    monkeypatch.delenv("SSL_CERT_FILE")

    # and there is a way out if the OS store is the problem
    monkeypatch.setenv("VULNOMETRY_SYSTEM_TRUST", "0")
    assert _verification() is True


def test_a_certificate_failure_fails_fast_with_an_explanation(monkeypatch):
    """Retrying a rejected certificate four times cannot help, and the raw
    OpenSSL text sends people hunting for a CA bundle to download."""
    import asyncio

    import httpx

    import vulnometry.net as net
    from vulnometry.config import reset_settings
    from vulnometry.net import Client, FeedError

    # the backoff is real seconds; shorten the loop rather than sitting through it
    monkeypatch.setenv("VULNOMETRY_MAX_RETRIES", "2")
    reset_settings()
    monkeypatch.setattr(net.asyncio, "sleep", _no_sleep)

    class Rejecting(httpx.AsyncClient):
        attempts = 0

        async def request(self, *args, **kwargs):
            type(self).attempts += 1
            raise httpx.ConnectError(
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                "unable to get local issuer certificate"
            )

    client = Client()
    client._client = Rejecting()

    async def run():
        return await client.request_json("GET", "https://www.cisa.gov/x", source="cisa-kev")

    with pytest.raises(FeedError) as caught:
        asyncio.run(run())

    assert Rejecting.attempts == 1, "a bad certificate must not be retried"
    message = str(caught.value)
    assert "TLS-inspecting proxy" in message
    assert "truststore" in message

    # and the retry loop really is live, so the count above means the fast path
    class Flaky(Rejecting):
        attempts = 0

        async def request(self, *args, **kwargs):
            type(self).attempts += 1
            raise httpx.ConnectError("connection reset by peer")

    other = Client()
    other._client = Flaky()

    async def run_flaky():
        return await other.request_json("GET", "https://www.cisa.gov/x", source="cisa-kev")

    with pytest.raises(FeedError):
        asyncio.run(run_flaky())
    assert Flaky.attempts > 1, "ordinary transport errors are still retried"
    reset_settings()
