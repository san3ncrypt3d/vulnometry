"""The exposure model is the product. It gets the most tests."""

from vulnometry.exposure import measure_exposure, verdict_for
from vulnometry.inventory import UNKNOWN_ASSET, AssetProfile
from vulnometry.schema import (
    ConfirmedExploitation,
    ExploitArtifact,
    ExploitProbability,
    Severity,
    Weakness,
)


def wormable(score: float = 9.8) -> Weakness:
    return Weakness(
        cve_id="CVE-2024-1",
        resolved=True,
        severities=[Severity(
            version="3.1", base_score=score, rating="CRITICAL",
            attack_vector="NETWORK", attack_complexity="LOW",
            privileges_required="NONE", user_interaction="NONE",
            confidentiality="HIGH", integrity="HIGH", availability="HIGH",
        )],
    )


def local_nuisance() -> Weakness:
    return Weakness(
        cve_id="CVE-2024-2",
        resolved=True,
        severities=[Severity(
            version="3.1", base_score=3.3, rating="LOW",
            attack_vector="LOCAL", attack_complexity="HIGH",
            privileges_required="HIGH", user_interaction="REQUIRED",
            confidentiality="NONE", integrity="NONE", availability="LOW",
        )],
    )


CROWN_JEWEL = AssetProfile(name="checkout", tier=1, internet_exposed=True,
                           environment="production", data_classification="restricted",
                           regimes=["pci-dss"], deployed=True)
LAB_BOX = AssetProfile(name="lab", tier=3, internet_exposed=False,
                       environment="development", data_classification="public", deployed=True)


def test_not_deployed_collapses_exposure_to_zero():
    """The headline claim: context can veto, with no override rule involved."""
    shelved = AssetProfile(name="decommissioned", tier=1, internet_exposed=True, deployed=False)
    measure = measure_exposure(
        wormable(10.0),
        ExploitProbability(probability=0.97, resolved=True),
        ConfirmedExploitation(confirmed=True, ransomware_linked=True),
        [ExploitArtifact(maturity="weaponised", popularity=5000)],
        shelved,
    )
    assert measure.index == 0.0
    assert measure.verdict == "Accept"
    assert measure.collapsed_by == "not-deployed"
    assert measure.threat == 1.0, "threat is still maximal, only reachability vetoed"


def test_same_cve_lands_differently_by_context():
    args = (wormable(10.0), ExploitProbability(probability=0.94, resolved=True),
            ConfirmedExploitation(confirmed=True), [])
    critical = measure_exposure(*args, CROWN_JEWEL)
    lab = measure_exposure(*args, LAB_BOX)

    assert critical.verdict == "Contain"
    assert critical.index > lab.index * 3
    assert critical.threat == lab.threat, "threat must be context-independent"
    assert critical.reachability > lab.reachability
    assert critical.consequence > lab.consequence


def test_severe_but_unreachable_ranks_below_mild_and_exploited():
    """The failure mode this whole tool exists to prevent."""
    severe_unreachable = measure_exposure(
        wormable(9.8), ExploitProbability(probability=0.02, resolved=True),
        ConfirmedExploitation(), [],
        AssetProfile(name="lab", tier=3, internet_exposed=False, deployed=True,
                     environment="development", data_classification="public"),
    )
    mild_exploited = measure_exposure(
        Weakness(cve_id="CVE-2024-3", resolved=True, severities=[Severity(
            version="3.1", base_score=6.1, attack_vector="NETWORK", attack_complexity="LOW",
            privileges_required="NONE", user_interaction="NONE",
            confidentiality="HIGH", integrity="LOW", availability="NONE")]),
        ExploitProbability(probability=0.6, resolved=True),
        ConfirmedExploitation(confirmed=True), [], CROWN_JEWEL,
    )
    assert mild_exploited.index > severe_unreachable.index
    assert mild_exploited.verdict == "Contain"


def test_confirmed_exploitation_maxes_threat():
    measure = measure_exposure(
        wormable(), ExploitProbability(probability=0.001, resolved=True),
        ConfirmedExploitation(confirmed=True, federal_deadline="2025-01-01"), [], CROWN_JEWEL,
    )
    assert measure.threat == 1.0, "observation beats prediction"
    assert any("KEV" in b for b in measure.threat_basis)


def test_compensating_controls_reduce_reachability_only():
    base = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                            ConfirmedExploitation(), [], CROWN_JEWEL)
    guarded = AssetProfile(**{**CROWN_JEWEL.__dict__, "compensating_controls": ["WAF virtual patch"]})
    with_controls = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                                     ConfirmedExploitation(), [], guarded)
    assert with_controls.reachability < base.reachability
    assert with_controls.consequence == base.consequence
    assert with_controls.threat == base.threat


def test_unknown_context_is_pessimistic_not_optimistic():
    args = (wormable(), ExploitProbability(probability=0.4, resolved=True), ConfirmedExploitation(), [])
    unknown = measure_exposure(*args, UNKNOWN_ASSET)
    known_safe = measure_exposure(*args, AssetProfile(name="x", tier=3, internet_exposed=False, deployed=True))
    assert unknown.reachability > known_safe.reachability


def test_regulated_scope_raises_consequence():
    plain = AssetProfile(name="a", tier=2, deployed=True, data_classification="confidential")
    regulated = AssetProfile(name="a", tier=2, deployed=True, data_classification="confidential",
                             regimes=["hipaa"])
    args = (wormable(), ExploitProbability(probability=0.3, resolved=True), ConfirmedExploitation(), [])
    assert measure_exposure(*args, regulated).consequence > measure_exposure(*args, plain).consequence


def test_local_nuisance_on_a_lab_box_is_accepted():
    measure = measure_exposure(local_nuisance(), ExploitProbability(probability=0.0004, resolved=True),
                               ConfirmedExploitation(), [], LAB_BOX)
    assert measure.verdict == "Accept"
    assert measure.index < 20


def test_weaponised_artifacts_outrank_a_bare_poc():
    args = (wormable(), ExploitProbability(probability=0.05, resolved=True), ConfirmedExploitation())
    poc = measure_exposure(*args, [ExploitArtifact(maturity="proof-of-concept")], CROWN_JEWEL)
    armed = measure_exposure(*args, [ExploitArtifact(maturity="weaponised")], CROWN_JEWEL)
    assert armed.threat > poc.threat


def test_every_factor_carries_its_reasoning():
    measure = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                               ConfirmedExploitation(), [], CROWN_JEWEL)
    assert measure.threat_basis and measure.reachability_basis and measure.consequence_basis


def test_confidence_degrades_with_missing_evidence():
    complete = measure_exposure(wormable(), ExploitProbability(probability=0.5, resolved=True),
                                ConfirmedExploitation(), [], CROWN_JEWEL)
    sparse = measure_exposure(Weakness(cve_id="CVE-2024-9"), ExploitProbability(), ConfirmedExploitation(),
                              [], UNKNOWN_ASSET)
    assert complete.confidence == "high"
    assert sparse.confidence == "low"


def test_verdict_thresholds():
    assert verdict_for(950) == "Contain"
    assert verdict_for(700) == "Contain"
    assert verdict_for(699) == "Remediate"
    assert verdict_for(400) == "Remediate"
    assert verdict_for(399) == "Schedule"
    assert verdict_for(150) == "Schedule"
    assert verdict_for(149) == "Accept"


def test_index_stays_in_range_across_extremes():
    for probability in (None, 0.0, 0.5, 1.0):
        for asset in (UNKNOWN_ASSET, CROWN_JEWEL, LAB_BOX):
            measure = measure_exposure(
                wormable(10.0),
                ExploitProbability(probability=probability, resolved=probability is not None),
                ConfirmedExploitation(confirmed=True), [], asset,
            )
            assert 0.0 <= measure.index <= 1000.0
