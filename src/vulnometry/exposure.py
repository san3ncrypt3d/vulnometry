"""Business Exposure Index: 1000 * Threat**0.8 * Reachability**0.7 * Consequence**0.6."""

from __future__ import annotations

from .inventory import UNKNOWN_ASSET, AssetProfile
from .schema import (
    ConfirmedExploitation,
    ExploitArtifact,
    ExploitProbability,
    ExposureMeasure,
    Weakness,
)

MODEL_VERSION = "bei-1.0"

THREAT_EXPONENT = 0.8
REACH_EXPONENT = 0.7
CONSEQUENCE_EXPONENT = 0.6

THRESHOLDS = [(700, "Contain"), (400, "Remediate"), (150, "Schedule"), (0, "Accept")]

VERDICT_MEANING = {
    "Contain": "Act now, outside the normal change process.",
    "Remediate": "Fix within this sprint, ahead of the routine cycle.",
    "Schedule": "Queue for the next planned maintenance window.",
    "Accept": "No action warranted. Record the decision and move on.",
}

VECTOR_REACH = {"N": 1.0, "A": 0.45, "L": 0.2, "P": 0.05}

MATURITY_THREAT = {"weaponised": 0.78, "proof-of-concept": 0.55, "referenced": 0.35}


def _first_letter(value: str) -> str:
    return (value or "").upper()[:1]


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def compute_threat(
    probability: ExploitProbability,
    exploitation: ConfirmedExploitation,
    artifacts: list[ExploitArtifact],
) -> tuple[float, list[str]]:
    basis: list[str] = []

    if exploitation.confirmed:
        basis.append("CISA KEV lists this as exploited in the wild: observed, not predicted")
        if exploitation.ransomware_linked:
            basis.append("Associated with known ransomware campaigns")
        if exploitation.federal_deadline:
            basis.append(f"US federal remediation deadline {exploitation.federal_deadline}")
        return 1.0, basis

    candidates: list[float] = []

    if probability.probability is not None:
        epss_threat = probability.probability ** 0.35
        candidates.append(epss_threat)
        percentile = (
            f", ahead of {probability.percentile * 100:.0f}% of all CVEs"
            if probability.percentile is not None
            else ""
        )
        basis.append(
            f"EPSS puts exploitation within 30 days at "
            f"{probability.probability * 100:.2f}%{percentile}"
        )
    else:
        basis.append("No EPSS score, usually a very new CVE, so treat as unresolved rather than safe")

    if artifacts:
        best = max(MATURITY_THREAT.get(a.maturity, 0.3) for a in artifacts)
        popularity = max((a.popularity or 0) for a in artifacts)
        if popularity > 200:
            best = min(0.85, best + 0.07)
        candidates.append(best)
        kinds = sorted({a.maturity for a in artifacts})
        basis.append(f"Public exploit material found ({', '.join(kinds)}; {len(artifacts)} item(s))")

    if not candidates:
        return 0.08, basis + ["No evidence of exploitation activity"]

    threat = max(candidates)
    return _clamp(threat, 0.02, 1.0), basis


def compute_reachability(
    weakness: Weakness, asset: AssetProfile
) -> tuple[float, list[str], str]:
    basis: list[str] = []
    severity = weakness.primary_severity()

    if asset.deployed is False:
        return 0.0, [f"{asset.name} does not run the affected component"], "not-deployed"

    if severity and severity.attack_vector:
        letter = _first_letter(severity.attack_vector)
        reach = VECTOR_REACH.get(letter, 0.5)
        basis.append(f"Attack vector is {severity.attack_vector.lower()}")
    else:
        reach = 0.6
        basis.append("Attack vector unpublished, assumed partially reachable")

    if severity:
        if _first_letter(severity.attack_complexity) == "H":
            reach *= 0.7
            basis.append("High attack complexity narrows who can pull it off")
        privileges = _first_letter(severity.privileges_required)
        if privileges == "L":
            reach *= 0.8
            basis.append("Requires some level of authenticated access")
        elif privileges == "H":
            reach *= 0.55
            basis.append("Requires privileged access already")
        if _first_letter(severity.user_interaction) == "R":
            reach *= 0.75
            basis.append("Needs a user to be tricked into acting")

    if asset.internet_exposed is True:
        basis.append(f"{asset.name} is reachable from the internet")
    elif asset.internet_exposed is False:
        reach *= 0.4
        basis.append(f"{asset.name} is not internet-reachable")
    else:
        reach *= 0.7
        basis.append("Internet exposure unknown: discounted, not dismissed")

    if asset.deployed is None and asset.name != UNKNOWN_ASSET.name:
        reach *= 0.9
        basis.append("Deployment status unconfirmed")

    if asset.has_controls:
        reach *= 0.45
        basis.append(f"Compensating controls in place: {', '.join(asset.compensating_controls[:3])}")

    collapsed = "reachability" if reach < 0.05 else ""
    return _clamp(reach), basis, collapsed


def compute_consequence(weakness: Weakness, asset: AssetProfile) -> tuple[float, list[str]]:
    basis: list[str] = []
    severity = weakness.primary_severity()

    if severity:
        impact = severity.impact_fraction
        if severity.confidentiality or severity.integrity or severity.availability:
            basis.append(
                f"CVSS impact C:{severity.confidentiality or '?'} "
                f"I:{severity.integrity or '?'} A:{severity.availability or '?'}"
            )
        elif severity.base_score is not None:
            basis.append(f"CVSS {severity.version} base score {severity.base_score:g} used as an impact proxy")
    else:
        impact = 0.5
        basis.append("No CVSS published, impact assumed moderate pending analysis")

    consequence = impact * asset.tier_weight
    basis.append(f"{asset.name} is {asset.tier_label} (tier weight {asset.tier_weight:g})")

    consequence *= asset.data_weight
    if asset.data_classification:
        basis.append(f"Holds {asset.data_classification} data (weight {asset.data_weight:g})")

    if asset.regulated:
        consequence *= 1.12
        basis.append(f"In scope for {', '.join(asset.regimes)}, breach carries reporting duties")

    if asset.is_production:
        consequence *= 1.08
        basis.append("Production environment")
    elif (asset.environment or "").lower().startswith("dev"):
        consequence *= 0.7
        basis.append("Development environment")

    return _clamp(consequence, 0.02, 1.0), basis


def verdict_for(index: float) -> str:
    for threshold, label in THRESHOLDS:
        if index >= threshold:
            return label
    return "Accept"


def _confidence(weakness: Weakness, probability: ExploitProbability, asset: AssetProfile) -> str:
    known = 0
    if weakness.resolved and weakness.primary_severity():
        known += 1
    if probability.resolved:
        known += 1
    if asset.tier is not None and asset.internet_exposed is not None:
        known += 1
    return {0: "low", 1: "low", 2: "medium", 3: "high"}[known]


def measure_exposure(
    weakness: Weakness,
    probability: ExploitProbability,
    exploitation: ConfirmedExploitation,
    artifacts: list[ExploitArtifact] | None = None,
    asset: AssetProfile | None = None,
) -> ExposureMeasure:
    artifacts = artifacts or []
    asset = asset or UNKNOWN_ASSET

    threat, threat_basis = compute_threat(probability, exploitation, artifacts)
    reach, reach_basis, collapsed = compute_reachability(weakness, asset)
    consequence, consequence_basis = compute_consequence(weakness, asset)

    index = 1000.0 * (
        (threat ** THREAT_EXPONENT)
        * (reach ** REACH_EXPONENT)
        * (consequence ** CONSEQUENCE_EXPONENT)
    )
    index = round(_clamp(index, 0.0, 1000.0), 1)

    return ExposureMeasure(
        index=index,
        verdict=verdict_for(index),
        model_version=MODEL_VERSION,
        threat=round(threat, 3),
        reachability=round(reach, 3),
        consequence=round(consequence, 3),
        threat_basis=threat_basis,
        reachability_basis=reach_basis,
        consequence_basis=consequence_basis,
        collapsed_by=collapsed,
        confidence=_confidence(weakness, probability, asset),
    )


def directive_for(
    measure: ExposureMeasure,
    exploitation: ConfirmedExploitation,
    fixes: list[str],
    asset: AssetProfile,
    due_by: str = "",
) -> str:
    """The action sentence that goes in the ticket."""
    parts = [VERDICT_MEANING.get(measure.verdict, "Review.")]

    if measure.collapsed_by == "not-deployed":
        return (
            f"{asset.name} does not run the affected component, so there is nothing to fix here. "
            "Confirm the inventory entry is current, then close."
        )

    if due_by:
        parts.append(f"Target date {due_by}.")
    if exploitation.confirmed and exploitation.federal_deadline:
        parts.append(f"CISA deadline for federal agencies was {exploitation.federal_deadline}.")
    if fixes:
        parts.append(f"Upgrade to {', '.join(fixes[:3])}.")
    elif measure.verdict in ("Contain", "Remediate"):
        parts.append("No fixed version published. Apply the vendor mitigation or isolate the service.")
    if measure.confidence == "low":
        parts.append("Confidence is low; the inventory entry or the CVE record is incomplete.")

    return " ".join(parts)
