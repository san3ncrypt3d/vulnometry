"""Data types."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.IGNORECASE)


def canonical_cve(raw: str) -> str:
    cve = (raw or "").strip().upper()
    if not CVE_PATTERN.match(cve):
        raise ValueError(f"{raw!r} is not a CVE identifier (expected CVE-YYYY-NNNN)")
    return cve


def harvest_cve_ids(text: str) -> list[str]:
    found = re.findall(r"CVE-\d{4}-\d{4,19}", text or "", flags=re.IGNORECASE)
    ordered: dict[str, None] = {}
    for item in found:
        ordered.setdefault(item.upper(), None)
    return list(ordered)


def _prune(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _prune(v) for k, v in obj.items() if v not in (None, [], {}, "")}
    if isinstance(obj, list):
        return [_prune(v) for v in obj]
    return obj


@dataclass
class Serialisable:
    def to_dict(self, prune: bool = True) -> dict:
        data = asdict(self)
        return _prune(data) if prune else data


@dataclass
class Severity(Serialisable):
    """A CVSS vector, decomposed into the parts the exposure model uses."""

    version: str = ""
    base_score: float | None = None
    rating: str = ""
    vector: str = ""
    issuer: str = ""
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""

    def _letter(self, value: str) -> str:
        return (value or "").upper()[:1]

    @property
    def impact_fraction(self) -> float:
        """0-1 proxy for how much damage successful exploitation does."""
        weights = {"H": 1.0, "L": 0.5, "N": 0.0}
        letters = [self._letter(self.confidentiality), self._letter(self.integrity), self._letter(self.availability)]
        known = [weights[letter] for letter in letters if letter in weights]
        if known:
            return min(1.0, max(known) * 0.7 + (sum(known) / 3.0) * 0.3)
        if self.base_score is not None:
            return min(1.0, self.base_score / 10.0)
        return 0.5


@dataclass
class Citation(Serialisable):
    url: str = ""
    issuer: str = ""
    labels: list[str] = field(default_factory=list)


@dataclass
class Remedy(Serialisable):
    ecosystem: str = ""
    component: str = ""
    affected_range: str = ""
    fixed_in: str = ""


@dataclass
class Weakness(Serialisable):
    """The public record for a CVE, merged across NVD and the CVE Program."""

    cve_id: str = ""
    summary: str = ""
    published: str = ""
    updated: str = ""
    state: str = ""
    severities: list[Severity] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    citations: list[Citation] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    issuer: str = ""
    retrieved_from: str = ""
    resolved: bool = False

    def primary_severity(self) -> Severity | None:
        if not self.severities:
            return None
        rank = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
        return sorted(
            self.severities,
            key=lambda s: (rank.get(s.version, 9), 0 if "nvd" in s.issuer.lower() else 1),
        )[0]


@dataclass
class ExploitProbability(Serialisable):
    cve_id: str = ""
    probability: float | None = None
    percentile: float | None = None
    as_of: str = ""
    resolved: bool = False


@dataclass
class ConfirmedExploitation(Serialisable):
    """A CISA KEV listing: observed exploitation, not predicted."""

    cve_id: str = ""
    vendor: str = ""
    product: str = ""
    title: str = ""
    catalogued: str = ""
    federal_deadline: str = ""
    required_action: str = ""
    ransomware_linked: bool = False
    confirmed: bool = False


@dataclass
class Bulletin(Serialisable):
    """A GHSA or OSV advisory, where fixed versions live."""

    ref: str = ""
    origin: str = ""
    summary: str = ""
    rating: str = ""
    aliases: list[str] = field(default_factory=list)
    published: str = ""
    remedies: list[Remedy] = field(default_factory=list)
    url: str = ""


@dataclass
class ExploitArtifact(Serialisable):
    maturity: str = ""
    url: str = ""
    label: str = ""
    popularity: int | None = None
    first_seen: str = ""


@dataclass
class ExposureMeasure(Serialisable):
    """The arithmetic behind a score."""

    index: float = 0.0
    verdict: str = "Accept"
    model_version: str = "bei-1.0"
    threat: float = 0.0
    reachability: float = 0.0
    consequence: float = 0.0
    threat_basis: list[str] = field(default_factory=list)
    reachability_basis: list[str] = field(default_factory=list)
    consequence_basis: list[str] = field(default_factory=list)
    collapsed_by: str = ""
    confidence: str = "medium"


@dataclass
class Assessment(Serialisable):
    """What Vulnometry concluded about one CVE, in one business context."""

    cve_id: str = ""
    exposure: ExposureMeasure = field(default_factory=ExposureMeasure)
    weakness: Weakness = field(default_factory=Weakness)
    probability: ExploitProbability = field(default_factory=ExploitProbability)
    exploitation: ConfirmedExploitation = field(default_factory=ConfirmedExploitation)
    bulletins: list[Bulletin] = field(default_factory=list)
    artifacts: list[ExploitArtifact] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)

    asset: str = ""
    owner: str = ""
    business_unit: str = ""
    environment: str = ""
    due_by: str = ""
    sla_days: int | None = None

    # what the scanner or spreadsheet called this finding's location, kept verbatim
    # whether or not it matched an asset in the inventory
    source_asset: str = ""
    source_host: str = ""
    source_component: str = ""

    directive: str = ""
    gaps: list[str] = field(default_factory=list)
    lens: str = "full"
    measured_at: str = ""

    def scanner_ref(self) -> str:
        """The identifier the scan used for this finding: project, host, or component."""
        return self.source_asset or self.source_host or self.source_component

    def where(self) -> str:
        """Best label for where this finding lives: the matched asset, else the scan's own name."""
        return self.asset or self.scanner_ref()

    def one_line(self) -> str:
        bits = [self.cve_id, f"BEI {self.exposure.index:.0f}", self.exposure.verdict]
        if self.where():
            bits.append(f"on {self.where()}")
        if self.exploitation.confirmed:
            bits.append("KEV")
        return " · ".join(bits)
