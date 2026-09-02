"""The business inventory: what you run, and in what context."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta
from pathlib import Path

TIER_LABELS = {1: "mission-critical", 2: "business-important", 3: "supporting"}

TIER_WEIGHT = {1: 1.0, 2: 0.72, 3: 0.45}
TIER_WEIGHT_UNKNOWN = 0.65

DATA_WEIGHT = {
    "restricted": 1.15,
    "confidential": 1.0,
    "internal": 0.85,
    "public": 0.7,
}
DATA_WEIGHT_UNKNOWN = 0.9

KNOWN_REGIMES = {"pci-dss", "hipaa", "sox", "gdpr", "fedramp", "nis2", "dora", "iso27001"}

BASE_SLA = {"Contain": 7, "Remediate": 30, "Schedule": 90, "Accept": 0}
TIER_SLA_FACTOR = {1: 0.5, 2: 1.0, 3: 1.75}


@dataclass
class AssetProfile:
    """One place you run something."""

    name: str = ""
    tier: int | None = None
    owner: str = ""
    business_unit: str = ""
    environment: str = ""
    internet_exposed: bool | None = None
    deployed: bool | None = None
    data_classification: str = ""
    regimes: list[str] = field(default_factory=list)
    compensating_controls: list[str] = field(default_factory=list)
    components: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    notes: str = ""


    @property
    def tier_label(self) -> str:
        return TIER_LABELS.get(self.tier or 0, "unclassified")

    @property
    def tier_weight(self) -> float:
        return TIER_WEIGHT.get(self.tier or 0, TIER_WEIGHT_UNKNOWN)

    @property
    def data_weight(self) -> float:
        return DATA_WEIGHT.get((self.data_classification or "").lower(), DATA_WEIGHT_UNKNOWN)

    @property
    def regulated(self) -> bool:
        return any(r.lower() in KNOWN_REGIMES for r in self.regimes)

    @property
    def is_production(self) -> bool:
        return (self.environment or "").lower().startswith("prod")

    @property
    def has_controls(self) -> bool:
        return bool(self.compensating_controls)

    def matches_component(self, *candidates: str) -> bool:
        """Does this asset run any of the named components?"""
        if not self.components:
            return False
        for candidate in candidates:
            text = (candidate or "").lower()
            if not text:
                continue
            for pattern in self.components:
                if fnmatch.fnmatch(text, pattern.lower()):
                    return True
        return False

    def matches_host(self, host: str) -> bool:
        text = (host or "").lower()
        if not text:
            return False
        if text == self.name.lower():
            return True
        return any(fnmatch.fnmatch(text, pattern.lower()) for pattern in self.hosts)

    def sla_days(self, verdict: str) -> int:
        base = BASE_SLA.get(verdict, 0)
        if not base:
            return 0
        days = base * TIER_SLA_FACTOR.get(self.tier or 0, 1.0)
        if self.regulated:
            days *= 0.6
        if self.is_production:
            days *= 0.8
        return max(1, int(round(days)))

    def due_date(self, verdict: str, from_date: date | None = None) -> str:
        days = self.sla_days(verdict)
        if not days:
            return ""
        return ((from_date or date.today()) + timedelta(days=days)).isoformat()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["tier_label"] = self.tier_label
        return {k: v for k, v in data.items() if v not in (None, [], "", {})}


UNKNOWN_ASSET = AssetProfile(name="(unspecified)", tier=None)


@dataclass
class Inventory:
    assets: list[AssetProfile] = field(default_factory=list)
    organisation: str = ""
    default_owner: str = ""
    source_path: str = ""


    @classmethod
    def from_dict(cls, data: dict, source_path: str = "") -> Inventory:
        raw_assets = data.get("assets") or data.get("services") or []
        assets = []
        for entry in raw_assets:
            if not isinstance(entry, dict):
                continue
            known = set(AssetProfile.__dataclass_fields__)
            clean = {k: v for k, v in entry.items() if k in known}
            if "criticality" in entry and "tier" not in clean:
                clean["tier"] = entry["criticality"]
            if "team" in entry and not clean.get("owner"):
                clean["owner"] = entry["team"]
            if "packages" in entry and not clean.get("components"):
                clean["components"] = entry["packages"]
            if isinstance(clean.get("regimes"), str):
                clean["regimes"] = [clean["regimes"]]
            if isinstance(clean.get("compensating_controls"), str):
                clean["compensating_controls"] = [clean["compensating_controls"]]
            assets.append(AssetProfile(**clean))
        return cls(
            assets=assets,
            organisation=data.get("organisation", "") or data.get("organization", ""),
            default_owner=data.get("default_owner", ""),
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".json",):
            data = json.loads(text)
        else:
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError("PyYAML is required to read YAML inventories") from exc
            data = yaml.safe_load(text) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{path} should contain a mapping with an 'assets' key")
        return cls.from_dict(data, source_path=str(path))

    @classmethod
    def discover(cls, explicit: str | None = None) -> Inventory:
        """Find an inventory without making the user pass a flag."""
        candidates = []
        if explicit:
            candidates.append(Path(explicit))
        from .config import settings

        if settings().inventory_path:
            candidates.append(Path(settings().inventory_path))
        cwd = Path.cwd()
        for name in ("vulnometry.yaml", "vulnometry.yml", "vulnometry.json", ".vulnometry.yaml"):
            candidates.append(cwd / name)
        for candidate in candidates:
            if candidate and candidate.exists():
                return cls.load(candidate)
        return cls()


    def by_name(self, name: str) -> AssetProfile | None:
        target = (name or "").lower()
        for asset in self.assets:
            if asset.name.lower() == target:
                return asset
        for asset in self.assets:
            if asset.matches_host(name):
                return asset
        return None

    def for_component(self, *candidates: str) -> list[AssetProfile]:
        """Every asset that runs one of these components."""
        return [a for a in self.assets if a.matches_component(*candidates)]

    def resolve(
        self,
        asset_name: str = "",
        host: str = "",
        component: str = "",
        override: AssetProfile | None = None,
    ) -> AssetProfile:
        """Best available profile for a finding."""
        if override is not None:
            return override
        for key in (asset_name, host):
            if key:
                found = self.by_name(key)
                if found:
                    return found
        if component:
            matches = self.for_component(component)
            if matches:
                return sorted(matches, key=lambda a: (a.tier or 9))[0]
        return UNKNOWN_ASSET


    @property
    def coverage(self) -> dict:
        tiers: dict[str, int] = {}
        for asset in self.assets:
            tiers[asset.tier_label] = tiers.get(asset.tier_label, 0) + 1
        return {
            "assets": len(self.assets),
            "by_tier": tiers,
            "internet_exposed": sum(1 for a in self.assets if a.internet_exposed),
            "regulated": sum(1 for a in self.assets if a.regulated),
            "with_owner": sum(1 for a in self.assets if a.owner),
            "source": self.source_path or "(none loaded)",
        }

    def to_dict(self) -> dict:
        return {
            "organisation": self.organisation,
            "assets": [a.to_dict() for a in self.assets],
            "coverage": self.coverage,
        }


TEMPLATE = """\
# Vulnometry inventory: what you run, and what it is worth.
#
# Only 'name' is required. Everything else sharpens the measurement.
# Leave a field out rather than guessing: Vulnometry treats "unknown" as
# uncertainty, which is safer than a confident wrong answer.

organisation: Example Corp
default_owner: platform-security@example.com

assets:
  - name: checkout-api
    tier: 1                        # 1 mission-critical, 2 business-important, 3 supporting
    owner: payments-team@example.com
    business_unit: Commerce
    environment: production
    internet_exposed: true
    data_classification: restricted    # public | internal | confidential | restricted
    regimes: [pci-dss, gdpr]
    components:                    # globs; matched against package and CPE names
      - "org.apache.logging.log4j*"
      - "spring-*"
    hosts:
      - "checkout-*.prod.example.com"

  - name: internal-wiki
    tier: 3
    owner: it-ops@example.com
    business_unit: Corporate
    environment: production
    internet_exposed: false
    data_classification: internal
    compensating_controls:
      - "VPN-only access"
      - "WAF virtual patching"

  - name: ml-sandbox
    tier: 3
    environment: development
    internet_exposed: false
    deployed: false                # not actually running; exposure collapses to zero
    data_classification: public
"""
