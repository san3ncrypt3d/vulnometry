"""Turn scanner exports, native JSON and manifests into findings."""

from __future__ import annotations

import json
from pathlib import Path

from .manifests import parse_manifest
from .scanners import parse_scanner_json, sniff_scanner
from .tabular import parse_tabular, preview_columns

__all__ = [
    "load_findings",
    "parse_tabular",
    "preview_columns",
    "parse_scanner_json",
    "sniff_scanner",
    "parse_manifest",
    "describe",
]

TABULAR_SUFFIXES = {".xlsx", ".xlsm", ".xls", ".csv", ".tsv"}
MANIFEST_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "go.mod", "go.sum",
    "Gemfile.lock", "Cargo.lock", "pom.xml", "poetry.lock",
}


def load_findings(path: str | Path, sheet: str = "") -> tuple[list[dict], str]:
    """Read any supported file. Returns (findings, description_of_format)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    suffix = path.suffix.lower()

    if suffix in TABULAR_SUFFIXES:
        return parse_tabular(path, sheet=sheet)

    if path.name in MANIFEST_NAMES or path.name.startswith("requirements"):
        components, label = parse_manifest(path)
        return components, f"dependency manifest ({label})"

    if suffix == ".json":
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path} is not valid JSON: {exc}") from exc
        flavour = sniff_scanner(data)
        if flavour:
            return parse_scanner_json(data, flavour), f"{flavour} report"
        components, label = parse_manifest(path)
        if components:
            return components, f"dependency manifest ({label})"
        from ..schema import harvest_cve_ids

        return [{"cve": c, "source": "json"} for c in harvest_cve_ids(text)], "generic JSON (CVE ids only)"

    from ..schema import harvest_cve_ids

    text = path.read_text(encoding="utf-8", errors="replace")
    return [{"cve": c, "source": "text"} for c in harvest_cve_ids(text)], "plain text (CVE ids only)"


def describe(path: str | Path) -> str:
    path = Path(path)
    if path.name in MANIFEST_NAMES or path.name.startswith("requirements"):
        return "manifest"
    if path.suffix.lower() in TABULAR_SUFFIXES:
        return "tabular"
    return "findings"
