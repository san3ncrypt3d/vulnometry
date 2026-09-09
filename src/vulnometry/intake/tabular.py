"""Spreadsheet and CSV intake with header detection."""

from __future__ import annotations

import csv
import re
from pathlib import Path

from ..schema import harvest_cve_ids

COLUMN_ALIASES = {
    "cve": [
        "cve", "cveid", "cves", "cvenumber", "vulnerabilityid", "vulnid",
        "vulnerabilitycve", "cvss3cve", "id", "identifier", "findingid",
    ],
    "asset": [
        "asset", "assetname", "service", "servicename", "application",
        "applicationname", "project", "repository", "repo", "system", "component",
    ],
    "host": [
        "host", "hostname", "ip", "ipaddress", "target", "fqdn", "netbiosname",
        "dnsname", "machine", "instance", "server",
    ],
    "component": [
        "package", "packagename", "library", "artifact", "product",
        "installedpackage", "componentname", "pkgname", "dependency",
    ],
    "version": [
        "version", "installedversion", "packageversion", "currentversion", "pkgversion",
    ],
    "raw_severity": [
        "severity", "risk", "riskfactor", "criticality", "priority", "rating", "cvssseverity",
    ],
    "owner": ["owner", "assignee", "team", "responsible", "contact", "custodian"],
    "business_unit": ["businessunit", "bu", "department", "division", "org", "group"],
    "environment": ["environment", "env", "stage", "tier", "lifecycle"],
}

_MAX_SCAN_ROWS = 25


def _normalise(header) -> str:
    return re.sub(r"[^a-z0-9]", "", str(header or "").lower())


def _map_columns(headers: list) -> dict[str, int]:
    mapping: dict[str, int] = {}
    normalised = [_normalise(h) for h in headers]

    for field, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalised:
                index = normalised.index(alias)
                if index not in mapping.values():
                    mapping[field] = index
                    break
        if field in mapping:
            continue
        for alias in sorted(aliases, key=len, reverse=True):
            for index, header in enumerate(normalised):
                if len(alias) >= 4 and alias in header and index not in mapping.values():
                    mapping[field] = index
                    break
            if field in mapping:
                break
    return mapping


def _find_header_row(rows: list[list]) -> int:
    """The header is the first row that maps to a CVE column, or row 0."""
    for index, row in enumerate(rows[:_MAX_SCAN_ROWS]):
        if not row:
            continue
        mapping = _map_columns(list(row))
        if "cve" in mapping:
            return index
        if len(mapping) >= 3:
            return index
    return 0


def _cell(row: list, index: int | None) -> str:
    if index is None or index >= len(row):
        return ""
    value = row[index]
    return "" if value is None else str(value).strip()


def _read_text_any(path: Path) -> str:
    """Best-effort decode. Exports come out of Windows tooling as often as not."""
    for encoding in ("utf-8-sig", "cp1252", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def _rows_from_csv(path: Path) -> list[list]:
    import io

    text = _read_text_any(path)
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    if path.suffix.lower() == ".csv":
        try:
            delimiter = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|").delimiter
        except csv.Error:
            delimiter = ","
    return list(csv.reader(io.StringIO(text), delimiter=delimiter))


def read_table(path: str | Path, sheet: str = "") -> tuple[list[list], str]:
    """Raw rows from a CSV/TSV/Excel file, plus the sheet name ('' for CSV/TSV)."""
    path = Path(path)
    if path.suffix.lower() in (".csv", ".tsv"):
        return _rows_from_csv(path), ""
    return _rows_from_excel(path, sheet)


def find_header_row(rows: list[list]) -> int:
    """Index of the row that looks like a header (public wrapper)."""
    return _find_header_row(rows)


def normalise_header(value) -> str:
    """Lowercase, strip non-alphanumerics: the key headers are matched on."""
    return _normalise(value)


def _rows_from_excel(path: Path, sheet: str = "") -> tuple[list[list], str]:
    from openpyxl import load_workbook

    workbook = load_workbook(path, read_only=True, data_only=True)
    try:
        if sheet:
            if sheet not in workbook.sheetnames:
                raise ValueError(f"sheet {sheet!r} not found; available: {', '.join(workbook.sheetnames)}")
            worksheet = workbook[sheet]
        else:
            worksheet = workbook[workbook.sheetnames[0]]
            for name in workbook.sheetnames:
                candidate = workbook[name]
                probe = []
                for index, row in enumerate(candidate.iter_rows(values_only=True)):
                    probe.append(row)
                    if index > 40:
                        break
                if harvest_cve_ids(" ".join(str(c) for r in probe for c in r if c)):
                    worksheet = candidate
                    break
        rows = [list(row) for row in worksheet.iter_rows(values_only=True)]
        return rows, worksheet.title
    finally:
        workbook.close()


def preview_columns(path: str | Path, sheet: str = "") -> dict:
    """What the column detector found. Run this before a big import."""
    path = Path(path)
    if path.suffix.lower() in (".csv", ".tsv"):
        rows, sheet_name = _rows_from_csv(path), ""
    else:
        rows, sheet_name = _rows_from_excel(path, sheet)
    if not rows:
        return {"error": "file contains no rows"}

    header_index = _find_header_row(rows)
    headers = list(rows[header_index])
    mapping = _map_columns(headers)

    return {
        "sheet": sheet_name,
        "header_row": header_index + 1,
        "total_rows": len(rows),
        "headers": [str(h) for h in headers],
        "detected": {field: str(headers[i]) for field, i in sorted(mapping.items(), key=lambda kv: kv[1])},
        "unmapped": [str(h) for i, h in enumerate(headers) if i not in mapping.values() and h],
        "cve_column_found": "cve" in mapping,
    }


def parse_tabular(path: str | Path, sheet: str = "") -> tuple[list[dict], str]:
    path = Path(path)
    if path.suffix.lower() in (".csv", ".tsv"):
        rows, sheet_name = _rows_from_csv(path), ""
        label = f"{path.suffix.lstrip('.').upper()} export"
    else:
        rows, sheet_name = _rows_from_excel(path, sheet)
        label = f"Excel export (sheet '{sheet_name}')"

    if not rows:
        return [], label

    header_index = _find_header_row(rows)
    headers = list(rows[header_index])
    mapping = _map_columns(headers)
    body = rows[header_index + 1 :]

    findings: list[dict] = []
    for row in body:
        if not row or not any(row):
            continue
        row = list(row)

        if "cve" in mapping:
            raw = _cell(row, mapping["cve"])
            cve_ids = harvest_cve_ids(raw)
        else:
            cve_ids = harvest_cve_ids(" ".join(str(c) for c in row if c is not None))

        if not cve_ids:
            continue

        base = {
            "asset": _cell(row, mapping.get("asset")),
            "host": _cell(row, mapping.get("host")),
            "component": _cell(row, mapping.get("component")),
            "version": _cell(row, mapping.get("version")),
            "raw_severity": _cell(row, mapping.get("raw_severity")),
            "owner": _cell(row, mapping.get("owner")),
            "business_unit": _cell(row, mapping.get("business_unit")),
            "environment": _cell(row, mapping.get("environment")),
            "source": path.name,
        }
        for cve in cve_ids:
            findings.append({**base, "cve": cve})

    return findings, label
