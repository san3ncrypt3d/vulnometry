"""Build an Inventory from an arbitrary asset export (CSV/XLSX) via a mapping file.

The exports organisations already keep (a CMDB extract, an application register, a
spreadsheet a security team maintains by hand) never use vulnometry's field names.
A mapping file says which column feeds which field, and how to translate the values:

    columns:
      name: Application Name
      tier: Criticality
      data_classification: Information Classification
      aliases: [Scanner Project, Also Known As]
      hosts: URL
      internet_exposed: [Internet Facing, Customer Facing]
    values:
      tier: {critical: 1, high: 2, moderate: 3, low: 3}
      data_classification: {secret: restricted, "internal use only": internal}
    transforms:
      aliases: split_lines
      hosts: extract_hosts
      internet_exposed: any_affirmative

Nothing here is specific to any one organisation: the column names and the value
tables all live in the mapping file the caller supplies.
"""

from __future__ import annotations

import json
import re
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from pathlib import Path

from .intake.tabular import find_header_row, normalise_header, read_table
from .inventory import AssetProfile, Inventory

# --- field groups -----------------------------------------------------------

LIST_FIELDS = {"regimes", "compensating_controls", "components", "hosts", "aliases"}
TRISTATE_FIELDS = {"internet_exposed", "deployed"}
_ASSET_FIELDS = {f.name for f in dataclass_fields(AssetProfile)}
VALID_DATA_CLASS = {"public", "internal", "confidential", "restricted"}

DEFAULT_TRUE = {"yes", "y", "true", "t", "1", "external", "public", "internet"}
DEFAULT_FALSE = {"no", "n", "false", "f", "0", "internal", "none", "n/a", "na", ""}

# a small set of universally-recognised criticality words, so a mapping file that
# only lists exotic values still gets the common ones for free
_TIER_WORDS = {
    "1": 1, "2": 2, "3": 3,
    "critical": 1, "very high": 1, "highest": 1,
    "high": 2, "important": 2,
    "medium": 3, "moderate": 3, "low": 3, "minor": 3, "normal": 3,
}

_URL_HOST = re.compile(r"https?://([A-Za-z0-9._-]+)", re.IGNORECASE)
_BARE_FQDN = re.compile(r"\b([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+){1,})\b")


# --- transforms -----------------------------------------------------------

def _split_lines(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[\r\n]+", value or "") if part.strip()]


def _split_delimited(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[;,/|\r\n]+", value or "") if part.strip()]


def _split_comma(value: str) -> list[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _extract_hosts(value: str) -> list[str]:
    if not value:
        return []
    found = _URL_HOST.findall(value)
    if not found:
        found = [m for m in _BARE_FQDN.findall(value) if "." in m]
    out: list[str] = []
    for host in found:
        host = host.strip().strip("/").lower()
        if host and host not in out:
            out.append(host)
    return out


LIST_TRANSFORMS = {
    "split_lines": _split_lines,
    "split_delimited": _split_delimited,
    "split_comma": _split_comma,
    "extract_hosts": _extract_hosts,
}

# transforms legal on a tri-state field; the resolver reads every source column
TRISTATE_TRANSFORMS = {"any_affirmative", "all_affirmative", "first", "mapped"}


# --- mapping file -------------------------------------------------------------

class MappingError(ValueError):
    """The mapping file is missing something or points at columns that do not exist."""


def load_mapping(path: str | Path) -> dict:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise MappingError("PyYAML is required to read a YAML mapping file") from exc
        data = yaml.safe_load(text) or {}
    if not isinstance(data, dict) or not isinstance(data.get("columns"), dict):
        raise MappingError(f"{path}: mapping file needs a top-level 'columns:' section")
    unknown = set(data["columns"]) - _ASSET_FIELDS
    if unknown:
        raise MappingError(
            f"{path}: columns map to fields that do not exist on an asset: {', '.join(sorted(unknown))}"
        )
    if "name" not in data["columns"]:
        raise MappingError(f"{path}: 'columns.name' is required")
    return data


# --- value coercion --------------------------------------------------------

def _lower_keys(table: dict | None) -> dict:
    return {str(k).strip().lower(): v for k, v in (table or {}).items()}


def _coerce_tier(raw: str, table: dict, name: str, warnings: list[str]) -> int | None:
    if not raw:
        return None
    key = raw.strip().lower()
    value = table.get(key, _TIER_WORDS.get(key, raw))
    try:
        tier = int(value)
    except (TypeError, ValueError):
        warnings.append(f"{name}: criticality {raw!r} did not map to a tier 1-3, left unset")
        return None
    if tier not in (1, 2, 3):
        warnings.append(f"{name}: tier {tier} is outside 1-3, left unset")
        return None
    return tier


def _coerce_data_class(raw: str, table: dict, name: str, warnings: list[str]) -> str:
    if not raw:
        return ""
    value = str(table.get(raw.strip().lower(), raw)).strip().lower()
    if value in VALID_DATA_CLASS:
        return value
    warnings.append(
        f"{name}: data classification {raw!r} is not one of {sorted(VALID_DATA_CLASS)}, left unset"
    )
    return ""


_TRUE_WORDS = {"true", "1", "yes"}
_FALSE_WORDS = {"false", "0", "no"}


def _tristate(
    cells: list[str],
    transform: str,
    true_set: set[str],
    false_set: set[str],
    value_map: dict | None = None,
) -> bool | None:
    """Blank cells carry no signal. An unrecognised non-blank value counts as affirmative."""
    signal = [(c or "").strip().lower() for c in cells]
    signal = [token for token in signal if token]
    if not signal:
        return None

    if transform == "mapped":
        # only values that translate to true/false via 'values.<field>' count; else no signal
        result: bool | None = None
        for token in signal:
            mapped = str((value_map or {}).get(token, "")).strip().lower()
            if mapped in _TRUE_WORDS:
                return True
            if mapped in _FALSE_WORDS:
                result = False
        return result

    if transform == "all_affirmative":
        return all(token not in false_set for token in signal)
    if transform == "first":
        if signal[0] in true_set:
            return True
        if signal[0] in false_set:
            return False
        return None

    # any_affirmative (default): true wins, then explicit false, else unknown
    seen_true = seen_false = False
    for token in signal:
        if token in false_set:
            seen_false = True
        else:
            seen_true = True
    if seen_true:
        return True
    return False if seen_false else None


# tokens that mean "nothing recorded" and should not become list entries
_NULLISH = {"", "none", "n/a", "na", "not applicable", "not assigned", "unknown", "tbd", "-"}


def _translate_list(items: list[str], table: dict, keep_unmapped_lowercased: bool) -> list[str]:
    out: list[str] = []
    for item in items:
        key = item.strip().lower()
        if key in _NULLISH:
            continue
        mapped = table.get(key)
        if mapped is not None:
            out.append(str(mapped))
        elif keep_unmapped_lowercased:
            out.append(key)
        else:
            out.append(item.strip())
    return list(dict.fromkeys(v for v in out if v and v.lower() not in _NULLISH))


# --- the parse -------------------------------------------------------------

def assets_from_table(
    path: str | Path, mapping: dict, sheet: str = ""
) -> tuple[list[AssetProfile], list[str]]:
    """Parse an export into AssetProfiles. Returns (assets, warnings)."""
    columns: dict = mapping["columns"]
    values = {field: _lower_keys(table) for field, table in (mapping.get("values") or {}).items()}
    transforms: dict = mapping.get("transforms") or {}
    booleans = mapping.get("booleans") or {}
    true_set = {str(s).strip().lower() for s in booleans.get("true", [])} or DEFAULT_TRUE
    false_set = {str(s).strip().lower() for s in booleans.get("false", [])} or DEFAULT_FALSE

    rows, _ = read_table(path, sheet or mapping.get("sheet", ""))
    warnings: list[str] = []
    if not rows:
        return [], [f"{path}: no rows"]

    header_index = find_header_row(rows)
    headers = [str(h or "").strip() for h in rows[header_index]]
    lookup: dict[str, int] = {}
    for index, header in enumerate(headers):
        lookup.setdefault(normalise_header(header), index)

    resolved: dict[str, list[int]] = {}
    for field, spec in columns.items():
        names = [n for n in (spec if isinstance(spec, list) else [spec]) if n]
        indices: list[int] = []
        for candidate in names:
            index = lookup.get(normalise_header(candidate))
            if index is not None and index not in indices:
                indices.append(index)
        if indices:
            resolved[field] = indices
        elif names:
            warnings.append(
                f"field {field!r}: none of its columns {names} were found in the header row"
            )
    if "name" not in resolved:
        raise MappingError("none of the configured name columns were found in the file")

    def cell(row: list, index: int) -> str:
        raw = row[index] if index < len(row) else None
        return "" if raw is None else str(raw).strip()

    assets: list[AssetProfile] = []
    seen: set[str] = set()
    for row in rows[header_index + 1 :]:
        if not row or not any(c not in (None, "") for c in row):
            continue

        name = next((cell(row, i) for i in resolved["name"] if cell(row, i)), "")
        if not name:
            continue
        if name.lower() in seen:
            warnings.append(f"duplicate asset {name!r}: keeping the first row only")
            continue
        seen.add(name.lower())

        record: dict = {"name": name}
        for field, indices in resolved.items():
            if field == "name":
                continue
            cells = [cell(row, i) for i in indices]
            if field in TRISTATE_FIELDS:
                transform = transforms.get(field, "any_affirmative")
                record[field] = _tristate(
                    cells, transform, true_set, false_set, values.get(field, {})
                )
                continue
            if field in LIST_FIELDS:
                joined = "\n".join(c for c in cells if c)
                default = "split_delimited" if field == "regimes" else "split_lines"
                splitter = LIST_TRANSFORMS.get(transforms.get(field, default), _split_lines)
                items = splitter(joined)
                record[field] = _translate_list(
                    items, values.get(field, {}), keep_unmapped_lowercased=(field == "regimes")
                )
                continue

            value = next((c for c in cells if c), "")
            named = transforms.get(field)
            if named in LIST_TRANSFORMS:
                pieces = LIST_TRANSFORMS[named](value)
                value = pieces[0] if pieces else ""
            if field == "tier":
                record[field] = _coerce_tier(value, values.get("tier", {}), name, warnings)
            elif field == "data_classification":
                record[field] = _coerce_data_class(value, values.get(field, {}), name, warnings)
            else:
                table = values.get(field, {})
                record[field] = str(table.get(value.strip().lower(), value)) if table else value

        assets.append(AssetProfile(**{k: v for k, v in record.items() if k in _ASSET_FIELDS}))

    return assets, warnings


# --- merge & write -------------------------------------------------------------

def merge_assets(
    existing: Inventory, incoming: list[AssetProfile], authoritative: set[str]
) -> tuple[Inventory, dict]:
    """Refresh the fields the export owns; keep everything a human added by hand."""
    by_name = {a.name.lower(): a for a in existing.assets}
    incoming_names = {a.name.lower() for a in incoming}
    added: list[str] = []
    changed: list[tuple[str, list[str]]] = []
    result: list[AssetProfile] = []

    for asset in incoming:
        old = by_name.get(asset.name.lower())
        if old is None:
            added.append(asset.name)
            result.append(asset)
            continue
        merged = replace(old)
        diffs: list[str] = []
        for field in authoritative:
            if field == "name":
                continue
            new_value = getattr(asset, field)
            if new_value in (None, "", [], {}):
                continue  # the export said nothing about this field; keep what we had
            if getattr(merged, field) != new_value:
                diffs.append(field)
                setattr(merged, field, new_value)
        if diffs:
            changed.append((asset.name, diffs))
        result.append(merged)

    kept = [by_name[n] for n in by_name if n not in incoming_names]
    result.extend(kept)
    inventory = Inventory(
        assets=result,
        organisation=existing.organisation,
        default_owner=existing.default_owner,
    )
    report = {
        "added": added,
        "changed": changed,
        "untouched_by_export": [a.name for a in kept],
    }
    return inventory, report


_FIELD_ORDER = [f.name for f in dataclass_fields(AssetProfile)]


def _asset_doc(asset: AssetProfile) -> dict:
    doc: dict = {}
    for field in _FIELD_ORDER:
        value = getattr(asset, field)
        if value in (None, "", [], {}):
            continue
        doc[field] = value
    return doc


def dump_inventory_yaml(inventory: Inventory) -> str:
    import yaml

    doc: dict = {}
    if inventory.organisation:
        doc["organisation"] = inventory.organisation
    if inventory.default_owner:
        doc["default_owner"] = inventory.default_owner
    doc["assets"] = [_asset_doc(a) for a in inventory.assets]

    header = (
        "# Generated by `vulnometry inventory import`.\n"
        "# Safe to hand-edit. Re-running import merges: columns named in the mapping file\n"
        "# are refreshed from the export, every other field you set here is preserved.\n\n"
    )
    return header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100)


# --- top level -------------------------------------------------------------

def build_inventory(export_path: str | Path, mapping_path: str | Path, sheet: str = "") -> Inventory:
    """Load an export straight into an Inventory (no YAML on disk)."""
    mapping = load_mapping(mapping_path)
    assets, _ = assets_from_table(export_path, mapping, sheet=sheet)
    return Inventory(assets=assets, source_path=str(export_path))
