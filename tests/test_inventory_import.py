"""Building an inventory from an arbitrary asset export via a mapping file."""

import pytest

from vulnometry.inventory import AssetProfile, Inventory
from vulnometry.inventory_import import (
    MappingError,
    assets_from_table,
    build_inventory,
    dump_inventory_yaml,
    load_mapping,
    merge_assets,
)

MAPPING = {
    "columns": {
        "name": ["App", "Application"],
        "tier": "Rating",
        "owner": "Custodian",
        "data_classification": "Classification",
        "regimes": "Compliance",
        "aliases": ["Snyk Project", "Code Name"],
        "hosts": "Endpoints",
        "internet_exposed": ["Public", "Customer Facing"],
    },
    "values": {
        "tier": {"gold": 1, "silver": 2, "bronze": 3},
        "data_classification": {"secret": "restricted", "house": "internal"},
        "regimes": {"pci": "pci-dss", "j-sox": "sox"},
    },
    "transforms": {
        "aliases": "split_lines",
        "regimes": "split_delimited",
        "hosts": "extract_hosts",
        "internet_exposed": "any_affirmative",
    },
}

HEADER = "App,Rating,Custodian,Classification,Compliance,Snyk Project,Code Name,Endpoints,Public,Customer Facing"


def _write(tmp_path, *rows, header=HEADER, name="assets.csv", encoding="utf-8"):
    path = tmp_path / name
    path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding=encoding)
    return path


def test_basic_field_and_value_mapping(tmp_path):
    path = _write(
        tmp_path,
        'checkout,Gold,pay@x.com,secret,"pci;j-sox;pii",,,,yes,no',
        'wiki,silver,it@x.com,house,,,,,"",no',
    )
    assets, warnings = assets_from_table(path, MAPPING)
    by_name = {a.name: a for a in assets}

    checkout = by_name["checkout"]
    assert checkout.tier == 1
    assert checkout.owner == "pay@x.com"
    assert checkout.data_classification == "restricted"
    assert checkout.regimes == ["pci-dss", "sox", "pii"]  # translated + unmapped passthrough
    assert checkout.regulated
    assert checkout.internet_exposed is True

    wiki = by_name["wiki"]
    assert wiki.tier == 2
    assert wiki.data_classification == "internal"
    assert wiki.internet_exposed is False
    assert not warnings


def test_generic_criticality_words_need_no_table(tmp_path):
    mapping = {"columns": {"name": "App", "tier": "Rating"}}
    path = _write(tmp_path, "a,Critical,,,,,,,,", "b,high,,,,,,,,", "c,2,,,,,,,,")
    assets, _ = assets_from_table(path, mapping)
    assert [a.tier for a in assets] == [1, 2, 2]


def test_unrecognised_tier_and_classification_warn_and_unset(tmp_path):
    path = _write(tmp_path, "a,platinum,,frobnicated,,,,,,")
    assets, warnings = assets_from_table(path, MAPPING)
    assert assets[0].tier is None
    assert assets[0].data_classification == ""
    assert any("platinum" in w for w in warnings)
    assert any("frobnicated" in w for w in warnings)


def test_aliases_split_and_resolve(tmp_path):
    path = _write(
        tmp_path,
        'acct,Bronze,,,,"acct_ci:AOWeb/packages.config\nacct_ci:AO.Tests/packages.config",AONXT,,,',
    )
    assets, _ = assets_from_table(path, MAPPING)
    asset = assets[0]
    assert asset.aliases == [
        "acct_ci:AOWeb/packages.config",
        "acct_ci:AO.Tests/packages.config",
        "AONXT",
    ]

    inventory = Inventory(assets=assets)
    assert inventory.by_name("acct_ci:AOWeb/packages.config") is asset
    assert inventory.by_name("AONXT") is asset
    assert inventory.by_name("nope") is None


def test_alias_globs_match(tmp_path):
    inventory = Inventory(assets=[AssetProfile(name="api", aliases=["myorg/*:package.json"])])
    assert inventory.by_name("myorg/api-gateway:package.json").name == "api"
    assert inventory.by_name("other/api:package.json") is None


def test_host_extraction_from_urls(tmp_path):
    path = _write(
        tmp_path,
        'app,Bronze,,,,,,"PROD https://app.example.com/x | SIT http://app.sit.example.com:8443/",no,no',
    )
    assets, _ = assets_from_table(path, MAPPING)
    assert assets[0].hosts == ["app.example.com", "app.sit.example.com"]
    assert assets[0].internet_exposed is False


def test_mapped_tristate_only_translates_known_values(tmp_path):
    mapping = {
        "columns": {"name": "App", "deployed": "Status"},
        "values": {"deployed": {"retired": "false", "live": "true"}},
        "transforms": {"deployed": "mapped"},
    }
    path = _write(
        tmp_path, "a,Retired", "b,Live", "c,Planned", "d,",
        header="App,Status",
    )
    assets = {a.name: a for a in assets_from_table(path, mapping)[0]}
    assert assets["a"].deployed is False
    assert assets["b"].deployed is True
    assert assets["c"].deployed is None   # not in the value table -> no signal
    assert assets["d"].deployed is None


def test_tristate_all_blank_is_none(tmp_path):
    path = _write(tmp_path, "app,Bronze,,,,,,,,")
    assets, _ = assets_from_table(path, MAPPING)
    assert assets[0].internet_exposed is None


def test_rows_without_a_name_are_skipped(tmp_path):
    path = _write(tmp_path, ",Gold,x,,,,,,,", "real,Gold,x,,,,,,,")
    assets, _ = assets_from_table(path, MAPPING)
    assert [a.name for a in assets] == ["real"]


def test_duplicate_names_keep_first(tmp_path):
    path = _write(tmp_path, "dup,Gold,,,,,,,,", "dup,Bronze,,,,,,,,")
    assets, warnings = assets_from_table(path, MAPPING)
    assert len(assets) == 1 and assets[0].tier == 1
    assert any("duplicate" in w for w in warnings)


def test_windows_1252_export_decodes(tmp_path):
    path = tmp_path / "cp.csv"
    # U+2019 (right single quote) is byte 0x92 in cp1252 and invalid as utf-8
    path.write_bytes((HEADER + "\napp’s,Gold,,,,,,,yes,no\n").encode("cp1252"))
    assets, _ = assets_from_table(path, MAPPING)
    assert assets[0].name.startswith("app") and assets[0].tier == 1


@pytest.mark.parametrize("bad", [
    {"values": {}},                                  # no columns section
    {"columns": {"name": "A", "bogus_field": "B"}},   # unknown field
    {"columns": {"tier": "Rating"}},                  # no name column
])
def test_mapping_validation(tmp_path, bad):
    import json

    path = tmp_path / "map.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(MappingError):
        load_mapping(path)


def test_merge_preserves_hand_added_fields(tmp_path):
    existing = Inventory(assets=[
        AssetProfile(
            name="checkout", tier=3, owner="old@x.com",
            compensating_controls=["WAF virtual patch"], deployed=False,
        )
    ])
    incoming = [AssetProfile(name="checkout", tier=1, owner="pay@x.com")]
    merged, report = merge_assets(existing, incoming, authoritative={"name", "tier", "owner"})

    asset = merged.assets[0]
    assert asset.tier == 1                       # refreshed from the export
    assert asset.owner == "pay@x.com"
    assert asset.compensating_controls == ["WAF virtual patch"]  # kept: not in the export
    assert asset.deployed is False              # kept
    assert ("checkout", ["owner", "tier"]) in [(n, sorted(d)) for n, d in report["changed"]]


def test_merge_keeps_assets_absent_from_export(tmp_path):
    existing = Inventory(assets=[AssetProfile(name="a", tier=1), AssetProfile(name="b", tier=2)])
    merged, report = merge_assets(existing, [AssetProfile(name="a", tier=1)], authoritative={"name", "tier"})
    assert {a.name for a in merged.assets} == {"a", "b"}
    assert report["untouched_by_export"] == ["b"]


def test_build_inventory_and_yaml_roundtrip(tmp_path):
    mapping_path = tmp_path / "map.yaml"
    import yaml

    mapping_path.write_text(yaml.safe_dump(MAPPING))
    path = _write(tmp_path, 'checkout,Gold,pay@x.com,secret,pci,"acct_ci:web",AONXT,https://x.example.com,yes,no')

    inventory = build_inventory(path, mapping_path)
    assert inventory.assets[0].tier == 1

    text = dump_inventory_yaml(inventory)
    reloaded = Inventory.load(_dump(tmp_path, text))
    asset = reloaded.by_name("checkout")
    assert asset.tier == 1
    assert asset.aliases == ["acct_ci:web", "AONXT"]
    assert asset.regimes == ["pci-dss"]
    assert reloaded.by_name("AONXT") is asset


def _dump(tmp_path, text):
    path = tmp_path / "vulnometry.yaml"
    path.write_text(text)
    return path
