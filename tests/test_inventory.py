from vulnometry.inventory import TEMPLATE, AssetProfile, Inventory


def test_template_parses(tmp_path):
    path = tmp_path / "vulnometry.yaml"
    path.write_text(TEMPLATE)
    inventory = Inventory.load(path)
    assert len(inventory.assets) == 3
    checkout = inventory.by_name("checkout-api")
    assert checkout.tier == 1
    assert checkout.internet_exposed is True
    assert "pci-dss" in checkout.regimes
    assert checkout.regulated


def test_friendly_aliases_are_accepted():
    inventory = Inventory.from_dict({"assets": [
        {"name": "api", "criticality": 1, "team": "sre@x.com", "packages": ["log4j*"]}
    ]})
    asset = inventory.assets[0]
    assert asset.tier == 1
    assert asset.owner == "sre@x.com"
    assert asset.components == ["log4j*"]


def test_host_and_component_globs():
    asset = AssetProfile(name="api", hosts=["web-*.prod.example.com"],
                         components=["org.apache.logging.log4j*"])
    assert asset.matches_host("web-03.prod.example.com")
    assert not asset.matches_host("db-01.prod.example.com")
    assert asset.matches_component("org.apache.logging.log4j:log4j-core")
    assert not asset.matches_component("requests")


def test_resolution_precedence():
    inventory = Inventory.from_dict({"assets": [
        {"name": "api", "tier": 1, "hosts": ["web-*"]},
        {"name": "batch", "tier": 3, "components": ["log4j*"]},
        {"name": "gateway", "tier": 1, "components": ["log4j*"]},
    ]})
    assert inventory.resolve(asset_name="api").name == "api"
    assert inventory.resolve(host="web-07").name == "api"
    assert inventory.resolve(component="log4j-core").name == "gateway"
    assert inventory.resolve().name == "(unspecified)"


def test_sla_shortens_for_tier_and_regulation():
    tier3 = AssetProfile(name="lab", tier=3)
    tier1_regulated = AssetProfile(name="pay", tier=1, regimes=["pci-dss"], environment="production")
    assert tier1_regulated.sla_days("Contain") < tier3.sla_days("Contain")
    assert tier3.sla_days("Accept") == 0
    assert tier1_regulated.due_date("Contain")


def test_unknown_tier_sits_between_known_values():
    assert AssetProfile(tier=3).tier_weight < AssetProfile().tier_weight < AssetProfile(tier=1).tier_weight
