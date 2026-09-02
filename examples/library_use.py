"""Vulnometry as a library. No model, no CLI, fully deterministic.

This is the path to use in CI or a scheduled job.
"""

import asyncio

from vulnometry import assess_finding, assess_portfolio
from vulnometry.assessment import portfolio_summary
from vulnometry.inventory import AssetProfile, Inventory


async def main() -> None:
    inventory = Inventory.load("vulnometry.yaml")

    result = await assess_finding(
        "CVE-2021-44228", inventory=inventory, asset_name="checkout-api", lens="full"
    )
    print(result.one_line())
    print("  ", result.directive)
    print("   due", result.due_by, f"({result.sla_days}d SLA), owner {result.owner}")
    print("   threat", result.exposure.threat,
          "reach", result.exposure.reachability,
          "consequence", result.exposure.consequence)
    print()

    everywhere = await assess_portfolio(
        [{"cve": "CVE-2021-44228", "asset": a.name} for a in inventory.assets],
        inventory=inventory, lens="signal",
    )
    for item in everywhere:
        print(f"  {item.asset:<20} {item.exposure.index:>6.1f}  {item.exposure.verdict}")
    print()

    ad_hoc = await assess_finding(
        "CVE-2021-44228",
        asset=AssetProfile(name="acquired-co-gateway", tier=1, internet_exposed=True,
                           deployed=True, data_classification="restricted", regimes=["pci-dss"]),
    )
    print(ad_hoc.one_line())

    summary = portfolio_summary(everywhere)
    print("\nsuppressed by context:", summary["suppressed_by_context"],
          f"({summary['not_deployed']} not deployed, {summary['unreachable_here']} unreachable here)")


if __name__ == "__main__":
    asyncio.run(main())
