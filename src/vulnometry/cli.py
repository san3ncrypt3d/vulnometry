"""Command line interface."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .assessment import assess_portfolio, portfolio_summary
from .config import settings
from .inventory import TEMPLATE, AssetProfile, Inventory
from .report import build_dashboard, build_workbook, render_one, render_table, to_csv, to_json, to_markdown
from .schema import harvest_cve_ids

OUT = Console()
ERR = Console(stderr=True)


def _override_asset(args) -> AssetProfile | None:
    """Asset details given on the command line, overriding the inventory."""
    def tri(yes: str, no: str):
        if getattr(args, yes, False):
            return True
        if getattr(args, no, False):
            return False
        return None

    exposed = tri("internet_exposed", "internal_only")
    deployed = False if getattr(args, "not_deployed", False) else None
    tier = getattr(args, "tier", None)
    controls = ["declared on the command line"] if getattr(args, "mitigated", False) else []
    classification = getattr(args, "data", "") or ""
    regimes = list(getattr(args, "regime", None) or [])
    environment = getattr(args, "environment", "") or ""

    if all(v in (None, False, "", []) for v in (exposed, deployed, tier, controls, classification, regimes, environment)):
        return None

    return AssetProfile(
        name=getattr(args, "asset", "") or "(command line)",
        tier=tier,
        environment=environment,
        internet_exposed=exposed,
        deployed=deployed,
        data_classification=classification,
        regimes=regimes,
        compensating_controls=controls,
    )


def _collect_ids(args) -> list[str]:
    ids: list[str] = []
    for value in getattr(args, "cve", None) or []:
        found = harvest_cve_ids(value)
        ids.extend(found or ([value.upper()] if value.upper().startswith("CVE-") else []))
    for path in getattr(args, "file", None) or []:
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8", errors="replace")
        ids.extend(harvest_cve_ids(text))
    if not ids and not sys.stdin.isatty():
        ids.extend(harvest_cve_ids(sys.stdin.read()))
    seen, unique = set(), []
    for cve in ids:
        if cve.upper() not in seen:
            seen.add(cve.upper())
            unique.append(cve.upper())
    return unique


def _emit(results, summary, args) -> None:
    written: list[str] = []

    if getattr(args, "workbook", None):
        path = build_workbook(results, args.workbook, summary)
        written.append(str(path))
    if getattr(args, "dashboard", None):
        path = build_dashboard(results, args.dashboard, summary, title=getattr(args, "title", "") or "Exposure dashboard")
        written.append(str(path))

    fmt = getattr(args, "format", "table")
    if fmt == "table":
        if len(results) == 1 and not getattr(args, "compact", False):
            render_one(results[0], OUT)
        else:
            render_table(results, OUT)
            _print_summary(summary)
    else:
        text = {"json": lambda r: to_json(r, summary), "markdown": lambda r: to_markdown(r, summary), "csv": to_csv}[fmt](results)
        if getattr(args, "output", None):
            Path(args.output).write_text(text, encoding="utf-8")
            written.append(args.output)
        else:
            print(text)

    for path in written:
        ERR.print(f"[green]Wrote[/] {path}")


def _print_summary(summary: dict) -> None:
    if not summary:
        return
    contain = summary.get("contain_now") or []
    if contain:
        OUT.print(f"\n[bold red]Contain now:[/] {', '.join(contain[:12])}")
    if summary.get("suppressed_by_context"):
        OUT.print(
            f"[dim]{summary['suppressed_by_context']} finding(s) reduced to negligible exposure "
            f"by business context.[/]"
        )
    if summary.get("unattributed"):
        OUT.print(
            f"[yellow]{summary['unattributed']} finding(s) matched no known asset[/] "
            f"and were scored pessimistically. Run [bold]vulnometry inventory init[/] to fix that."
        )


async def cmd_measure(args) -> int:
    ids = _collect_ids(args)
    if not ids:
        ERR.print("[red]No CVE identifiers found.[/] Pass them as arguments, with -f FILE, or on stdin.")
        return 2

    inventory = Inventory.discover(args.inventory)
    lens = args.lens or ("full" if len(ids) <= 5 else "signal")

    findings = [{"cve": cve, "asset": args.asset} for cve in ids] if args.asset else ids

    with ERR.status(f"Measuring {len(ids)} finding(s) at lens '{lens}'..."):
        results = await assess_portfolio(
            findings, inventory=inventory, lens=lens, asset=_override_asset(args), concurrency=args.concurrency
        )

    summary = portfolio_summary(results)
    if args.min_index:
        results = [r for r in results if r.exposure.index >= args.min_index]
    _emit(results, summary, args)

    if args.fail_on:
        floor = {"contain": 700, "remediate": 400, "schedule": 150}[args.fail_on]
        if any(r.exposure.index >= floor for r in results):
            return 1
    return 0


async def cmd_import(args) -> int:
    from .intake import describe, load_findings, preview_columns

    path = Path(args.path)
    kind = describe(path)

    if args.preview:
        if kind != "tabular":
            ERR.print("[yellow]--preview only applies to spreadsheets and CSV files.[/]")
            return 2
        info = preview_columns(path, sheet=args.sheet)
        OUT.print_json(data=info)
        if not info.get("cve_column_found"):
            ERR.print("[yellow]No CVE column detected. Vulnometry will scan whole rows for identifiers instead.[/]")
        return 0

    try:
        rows, label = load_findings(path, sheet=args.sheet)
    except (ValueError, FileNotFoundError) as exc:
        ERR.print(f"[red]{exc}[/]")
        return 2

    if kind == "manifest":
        ERR.print(f"[yellow]{path} is a dependency manifest.[/] Use [bold]vulnometry sweep[/] for those.")
        return 2

    if not rows:
        ERR.print(f"[red]No CVE identifiers found in {path}[/] ({label}).")
        ERR.print("[dim]Try `vulnometry import FILE --preview` to see which columns were detected.[/]")
        return 2

    ERR.print(f"Read [bold]{len(rows)}[/] finding(s) from {path.name}: {label}")

    inventory = Inventory.discover(args.inventory)
    if inventory.assets:
        ERR.print(f"Matching against [bold]{len(inventory.assets)}[/] known asset(s) from {inventory.source_path}")
    else:
        ERR.print("[yellow]No inventory loaded[/]. Everything will be scored with pessimistic defaults.")

    if args.limit:
        rows = rows[: args.limit]

    with ERR.status(f"Measuring {len(rows)} finding(s)..."):
        results = await assess_portfolio(
            rows, inventory=inventory, lens=args.lens, asset=_override_asset(args), concurrency=args.concurrency
        )

    summary = portfolio_summary(results)
    if args.min_index:
        results = [r for r in results if r.exposure.index >= args.min_index]

    if not args.workbook and not args.dashboard and args.format == "table":
        stem = path.with_suffix("").name
        args.workbook = args.workbook or f"{stem}-assessed.xlsx"
        args.dashboard = args.dashboard or f"{stem}-dashboard.html"

    _emit(results, summary, args)

    if args.fail_on:
        floor = {"contain": 700, "remediate": 400, "schedule": 150}[args.fail_on]
        if any(r.exposure.index >= floor for r in results):
            return 1
    return 0


async def cmd_sweep(args) -> int:
    from .feeds import advisories as adv_feed
    from .intake.manifests import parse_manifest
    from .net import FeedError

    components, label = parse_manifest(args.path)
    if not components:
        ERR.print(f"[red]Could not parse {args.path}[/] as a dependency manifest.")
        return 2
    ERR.print(f"Parsed [bold]{len(components)}[/] component(s) from {args.path} ({label})")

    try:
        with ERR.status("Querying OSV..."):
            hits = await adv_feed.osv_batch(components)
    except FeedError as exc:
        ERR.print(f"[red]Could not reach OSV:[/] {exc}")
        return 2

    if not hits:
        OUT.print("[green]No known vulnerabilities in these components.[/]")
        return 0

    findings: list[dict] = []
    table = Table(title=f"{len(hits)} vulnerable component(s)")
    table.add_column("Component")
    table.add_column("Advisories", overflow="fold")
    for label_key, ids in sorted(hits.items()):
        table.add_row(label_key, ", ".join(ids[:6]) + ("..." if len(ids) > 6 else ""))
        component_name = label_key.split("/", 1)[-1].split("@")[0]
        for identifier in ids:
            if identifier.upper().startswith("CVE-"):
                findings.append({"cve": identifier, "component": component_name})
    OUT.print(table)

    if args.no_measure or not findings:
        return 1

    OUT.print()
    inventory = Inventory.discover(args.inventory)
    with ERR.status(f"Measuring {len(findings)} finding(s) against your inventory..."):
        results = await assess_portfolio(
            findings[:250], inventory=inventory, lens=args.lens, asset=_override_asset(args)
        )
    summary = portfolio_summary(results)
    if args.min_index:
        results = [r for r in results if r.exposure.index >= args.min_index]
    _emit(results, summary, args)
    return 1


async def cmd_compare(args) -> int:
    """Run one CVE against every asset in the inventory."""
    inventory = Inventory.discover(args.inventory)
    if not inventory.assets:
        ERR.print("[red]No inventory found.[/] Run [bold]vulnometry inventory init[/] first.")
        return 2

    assets = inventory.assets[: args.limit]
    with ERR.status(f"Measuring {args.cve} across {len(assets)} asset(s)..."):
        results = await assess_portfolio(
            [{"cve": args.cve, "asset": a.name} for a in assets], inventory=inventory, lens="full"
        )

    table = Table(title=f"{args.cve.upper()}: one CVE, {len(results)} answers")
    table.add_column("Asset", style="bold")
    table.add_column("BEI", justify="right")
    table.add_column("Verdict")
    table.add_column("Threat", justify="right")
    table.add_column("Reach", justify="right")
    table.add_column("Conseq.", justify="right")
    table.add_column("Due")
    for item in results:
        table.add_row(
            item.asset or "-", f"{item.exposure.index:g}", item.exposure.verdict,
            f"{item.exposure.threat:.2f}", f"{item.exposure.reachability:.2f}",
            f"{item.exposure.consequence:.2f}", item.due_by or "-",
        )
    OUT.print(table)

    if len(results) > 1:
        spread = results[0].exposure.index - results[-1].exposure.index
        OUT.print(
            f"\n[dim]Threat is identical everywhere. The {spread:.0f}-point spread is entirely "
            f"reachability and consequence. That difference is what knowing your own estate buys you.[/]"
        )
    return 0


async def cmd_inventory(args) -> int:
    if args.action == "init":
        target = Path(args.path or "vulnometry.yaml")
        if target.exists() and not args.force:
            ERR.print(f"[yellow]{target} already exists.[/] Pass --force to overwrite.")
            return 2
        target.write_text(TEMPLATE, encoding="utf-8")
        OUT.print(f"[green]Created {target}[/]")
        OUT.print("\nEdit it to describe what you run. Only [bold]name[/] is required; every other")
        OUT.print("field sharpens the measurement. Then run [bold]vulnometry measure CVE-... [/]")
        return 0

    inventory = Inventory.discover(args.path)
    if args.action == "show":
        if not inventory.assets:
            ERR.print("[yellow]No inventory found.[/] Run [bold]vulnometry inventory init[/] to create one.")
            return 2
        table = Table(title=f"Inventory: {inventory.source_path}")
        table.add_column("Asset", style="bold")
        table.add_column("Tier")
        table.add_column("Owner", overflow="fold", max_width=26)
        table.add_column("Unit")
        table.add_column("Env")
        table.add_column("Internet")
        table.add_column("Data")
        table.add_column("Regimes", overflow="fold")
        for asset in inventory.assets:
            exposure = {True: "[red]yes[/]", False: "no"}.get(asset.internet_exposed, "[dim]?[/]")
            table.add_row(
                asset.name, f"{asset.tier or '?'} {asset.tier_label}", asset.owner or "-",
                asset.business_unit or "-", asset.environment or "-", exposure,
                asset.data_classification or "-", ", ".join(asset.regimes) or "-",
            )
        OUT.print(table)
        OUT.print_json(data=inventory.coverage)
        return 0

    OUT.print_json(data=inventory.to_dict())
    return 0


async def cmd_watch(args) -> int:
    from .feeds import catalogue as kev_feed

    entries = await (kev_feed.past_deadline() if args.overdue else kev_feed.added_since(days=args.days))
    title = (
        f"Past the CISA remediation deadline ({len(entries)})"
        if args.overdue
        else f"Newly confirmed as exploited, last {args.days} days ({len(entries)})"
    )

    if args.format == "json":
        print(json.dumps([e.to_dict() for e in entries], indent=2))
        return 0

    if args.measure:
        inventory = Inventory.discover(args.inventory)
        ids = [e.cve_id for e in entries][: args.limit]
        if not ids:
            OUT.print("[green]Nothing new.[/]")
            return 0
        with ERR.status(f"Measuring {len(ids)} newly-exploited CVE(s) against your inventory..."):
            results = await assess_portfolio(ids, inventory=inventory, lens="signal")
        summary = portfolio_summary(results)
        render_table(results, OUT)
        _print_summary(summary)
        return 0

    table = Table(title=title)
    table.add_column("CVE", style="bold")
    table.add_column("Vendor")
    table.add_column("Product")
    table.add_column("Catalogued")
    table.add_column("Deadline")
    table.add_column("Ransomware")
    for entry in entries[: args.limit]:
        table.add_row(
            entry.cve_id, entry.vendor, entry.product, entry.catalogued,
            entry.federal_deadline, "[red]yes[/]" if entry.ransomware_linked else "",
        )
    OUT.print(table)
    return 0


async def cmd_ask(args) -> int:
    from .analyst import Step, run_analysis
    from .providers import ProviderError

    def trace(step: Step) -> None:
        if args.quiet:
            return
        if step.kind == "action":
            ERR.print(f"[dim]→ {step.name}({json.dumps(step.data, default=str)[:110]})[/]")
        elif step.kind == "error":
            ERR.print(f"[red]{step.data}[/]")

    try:
        run = await run_analysis(args.question, model=args.model, on_step=trace)
    except ProviderError as exc:
        ERR.print(f"[red]{exc}[/]\n\nRun [bold]vulnometry providers[/] to see what is configured.")
        return 2

    if args.format == "json":
        print(json.dumps({
            "answer": run.answer, "provider": run.provider, "model": run.model,
            "actions_used": run.actions_used(), "turns": run.turns, "usage": run.usage,
        }, indent=2))
        return 0

    OUT.print()
    OUT.print(run.answer or "[dim](no answer returned)[/]")
    if not args.quiet:
        ERR.print(f"\n[dim]{run.provider}:{run.model} · {run.calls} action(s) · {run.turns} turn(s)[/]")
    return 0


async def cmd_providers(args) -> int:
    from .providers import ProviderError, configured_providers, get_provider

    entries = configured_providers()

    if args.probe:
        table = Table(title="Provider reachability")
        table.add_column("Provider", style="bold")
        table.add_column("Status")
        table.add_column("Detail", overflow="fold")
        for name, meta in entries.items():
            if not meta["configured"]:
                table.add_row(name, "[dim]not configured[/]", f"needs {meta.get('needs', '-')}")
                continue
            try:
                provider = get_provider(meta["example"].split()[-1])
                result = await provider.check()
                await provider.aclose()
                table.add_row(
                    name,
                    "[green]reachable[/]" if result.get("ok") else "[red]unreachable[/]",
                    str(result.get("detail") or meta["detail"])[:110],
                )
            except ProviderError as exc:
                table.add_row(name, "[red]error[/]", str(exc)[:110])
        OUT.print(table)
        return 0

    table = Table(title="Inference providers (all optional)")
    table.add_column("Provider", style="bold")
    table.add_column("Ready")
    table.add_column("What it is", overflow="fold")
    table.add_column("Flag", overflow="fold")
    for name, meta in entries.items():
        table.add_row(
            name,
            "[green]yes[/]" if meta["configured"] else f"[dim]needs {meta.get('needs', '')}[/]",
            meta["description"],
            meta["example"],
        )
    OUT.print(table)
    OUT.print("\n[dim]vulnometry providers --probe makes a live call to each configured provider.[/]")
    return 0


async def cmd_doctor(args) -> int:
    from .registry import invoke

    with ERR.status("Probing feeds..."):
        health = await invoke("diagnostics", {})

    table = Table(title="Data feeds")
    table.add_column("Feed", style="bold")
    table.add_column("Status", overflow="fold")
    for name, status in (health.get("feeds") or {}).items():
        table.add_row(name, "[green]ok[/]" if status == "ok" else f"[red]{status}[/]")
    OUT.print(table)

    cfg = settings()
    coverage = health.get("inventory") or {}
    OUT.print()
    OUT.print(f"Exposure model:  {health.get('exposure_model')}")
    OUT.print(f"State dir:       {cfg.state_dir}")
    OUT.print(f"Inventory:       {coverage.get('source')}, {coverage.get('assets', 0)} asset(s)")
    if not coverage.get("assets"):
        OUT.print("                 [yellow]no inventory: findings will be scored pessimistically. Run `vulnometry inventory init`.[/]")
    OUT.print(f"NVD API key:     {'[green]set[/]' if cfg.nvd_api_key else '[yellow]not set: NVD limits you to 5 requests / 30s (free key: https://nvd.nist.gov/developers/request-an-api-key)[/]'}")
    OUT.print(f"GitHub token:    {'[green]set[/]' if cfg.github_token else '[yellow]not set: advisory and exploit lookups will be throttled[/]'}")
    budget = health.get("github_budget") or {}
    if budget.get("remaining") is not None:
        OUT.print(f"GitHub budget:   {budget['remaining']}/{budget.get('limit')} remaining")
    OUT.print()
    await cmd_providers(argparse.Namespace(probe=False))
    return 0


async def cmd_actions(args) -> int:
    from .surfaces.schemas import DIALECTS

    if args.dialect:
        print(json.dumps(DIALECTS[args.dialect](), indent=2))
        return 0

    from .registry import ACTIONS

    table = Table(title=f"{len(ACTIONS)} actions")
    table.add_column("Name", style="bold")
    table.add_column("Description", overflow="fold")
    for action in ACTIONS:
        table.add_row(action.name, action.description)
    OUT.print(table)
    OUT.print("\n[dim]vulnometry actions --dialect openai|anthropic|bedrock|gemini|neutral prints schemas as JSON.[/]")
    return 0


async def cmd_run(args) -> int:
    from .registry import invoke

    try:
        arguments = json.loads(args.arguments) if args.arguments else {}
    except json.JSONDecodeError as exc:
        ERR.print(f"[red]--arguments must be valid JSON: {exc}[/]")
        return 2
    result = await invoke(args.name, arguments)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1


def cmd_serve(args) -> int:
    if args.what == "mcp":
        from .surfaces.mcp import main as mcp_main

        mcp_main()
        return 0

    from .surfaces.service import main as http_main

    ERR.print(f"[green]vulnometry on http://{args.host}:{args.port}[/]  (dashboard at /dashboard, schema at /openapi.json)")
    http_main(host=args.host, port=args.port)
    return 0


async def cmd_cache(args) -> int:
    from .net import cache

    if args.clear:
        removed = await cache().purge()
        OUT.print(f"Cleared {removed} cached responses.")
    else:
        path = settings().state_dir / "feed-cache.sqlite3"
        size = path.stat().st_size / 1024 if path.exists() else 0
        OUT.print(f"Feed cache: {path} ({size:.0f} KB)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnometry",
        description="Measure what a vulnerability is worth to your business, not how severe it is in the abstract.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  vulnometry inventory init                        describe what you run
  vulnometry measure CVE-2021-44228                measure one finding
  vulnometry compare CVE-2021-44228                the same CVE across your whole estate
  vulnometry import qualys-export.xlsx             bulk: spreadsheet in, workbook + dashboard out
  vulnometry sweep package-lock.json               dependencies
  vulnometry watch --days 7 --measure              new KEV entries, measured against your inventory
  vulnometry ask "what must ship before Friday?" --model ollama:qwen3
  vulnometry serve mcp                             expose the actions to an MCP client
  vulnometry doctor                                check feeds, keys and inventory
""",
    )
    parser.add_argument("-V", "--version", action="version", version=f"vulnometry {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def context_flags(p):
        group = p.add_argument_group("business context (overrides the inventory)")
        group.add_argument("--asset", help="name of the asset in your inventory")
        group.add_argument("--tier", type=int, choices=[1, 2, 3], help="1 mission-critical, 2 business-important, 3 supporting")
        group.add_argument("--internet-exposed", action="store_true")
        group.add_argument("--internal-only", action="store_true")
        group.add_argument("--not-deployed", action="store_true", help="collapses exposure to zero")
        group.add_argument("--mitigated", action="store_true", help="compensating controls are in place")
        group.add_argument("--data", choices=["public", "internal", "confidential", "restricted"])
        group.add_argument("--regime", action="append", help="pci-dss, hipaa, sox, gdpr... (repeatable)")
        group.add_argument("--environment", help="production | staging | development")

    def output_flags(p):
        p.add_argument("--format", choices=["table", "json", "markdown", "csv"], default="table")
        p.add_argument("-o", "--output", help="write the chosen format to a file")
        p.add_argument("--workbook", metavar="FILE.xlsx", help="write an annotated Excel workbook")
        p.add_argument("--dashboard", metavar="FILE.html", help="write a self-contained HTML dashboard")
        p.add_argument("--title", help="dashboard title")
        p.add_argument("--min-index", type=float, default=0.0, help="drop findings below this BEI")
        p.add_argument("--inventory", help="path to an inventory file")
        p.add_argument("--compact", action="store_true", help="always use the table view")

    m = sub.add_parser("measure", help="measure one or more CVEs")
    m.add_argument("cve", nargs="*")
    m.add_argument("-f", "--file", action="append", help="file containing CVE ids ('-' for stdin)")
    m.add_argument("--lens", choices=["signal", "full", "forensic"])
    m.add_argument("--concurrency", type=int, default=6)
    m.add_argument("--fail-on", choices=["contain", "remediate", "schedule"], help="exit 1 if anything reaches this verdict (for CI)")
    context_flags(m)
    output_flags(m)
    m.set_defaults(func=cmd_measure, is_async=True)

    i = sub.add_parser("import", help="bulk-measure a scanner export: xlsx, csv, Trivy/Grype/Snyk/SARIF JSON")
    i.add_argument("path")
    i.add_argument("--sheet", default="", help="worksheet name, for multi-sheet workbooks")
    i.add_argument("--preview", action="store_true", help="show detected columns without measuring anything")
    i.add_argument("--limit", type=int, help="only measure the first N findings")
    i.add_argument("--lens", choices=["signal", "full", "forensic"], default="signal")
    i.add_argument("--concurrency", type=int, default=6)
    i.add_argument("--fail-on", choices=["contain", "remediate", "schedule"])
    context_flags(i)
    output_flags(i)
    i.set_defaults(func=cmd_import, is_async=True)

    s = sub.add_parser("sweep", help="check a dependency manifest or SBOM, then measure what it finds")
    s.add_argument("path")
    s.add_argument("--no-measure", action="store_true", help="just list vulnerable components")
    s.add_argument("--lens", choices=["signal", "full", "forensic"], default="signal")
    context_flags(s)
    output_flags(s)
    s.set_defaults(func=cmd_sweep, is_async=True)

    c = sub.add_parser("compare", help="measure one CVE across every asset in your inventory")
    c.add_argument("cve")
    c.add_argument("--limit", type=int, default=15)
    c.add_argument("--inventory")
    c.set_defaults(func=cmd_compare, is_async=True)

    inv = sub.add_parser("inventory", help="create or inspect your business inventory")
    inv.add_argument("action", choices=["init", "show", "json"], nargs="?", default="show")
    inv.add_argument("--path", help="inventory file path")
    inv.add_argument("--force", action="store_true")
    inv.set_defaults(func=cmd_inventory, is_async=True)

    w = sub.add_parser("watch", help="newly confirmed exploitation from the CISA KEV catalogue")
    w.add_argument("--days", type=int, default=14)
    w.add_argument("--overdue", action="store_true", help="entries past their remediation deadline")
    w.add_argument("--measure", action="store_true", help="measure them against your inventory")
    w.add_argument("--limit", type=int, default=40)
    w.add_argument("--format", choices=["table", "json"], default="table")
    w.add_argument("--inventory")
    w.set_defaults(func=cmd_watch, is_async=True)

    a = sub.add_parser("ask", help="ask a model, with the actions attached")
    a.add_argument("question")
    a.add_argument("--model", help="ollama:qwen3, bedrock:us.anthropic.claude-sonnet-4-20250514-v1:0, azure:my-deployment, onprem:my-model...")
    a.add_argument("--quiet", action="store_true")
    a.add_argument("--format", choices=["text", "json"], default="text")
    a.set_defaults(func=cmd_ask, is_async=True)

    p = sub.add_parser("providers", help="list inference providers and whether they are configured")
    p.add_argument("--probe", action="store_true", help="make a live call to each")
    p.set_defaults(func=cmd_providers, is_async=True)

    d = sub.add_parser("doctor", help="check feeds, credentials, inventory and providers")
    d.set_defaults(func=cmd_doctor, is_async=True)

    ac = sub.add_parser("actions", help="list actions, or print schemas for your own agent")
    ac.add_argument("--dialect", choices=["openai", "anthropic", "bedrock", "gemini", "neutral"])
    ac.set_defaults(func=cmd_actions, is_async=True)

    r = sub.add_parser("run", help="invoke a single action directly (for debugging)")
    r.add_argument("name")
    r.add_argument("--arguments", default="{}", help="JSON object")
    r.set_defaults(func=cmd_run, is_async=True)

    sv = sub.add_parser("serve", help="run vulnometry as a server")
    sv.add_argument("what", choices=["mcp", "http"])
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    sv.set_defaults(func=cmd_serve, is_async=False)

    ca = sub.add_parser("cache", help="inspect or clear the feed cache")
    ca.add_argument("--clear", action="store_true")
    ca.set_defaults(func=cmd_cache, is_async=True)

    return parser


async def _run(args) -> int:
    from .net import aclose

    try:
        return await args.func(args)
    finally:
        await aclose()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code = asyncio.run(_run(args)) if getattr(args, "is_async", True) else args.func(args)
    except KeyboardInterrupt:
        ERR.print("\n[dim]interrupted[/]")
        return 130
    except Exception as exc:  # noqa: BLE001
        ERR.print(f"[red]{type(exc).__name__}: {exc}[/]")
        return 1
    sys.exit(code or 0)


if __name__ == "__main__":
    main()
