"""Terminal rendering."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..schema import Assessment

VERDICT_STYLE = {
    "Contain": "bold white on red",
    "Remediate": "bold red",
    "Schedule": "yellow",
    "Accept": "dim",
}


def console() -> Console:
    return Console()


def _bar(value: float, width: int = 12) -> str:
    filled = int(round(max(0.0, min(1.0, value)) * width))
    return "█" * filled + "·" * (width - filled)


def _location(item: Assessment) -> str:
    """Matched asset name, or the scanner's own label prefixed with ~ when unmatched."""
    if item.asset:
        return item.asset
    ref = item.scanner_ref()
    return f"~{ref}" if ref else "-"


def render_one(item: Assessment, out: Console | None = None) -> None:
    out = out or console()
    style = VERDICT_STYLE.get(item.exposure.verdict, "white")

    header = Text()
    header.append(f"{item.cve_id}  ", style="bold")
    header.append(f" {item.exposure.verdict} ", style=style)
    header.append(f"  BEI {item.exposure.index:g}/1000")
    if item.asset:
        header.append(f"   on {item.asset}", style="cyan")
    elif item.scanner_ref():
        header.append(f"   on ~{item.scanner_ref()}", style="cyan")
    out.print(Panel(header, expand=False, border_style=style.split()[-1]))

    if item.weakness.summary:
        out.print(Text(item.weakness.summary.strip()[:600], style="dim"))
        out.print()

    factors = Table.grid(padding=(0, 2))
    factors.add_column(style="dim", justify="right", width=13)
    factors.add_column(width=14)
    factors.add_column()
    factors.add_row("Threat", _bar(item.exposure.threat), f"{item.exposure.threat:.2f}  will anyone try?")
    factors.add_row("Reachability", _bar(item.exposure.reachability), f"{item.exposure.reachability:.2f}  can they get to it here?")
    factors.add_row("Consequence", _bar(item.exposure.consequence), f"{item.exposure.consequence:.2f}  what does it cost us?")
    out.print(factors)
    out.print()

    facts = Table.grid(padding=(0, 2))
    facts.add_column(style="dim", justify="right", width=13)
    facts.add_column()
    severity = item.weakness.primary_severity()
    facts.add_row("CVSS", f"{severity.base_score:g} ({severity.rating}) v{severity.version}" if severity and severity.base_score is not None else "not published")
    facts.add_row(
        "EPSS",
        f"{item.probability.probability * 100:.2f}% in 30 days" if item.probability.probability is not None else "no score",
    )
    kev = "not listed"
    if item.exploitation.confirmed:
        kev = f"exploited in the wild (catalogued {item.exploitation.catalogued})"
        if item.exploitation.ransomware_linked:
            kev += ", ransomware-linked"
    facts.add_row("CISA KEV", kev)
    if not item.asset and item.scanner_ref():
        facts.add_row("Scanner ref", f"{item.scanner_ref()}  (no inventory match)")
    if item.owner:
        facts.add_row("Owner", item.owner)
    if item.business_unit:
        facts.add_row("Business unit", item.business_unit)
    if item.due_by:
        facts.add_row("Due by", f"{item.due_by}  ({item.sla_days}d SLA)")
    if item.fixes:
        facts.add_row("Fixed in", ", ".join(item.fixes[:5]))
    facts.add_row("Confidence", item.exposure.confidence)
    out.print(facts)

    out.print()
    out.print(Text("How this was measured", style="bold"))
    for label, reasons in (
        ("Threat", item.exposure.threat_basis),
        ("Reachability", item.exposure.reachability_basis),
        ("Consequence", item.exposure.consequence_basis),
    ):
        for reason in reasons:
            out.print(f"  {label:<13} {reason}", highlight=False)

    out.print()
    out.print(Panel(item.directive, title="Directive", border_style=style.split()[-1], expand=False))

    if item.bulletins:
        out.print()
        out.print(Text("Advisories", style="bold"))
        for bulletin in item.bulletins[:5]:
            out.print(f"  {bulletin.origin}: {bulletin.ref} - {bulletin.summary[:80]}", highlight=False)

    if item.gaps:
        out.print()
        out.print(Text("Gaps in the evidence", style="yellow"))
        for gap in item.gaps:
            out.print(f"  {gap}", style="yellow", highlight=False)


def render_table(items: list[Assessment], out: Console | None = None, limit: int = 60) -> None:
    out = out or console()
    table = Table(title=f"{len(items)} findings, highest exposure first")
    table.add_column("CVE", style="bold")
    table.add_column("BEI", justify="right")
    table.add_column("Verdict")
    table.add_column("Asset / ~scan ref", overflow="fold", max_width=22)
    table.add_column("Owner", overflow="fold", max_width=18)
    table.add_column("T", justify="right")
    table.add_column("R", justify="right")
    table.add_column("C", justify="right")
    table.add_column("Due", max_width=11)

    for item in items[:limit]:
        table.add_row(
            item.cve_id,
            f"{item.exposure.index:g}",
            Text(item.exposure.verdict, style=VERDICT_STYLE.get(item.exposure.verdict, "")),
            _location(item),
            item.owner or "-",
            f"{item.exposure.threat:.2f}",
            f"{item.exposure.reachability:.2f}",
            f"{item.exposure.consequence:.2f}",
            item.due_by or "-",
        )
    out.print(table)
    if len(items) > limit:
        out.print(f"[dim]...and {len(items) - limit} more. Use --format json or --workbook for the full set.[/]")


def to_json(items: list[Assessment], summary: dict | None = None) -> str:
    payload: dict | list
    if summary is not None:
        payload = {"summary": summary, "findings": [i.to_dict() for i in items]}
    else:
        payload = [i.to_dict() for i in items]
        if len(items) == 1:
            payload = payload[0]
    return json.dumps(payload, indent=2, default=str)


def to_markdown(items: list[Assessment], summary: dict | None = None) -> str:
    lines = ["# Exposure assessment", ""]
    if summary:
        contain = len(summary.get("contain_now", []))
        lines.append(
            f"{summary['assessed']} findings assessed. "
            f"**{contain} {'requires' if contain == 1 else 'require'} containment now**, "
            f"{summary['actionable']} actionable in total, "
            f"{summary['deferrable']} can wait for the routine cycle."
        )
        if summary.get("suppressed_by_context"):
            lines.append("")
            lines.append(
                f"{summary['suppressed_by_context']} finding(s) were reduced to negligible exposure "
                "by business context: the affected component is not deployed or not reachable."
            )
        lines.append("")

    lines += [
        "| CVE | BEI | Verdict | Asset / ~scan ref | Owner | Due | Fix |",
        "|---|---:|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {item.cve_id} | {item.exposure.index:g} | {item.exposure.verdict} "
            f"| {_location(item)} | {item.owner or '-'} | {item.due_by or '-'} "
            f"| {', '.join(item.fixes[:2]) or '-'} |"
        )

    for item in items:
        if item.exposure.verdict == "Accept":
            continue
        lines += ["", f"## {item.cve_id}: {item.exposure.verdict} (BEI {item.exposure.index:g})", ""]
        if item.where():
            label = "Asset" if item.asset else "Scanner ref (no inventory match)"
            lines.append(f"**{label}:** {item.where()} · **Owner:** {item.owner or 'unassigned'} · **Due:** {item.due_by or 'n/a'}")
            lines.append("")
        if item.weakness.summary:
            lines += [item.weakness.summary.strip()[:700], ""]
        lines.append(
            f"Threat {item.exposure.threat:.2f} × Reachability {item.exposure.reachability:.2f} "
            f"× Consequence {item.exposure.consequence:.2f}"
        )
        lines.append("")
        for reason in item.exposure.threat_basis + item.exposure.reachability_basis + item.exposure.consequence_basis:
            lines.append(f"- {reason}")
        lines += ["", f"**Directive:** {item.directive}", ""]
    return "\n".join(lines)


def to_csv(items: list[Assessment]) -> str:
    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "cve", "bei", "verdict", "threat", "reachability", "consequence",
        "asset", "scanner_ref", "owner", "business_unit", "environment", "due_by", "sla_days",
        "cvss", "epss", "kev", "fixes", "confidence", "directive",
    ])
    for item in items:
        severity = item.weakness.primary_severity()
        writer.writerow([
            item.cve_id, item.exposure.index, item.exposure.verdict,
            item.exposure.threat, item.exposure.reachability, item.exposure.consequence,
            item.asset, item.scanner_ref(), item.owner, item.business_unit, item.environment,
            item.due_by, item.sla_days or "",
            severity.base_score if severity and severity.base_score is not None else "",
            item.probability.probability if item.probability.probability is not None else "",
            "yes" if item.exploitation.confirmed else "",
            "; ".join(item.fixes[:5]), item.exposure.confidence, item.directive,
        ])
    return buffer.getvalue()
