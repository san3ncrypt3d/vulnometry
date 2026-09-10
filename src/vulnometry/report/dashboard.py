"""A single self-contained HTML file. No server, no CDN, no JavaScript."""

from __future__ import annotations

import html
from datetime import date
from pathlib import Path

from ..schema import Assessment

VERDICT_COLOUR = {
    "Contain": "#c0392b",
    "Remediate": "#e67e22",
    "Schedule": "#d4ac0d",
    "Accept": "#7f8c8d",
}
VERDICT_ORDER = ["Contain", "Remediate", "Schedule", "Accept"]


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _donut(counts: dict[str, int], size: int = 190) -> str:
    total = sum(counts.values()) or 1
    radius, thickness = size / 2 - 14, 26
    centre = size / 2
    circumference = 2 * 3.14159265 * radius

    segments, offset = [], 0.0
    for verdict in VERDICT_ORDER:
        value = counts.get(verdict, 0)
        if not value:
            continue
        length = circumference * (value / total)
        segments.append(
            f'<circle cx="{centre}" cy="{centre}" r="{radius}" fill="none" '
            f'stroke="{VERDICT_COLOUR[verdict]}" stroke-width="{thickness}" '
            f'stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {centre} {centre})">'
            f"<title>{verdict}: {value}</title></circle>"
        )
        offset += length

    actionable = counts.get("Contain", 0) + counts.get("Remediate", 0)
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img">'
        f'<circle cx="{centre}" cy="{centre}" r="{radius}" fill="none" stroke="#eceff1" stroke-width="{thickness}"/>'
        + "".join(segments)
        + f'<text x="{centre}" y="{centre - 4}" text-anchor="middle" font-size="30" font-weight="700" fill="#1f3a53">{actionable}</text>'
        f'<text x="{centre}" y="{centre + 16}" text-anchor="middle" font-size="11" fill="#7f8c8d">need action</text>'
        "</svg>"
    )


def _bars(rows: list[tuple[str, float]], width: int = 460, colour: str = "#1f3a53") -> str:
    if not rows:
        return '<p class="muted">Nothing to show.</p>'
    rows = rows[:10]
    peak = max(value for _, value in rows) or 1
    bar_height, gap = 22, 10
    height = len(rows) * (bar_height + gap)
    label_width = 165

    parts = []
    for index, (label, value) in enumerate(rows):
        y = index * (bar_height + gap)
        bar = (width - label_width - 52) * (value / peak)
        parts.append(
            f'<text x="{label_width - 8}" y="{y + 15}" text-anchor="end" font-size="12" fill="#37474f">'
            f"{_e(label[:26])}</text>"
            f'<rect x="{label_width}" y="{y}" width="{max(bar, 2):.1f}" height="{bar_height}" rx="3" fill="{colour}"/>'
            f'<text x="{label_width + max(bar, 2) + 8}" y="{y + 15}" font-size="11" fill="#546e7a">{value:g}</text>'
        )
    return f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}">' + "".join(parts) + "</svg>"


def _scatter(items: list[Assessment], width: int = 470, height: int = 260) -> str:
    """Reachability against consequence, sized by threat."""
    pad = 38
    plot_w, plot_h = width - pad * 2, height - pad * 2
    points = []
    for item in items[:400]:
        x = pad + item.exposure.reachability * plot_w
        y = height - pad - item.exposure.consequence * plot_h
        r = 3 + item.exposure.threat * 7
        colour = VERDICT_COLOUR.get(item.exposure.verdict, "#7f8c8d")
        points.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{colour}" fill-opacity="0.55" '
            f'stroke="{colour}" stroke-width="0.8"><title>{_e(item.cve_id)}: BEI {item.exposure.index:g}'
            f'{" on " + _e(item.where()) if item.where() else ""}</title></circle>'
        )

    grid = "".join(
        f'<line x1="{pad + plot_w * f}" y1="{pad}" x2="{pad + plot_w * f}" y2="{height - pad}" stroke="#eceff1"/>'
        f'<line x1="{pad}" y1="{pad + plot_h * f}" x2="{width - pad}" y2="{pad + plot_h * f}" stroke="#eceff1"/>'
        for f in (0.25, 0.5, 0.75)
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}">{grid}'
        f'<line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" stroke="#b0bec5"/>'
        f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{height - pad}" stroke="#b0bec5"/>'
        + "".join(points)
        + f'<text x="{width / 2}" y="{height - 8}" text-anchor="middle" font-size="11" fill="#78909c">Reachability →</text>'
        f'<text x="12" y="{height / 2}" text-anchor="middle" font-size="11" fill="#78909c" '
        f'transform="rotate(-90 12 {height / 2})">Consequence →</text>'
        "</svg>"
    )


STYLE = """
:root { --ink:#1f3a53; --muted:#7f8c8d; --line:#e3e8ec; --bg:#f6f8fa; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:#233; font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
header { background:var(--ink); color:#fff; padding:26px 32px; }
header h1 { margin:0 0 4px; font-size:21px; letter-spacing:.2px; }
header p { margin:0; opacity:.72; font-size:13px; }
main { padding:24px 32px 56px; max-width:1240px; margin:0 auto; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:18px; margin-bottom:22px; }
.card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:18px 20px; display:flex; flex-direction:column; }
.card h2 { margin:0 0 14px; font-size:12px; text-transform:uppercase; letter-spacing:.9px; color:var(--muted); font-weight:700; }
.kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:14px; margin-bottom:22px; }
.kpi { background:#fff; border:1px solid var(--line); border-radius:10px; padding:16px 18px; }
.kpi .n { font-size:28px; font-weight:700; color:var(--ink); line-height:1.1; }
.kpi .l { font-size:11px; text-transform:uppercase; letter-spacing:.7px; color:var(--muted); margin-top:5px; }
.kpi .s { font-size:11px; color:var(--muted); margin-top:3px; opacity:.85; }
.kpi.alert .n { color:#c0392b; }
.kpi.good .n { color:#1e7a4c; }
table.heat { border-collapse:separate; border-spacing:3px; width:100%; }
table.heat th { padding:6px 8px; border:none; }
table.heat th.rl { text-align:left; font-size:11px; color:var(--muted); text-transform:none; letter-spacing:0; font-weight:600; white-space:nowrap; max-width:230px; overflow:hidden; text-overflow:ellipsis; }
table.heat td { border:none; padding:0; }
td.hc { border-radius:5px; text-align:center; height:30px; min-width:52px; }
td.hc span { color:#fff; font-weight:700; font-size:12px; font-variant-numeric:tabular-nums; }
td.hc.empty { background:#f2f5f7; }
td.hc.empty span { color:#c3ccd3; font-weight:400; }
td.rt { text-align:right; padding-right:6px; font-weight:700; color:var(--ink); font-variant-numeric:tabular-nums; font-size:12px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted); padding:8px 10px; border-bottom:2px solid var(--line); white-space:nowrap; }
td { padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
tr:last-child td { border-bottom:none; }
.pill { display:inline-block; padding:2px 9px; border-radius:11px; font-size:11px; font-weight:700; color:#fff; white-space:nowrap; }
.bei { font-weight:700; color:var(--ink); font-variant-numeric:tabular-nums; }
.muted { color:var(--muted); font-size:12px; }
.legend { display:flex; gap:14px; flex-wrap:wrap; margin-top:12px; font-size:12px; }
.legend span { display:flex; align-items:center; gap:6px; }
.dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
.card > svg { margin-block:auto; }
.chartrow { display:flex; gap:20px; align-items:center; justify-content:center; flex-wrap:wrap; margin-block:auto; }
footer { color:var(--muted); font-size:12px; padding:0 32px 40px; max-width:1240px; margin:0 auto; }
code { background:#eef2f5; padding:1px 5px; border-radius:4px; font-size:12px; }
"""


def _kpi(value, label: str, alert: bool = False, note: str = "", tone: str = "") -> str:
    classes = "kpi" + (" alert" if alert else "") + (f" {tone}" if tone else "")
    sub = f'<div class="s">{_e(note)}</div>' if note else ""
    return (f'<div class="{classes}"><div class="n">{_e(value)}</div>'
            f'<div class="l">{_e(label)}</div>{sub}</div>')


def _mins(reduction: dict) -> str:
    low, high = (reduction.get("triage_minutes_assumed") or [30, 120])[:2]
    def h(m):
        return f"{m / 60:g} h" if m >= 60 else f"{m:g} min"
    return f"{h(low)}\u2013{h(high)}"


def _hours_band(reduction: dict) -> str:
    low = reduction.get("analyst_hours_saved_low", 0)
    high = reduction.get("analyst_hours_saved_high", 0)
    if not high:
        return "0"
    return f"{low:,g}\u2013{high:,g}"


def _group_key(item: Assessment) -> str:
    return item.business_unit or item.owner or item.asset or item.scanner_ref() or "unattributed"


def _heatmap(items: list[Assessment], limit: int = 14) -> tuple[str, str]:
    """Where the work sits: one row per business unit (or owner), one column per verdict.

    Returns (html, dimension-label) so the card can say what it grouped by.
    """
    if not items:
        return "", ""
    dimension = ("business unit" if any(i.business_unit for i in items)
                 else "owner" if any(i.owner for i in items)
                 else "asset")

    grid: dict[str, dict[str, int]] = {}
    weight: dict[str, float] = {}
    for item in items:
        key = _group_key(item)
        row = grid.setdefault(key, dict.fromkeys(VERDICT_ORDER, 0))
        row[item.exposure.verdict] = row.get(item.exposure.verdict, 0) + 1
        weight[key] = weight.get(key, 0.0) + item.exposure.index

    ordered = sorted(grid, key=lambda k: -weight[k])
    hidden = max(0, len(ordered) - limit)
    ordered = ordered[:limit]
    peak = max((n for row in grid.values() for n in row.values()), default=1) or 1

    head = "".join(f"<th>{_e(v)}</th>" for v in VERDICT_ORDER)
    body = []
    for key in ordered:
        cells = []
        for verdict in VERDICT_ORDER:
            n = grid[key][verdict]
            if n:
                # opacity carries the magnitude, hue carries the verdict
                alpha = 0.18 + 0.82 * (n / peak)
                cells.append(f'<td class="hc" style="background:{VERDICT_COLOUR[verdict]};'
                             f'opacity:{alpha:.2f}"><span>{n}</span></td>')
            else:
                cells.append('<td class="hc empty"><span>&middot;</span></td>')
        total = sum(grid[key].values())
        body.append(f'<tr><th class="rl" title="{_e(key)}">{_e(key[:38])}</th>'
                    + "".join(cells) + f'<td class="rt">{total}</td></tr>')

    more = (f'<p class="muted">Showing the {limit} groups carrying the most exposure; '
            f'{hidden} more not shown.</p>') if hidden else ""
    return (
        f'<table class="heat"><thead><tr><th class="rl">{_e(dimension)}</th>{head}'
        f'<th class="rt">all</th></tr></thead><tbody>{"".join(body)}</tbody></table>{more}',
        dimension,
    )


def _funnel(reduction: dict, width: int = 460) -> str:
    """Horizontal bars, widest first: scanner rows in, upgrades out."""
    if not reduction or not reduction.get("findings_assessed"):
        return ""
    floor = reduction.get("severity_floor", 7.0)
    # One unit only. unique_cves and cve_asset_pairs count CVEs and pairs, not
    # findings, so putting them in this chain draws a funnel that can widen.
    # They are still reported in the console funnel and in summary.reduction.
    stages = [
        ("Scanner findings", reduction["findings_assessed"], "#1f3a53"),
        (f"Urgent on CVSS alone (≥ {floor:g})", reduction["urgent_on_severity_alone"], "#36688d"),
        ("Actionable after analysis", reduction["actionable_findings"], "#c0392b"),
        ("Upgrades to perform", reduction["actionable_work_items"], "#7d2018"),
    ]
    top = max(v for _, v, _ in stages) or 1
    row_h, gap = 26, 6
    parts = []
    for i, (label, value, colour) in enumerate(stages):
        w = max(2, round(width * value / top))
        y = i * (row_h + gap)
        parts.append(
            f'<rect x="0" y="{y}" width="{w}" height="{row_h}" rx="3" fill="{colour}"></rect>'
            f'<text x="{w + 8}" y="{y + row_h - 8}" class="fl">{value:,} &middot; {_e(label)}</text>'
        )
    height = len(stages) * (row_h + gap)
    return (
        f'<svg viewBox="0 0 {width + 190} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="Reduction funnel">'
        f'<style>.fl{{font:12px system-ui,sans-serif;fill:#33475b}}</style>'
        + "".join(parts) + "</svg>"
    )


def _table(items: list[Assessment], limit: int = 40) -> str:
    if not items:
        return '<p class="muted">No findings.</p>'
    rows = []
    for item in items[:limit]:
        colour = VERDICT_COLOUR.get(item.exposure.verdict, "#7f8c8d")
        driver = ""
        if item.exposure.threat_basis:
            driver = item.exposure.threat_basis[0]
        rows.append(
            "<tr>"
            f"<td><strong>{_e(item.cve_id)}</strong></td>"
            f'<td class="bei">{item.exposure.index:g}</td>'
            f'<td><span class="pill" style="background:{colour}">{_e(item.exposure.verdict)}</span></td>'
            f"<td>{_e(item.asset or (('~' + item.scanner_ref()) if item.scanner_ref() else '-'))}</td>"
            f"<td>{_e(item.owner or '-')}</td>"
            f"<td>{_e(item.due_by or '-')}</td>"
            f'<td class="muted">{_e(driver[:96])}</td>'
            "</tr>"
        )
    return (
        "<table><thead><tr><th>CVE</th><th>BEI</th><th>Verdict</th><th>Asset</th>"
        "<th>Owner</th><th>Due</th><th>Primary driver</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def build_dashboard(
    items: list[Assessment],
    path: str | Path,
    summary: dict | None = None,
    title: str = "Exposure dashboard",
) -> Path:
    path = Path(path)
    summary = summary or {}

    counts = dict.fromkeys(VERDICT_ORDER, 0)
    for item in items:
        counts[item.exposure.verdict] = counts.get(item.exposure.verdict, 0) + 1

    by_unit = summary.get("exposure_by_business_unit") or {}
    by_owner = summary.get("load_by_owner") or {}
    confirmed = len(summary.get("confirmed_exploited") or [])
    suppressed = summary.get("suppressed_by_context", 0)
    unattributed = summary.get("unattributed", 0)
    reduction = summary.get("reduction") or {}

    overdue = sum(1 for i in items if i.due_by and i.due_by < date.today().isoformat())
    heat, heat_dimension = _heatmap(items)

    legend = "".join(
        f'<span><i class="dot" style="background:{VERDICT_COLOUR[v]}"></i>{v} ({counts.get(v, 0)})</span>'
        for v in VERDICT_ORDER
    )

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{STYLE}</style></head>
<body>
<header>
  <h1>{_e(title)}</h1>
  <p>{len(items)} findings measured · generated {date.today().isoformat()} · Business Exposure Index, 0&ndash;1000</p>
</header>
<main>

<div class="kpis">
  {_kpi(counts.get("Contain", 0), "contain now", alert=counts.get("Contain", 0) > 0,
        note="outside the change process")}
  {_kpi(counts.get("Remediate", 0), "remediate this sprint", note="ahead of the routine cycle")}
  {_kpi(counts.get("Schedule", 0), "schedule", note="next maintenance window")}
  {_kpi(counts.get("Accept", 0), "accept", note="below the action threshold", tone="good")}
  {_kpi(confirmed, "confirmed exploited", alert=confirmed > 0, note="listed in CISA KEV")}
  {_kpi(overdue, "past due date", alert=overdue > 0, note="against your own SLA")}
</div>

<div class="kpis">
  {_kpi(f'{reduction.get("analysis_reduction_pct", 0)}%', "of the severity queue removed",
        tone="good",
        note=f'{reduction.get("urgent_on_severity_alone", 0):,} urgent on CVSS → '
             f'{reduction.get("actionable_findings", 0):,} actionable')
   if reduction else ""}
  {_kpi(reduction.get("actionable_work_items", 0), "upgrades to perform",
        note=f'across {reduction.get("actionable_work_assets", 0):,} '
             f'{"asset" if reduction.get("actionable_work_assets") == 1 else "assets"}; '
             f'one bump clears every CVE in that package') if reduction else ""}
  {_kpi(_hours_band(reduction), "analyst hours avoided", tone="good",
        note=f'{reduction.get("findings_not_triaged", 0):,} findings never hand-triaged, '
             f'at {_mins(reduction)} each')
   if reduction else ""}
  {_kpi(unattributed, "unmatched to an asset", alert=unattributed > 0,
        note="scored pessimistically")}
  {_kpi(suppressed, "suppressed by context", note="not deployed or unreachable")}
</div>

<div class="grid">
  <div class="card">
    <h2>Verdict mix</h2>
    <div class="chartrow">{_donut(counts)}</div>
    <div class="legend">{legend}</div>
  </div>
  <div class="card">
    <h2>Reachability vs consequence</h2>
    {_scatter(items)}
    <p class="muted">Bubble size is threat. The top-right corner is the work; the left edge is noise
    that a severity-only view would have ranked identically.</p>
  </div>
</div>

{f'''<div class="card">
  <h2>What the analysis removed</h2>
  {_funnel(reduction)}
  <p class="muted">A severity-driven queue would call
  <strong>{reduction.get("urgent_on_severity_alone", 0):,}</strong> of these urgent
  (CVSS &ge; {reduction.get("severity_floor", 7.0):g}). Measuring exposure where you actually run
  them leaves <strong>{reduction.get("actionable_findings", 0):,}</strong> &mdash;
  <strong>{reduction.get("analysis_reduction_pct", 0)}% of that queue removed</strong>, and what
  is left is {reduction.get("actionable_work_items", 0):,} package
  {"upgrade" if reduction.get("actionable_work_items") == 1 else "upgrades"}, because one bump
  closes every CVE that package carries. Separately, and not counted as analysis, those
  {reduction.get("findings_assessed", 0):,} rows describe
  {reduction.get("unique_cves", 0):,} distinct CVEs across
  {reduction.get("cve_asset_pairs", 0):,} CVE&nbsp;&times;&nbsp;asset decisions: a scanner emits one
  row per (CVE, project, manifest), which inflates the count before anyone judges anything.</p>
</div>''' if reduction.get("findings_assessed") else ""}

{f'''<div class="card">
  <h2>Where the work sits &mdash; {_e(heat_dimension)} &times; verdict</h2>
  {heat}
  <p class="muted">Colour is the verdict, depth is the count. Rows are ordered by total exposure,
  so the top row is where attention buys the most. A row that is wide on the right and empty on
  the left is carrying volume, not risk.</p>
</div>''' if heat else ""}

<div class="grid">
  <div class="card">
    <h2>Exposure by business unit</h2>
    {_bars([(k, v) for k, v in by_unit.items()])}
  </div>
  <div class="card">
    <h2>Actionable load by owner</h2>
    {_bars([(k, float(v)) for k, v in by_owner.items()], colour="#c0392b")}
  </div>
</div>

<div class="card">
  <h2>Highest exposure</h2>
  {_table(items)}
  {'<p class="muted">Showing the top 40 of ' + str(len(items)) + '.</p>' if len(items) > 40 else ''}
</div>

</main>
<footer>
  <p><strong>BEI = 1000 &times; Threat<sup>0.8</sup> &times; Reachability<sup>0.7</sup> &times; Consequence<sup>0.6</sup></strong>.
  Multiplicative, so any factor can veto: a flaw nobody can reach scores near zero however severe it is in the abstract.
  Thresholds: Contain &ge; 700, Remediate &ge; 400, Schedule &ge; 150.</p>
  <p>{unattributed} finding(s) could not be matched to a known asset and were scored with pessimistic defaults.
  Add them to your inventory (<code>vulnometry.yaml</code>) to sharpen the measurement.</p>
  <p>Sources: NIST NVD, CVE Program, FIRST EPSS, CISA KEV, OSV.dev, GitHub Security Advisories.
  Exploit-artifact discovery is heuristic. Reachability is inventory-derived, not verified in code.</p>
</footer>
</body></html>"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path
