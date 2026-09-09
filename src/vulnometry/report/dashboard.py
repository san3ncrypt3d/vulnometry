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
.kpi.alert .n { color:#c0392b; }
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


def _kpi(value, label: str, alert: bool = False) -> str:
    return f'<div class="kpi{" alert" if alert else ""}"><div class="n">{_e(value)}</div><div class="l">{_e(label)}</div></div>'


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

    overdue = sum(1 for i in items if i.due_by and i.due_by < date.today().isoformat())

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
  {_kpi(counts.get("Contain", 0), "contain now", alert=counts.get("Contain", 0) > 0)}
  {_kpi(counts.get("Remediate", 0), "remediate this sprint")}
  {_kpi(counts.get("Schedule", 0), "next window")}
  {_kpi(confirmed, "confirmed exploited", alert=confirmed > 0)}
  {_kpi(overdue, "past due date", alert=overdue > 0)}
  {_kpi(suppressed, "suppressed by context")}
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
