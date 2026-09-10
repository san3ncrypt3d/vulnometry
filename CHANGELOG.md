# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/), with the addition
that any change to the exposure model bumps `MODEL_VERSION` independently.

## [Unreleased]

### Added

- `summary.severity_crosstab`: how each severity band was judged, on both axes — what the
  scanner called it and what NVD's CVSS calls it — against the verdict. "You accepted 40
  Critical findings" is the first challenge any report of this kind meets, so it is stated
  rather than left to be discovered. `Assessment` now carries `scanner_severity`, the
  scanner's own rating verbatim; it is kept for comparison and never used in the score.
  Shown on the dashboard as three rankings of the same findings -- what the scanner called
  Critical and High, what CVSS calls them, and what the model decided -- with a
  plain-language summary, since the three routinely disagree.

### Changed

- Dashboard: dropped the "Highest exposure" findings table. It grew with the scan and on a
  real run pushed the page past 40 KB while duplicating the workbook's Findings and Action
  Plan sheets, which are the right place to read individual rows. The page is now a fixed
  size regardless of scan volume.

### Fixed

- Tabular intake mapped `raw_severity` to the wrong column whenever an export carried both
  a finding severity and an asset criticality. `criticality` was a severity alias and the
  longest-alias-first tiebreak made it beat `severity`, so a Snyk export recorded
  `PROJECT_CRITICALITY` — the project's business-criticality tag — as the finding's
  severity. `criticality` is no longer a severity alias (asset criticality is modelled
  separately as tier) and the common explicit spellings are matched first.

## [0.2.0] - 2026-09-10

### Added

- Every bulk report states how much the analysis narrowed the pile, under
  `summary.reduction`: scanner findings, unique CVEs, CVE-by-asset decisions, how many a
  severity-driven queue would call urgent (CVSS >= 7), how many are actionable, and finally
  the distinct (asset, package) upgrades to perform, since one dependency bump closes every
  CVE that package carries. `analysis_reduction_pct` is measured against the severity queue
  rather than the row count, so scanner duplication is not counted as the tool's work.
  Effort avoided is reported as a band with the per-finding triage assumption beside it
  (`VULNOMETRY_TRIAGE_MINUTES_LOW` / `_HIGH`) and never feeds a score. Rendered as a tree in
  the console, a numbered list in Markdown, a bar chart on the dashboard and a block in the
  workbook's Method sheet.
- Dashboard: a leadership view — a verdict KPI row that now includes **Accept**, each card
  carrying a plain-language subtitle; a second row with the severity-queue reduction, the
  upgrades left, the analyst hours avoided and what matched no asset; and a business-unit
  (or owner, or asset) by verdict heat map ordered by total exposure.
- Every assessment carries a one-sentence `rationale()`: what drove the verdict (the deciding
  factor and its evidence) plus the context it was judged in — internet exposure, tier, data
  class, EPSS score and its date, KEV status, confidence. `Assessment` now also keeps `tier`,
  `internet_exposed` and `data_classification` from the matched asset.
- Workbook: a new **Accepted** sheet — an audit-ready register of every finding below the
  action threshold, with the rationale, inputs, evidence gaps, model version and run timestamp,
  and blank columns for the human decision (who, when, review-by date, reopen triggers). The
  Findings sheet gains **Internet**, **EPSS date** and **Rationale** columns; the Method sheet
  records the run timestamp and model version. The Markdown report now lists Accepted findings
  with their rationale instead of dropping them.
- Findings keep the identifier the scan gave them (`source_asset`, `source_host`,
  `source_component` on `Assessment`) even when nothing in the inventory matches, so a
  bulk import no longer produces anonymous rows. The workbook gains a **Scanner ref**
  column; the Action Plan, terminal table, Markdown, CSV and dashboard fall back to the
  scan's own label (shown as `~name`) when there is no matched asset.
- `vulnometry inventory import EXPORT --map MAPPING.yaml`: build the business inventory
  from an arbitrary CSV/XLSX asset export (a CMDB extract, an application register). The
  mapping file names the columns and the value translations; built-in transforms cover
  multi-value cells, host extraction from URLs and tri-state booleans. Re-running merges,
  keeping fields added by hand. Also usable inline: `--inventory EXPORT --inventory-map MAPPING`.
- `docs/INVENTORY-IMPORT.md`: full reference and a runnable worked example
  (`examples/asset-export.csv`, `examples/inventory-mapping.yaml`,
  `examples/inventory-from-export.yaml`) with a line-by-line account of how each column is read.
- `aliases` on an asset: other names a scan might use for it (a scanner project, a code
  name, a ticket key). `Inventory.by_name()` resolves them, with glob support.
- CSV intake now decodes cp1252 / latin-1 exports, not just UTF-8.
- Dashboard screenshot in the README, with the sample export
  (`examples/scan-export.csv`) and generated page (`examples/exposure.html`) that produced it.

### Changed

- Dashboard cards centre their chart vertically, so a short chart no longer leaves
  a band of empty space when the card next to it is taller.

## [0.1.0] - 2026-09-02

First release. Exposure model `bei-1.0`.

### Added

- **Business Exposure Index.** `BEI = 1000 · Threat^0.8 · Reachability^0.7 ·
  Consequence^0.6`. Multiplicative, so any factor can veto; every factor carries
  its reasoning. Verdicts: Contain, Remediate, Schedule, Accept.
- **Business inventory** (`vulnometry.yaml`): asset tiers, owners, business units,
  environments, internet exposure, data classification, regulatory scope,
  compensating controls, component and hostname globs. Due dates derived from
  verdict plus asset policy.
- **Feeds:** NIST NVD with automatic CVE Program fallback, FIRST EPSS, CISA KEV,
  OSV.dev, GitHub Security Advisories, and heuristic exploit-artifact discovery.
- **Intake:** Excel and CSV with header-row detection and column alias matching;
  native JSON from Trivy, Grype, Snyk, OSV-Scanner, Dependabot and SARIF;
  lockfiles and SBOMs (requirements.txt, poetry.lock, package-lock.json, go.mod,
  Gemfile.lock, Cargo.lock, pom.xml, CycloneDX, SPDX).
- **Reporting:** annotated four-sheet Excel workbook (Findings, Action Plan, By
  Owner, Method); self-contained HTML dashboard with inline SVG and no
  JavaScript; terminal, JSON, Markdown and CSV output.
- **Commands:** `measure`, `import`, `sweep`, `compare`, `inventory`, `watch`,
  `ask`, `providers`, `doctor`, `actions`, `run`, `serve`, `cache`.
- **Surfaces:** MCP over stdio with no SDK dependency; OpenAI, Anthropic,
  Bedrock and Gemini tool schemas; FastAPI service with OpenAPI.
- **Providers:** Ollama, any OpenAI-compatible server, OpenAI/Codex, Azure AI
  Foundry and Azure OpenAI, AWS Bedrock, Anthropic, Google Gemini.
- Client-side per-host rate limiting and a SQLite feed cache.
- 58 offline tests.
