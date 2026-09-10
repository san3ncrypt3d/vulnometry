# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/), with the addition
that any change to the exposure model bumps `MODEL_VERSION` independently.

## [Unreleased]

## [0.3.1] - 2026-09-10

### Fixed

- Every feed failed with `CERTIFICATE_VERIFY_FAILED` on a corporate network. httpx verifies
  against certifi, which does not know the private root that a TLS-inspecting proxy re-signs
  traffic with, so `curl` succeeded where vulnometry could not reach anything. Verification now
  goes through the operating system's own trust store via `truststore`, which is a dependency.
  Python 3.13 made this worse by enabling `VERIFY_X509_STRICT`, which rejects enterprise roots
  that omit the critical flag on `basicConstraints`; macOS and Windows tolerate those, so asking
  the OS fixes both halves. An explicit `SSL_CERT_FILE` or `SSL_CERT_DIR` still wins, and
  `VULNOMETRY_SYSTEM_TRUST=0` restores the old behaviour.
- A rejected certificate was retried four times and then reported as a raw OpenSSL string, which
  reads like a network fault and sends people looking for a CA bundle to download. It now fails
  on the first attempt and names the likely cause, the one-command way to confirm it, and the fix.


## [0.3.0] - 2026-09-10

### Added

- `summary.severity_crosstab`: how each severity band was judged, on both axes — what the
  scanner called it and what NVD's CVSS calls it — against the verdict. "You accepted 40
  Critical findings" is the first challenge any report of this kind meets, so it is stated
  rather than left to be discovered. `Assessment` now carries `scanner_severity`, the
  scanner's own rating verbatim; it is kept for comparison and never used in the score.
  Shown on the dashboard as three rankings of the same findings — what the scanner called
  Critical and High, what CVSS calls them, and what the model decided — with a
  plain-language summary, since the three routinely disagree.

### Changed

- Dashboard names the tool that produced the export rather than saying "the scanner".
  `sniff_tabular_scanner()` recognises Snyk, Tenable Nessus, Qualys, Rapid7 InsightVM, Wiz,
  Prisma Cloud, Trivy and Dependabot exports by the columns only that tool emits, and every
  signature needs at least two of them so a stray "Plugin ID" in a hand-made spreadsheet
  cannot make a report claim the data came from Nessus. Unrecognised exports still read
  "Scanner". Purely cosmetic: nothing in the model branches on it.
- Dashboard: dropped the "Highest exposure" findings table. It grew with the scan and on a
  real run pushed the page past 40 KB while duplicating the workbook's Findings and Action
  Plan sheets, which are the right place to read individual rows. The page is now a fixed
  size regardless of scan volume.

### Fixed

- Dashboard escaped everything except the scanner name, which reaches the page from the
  export and so could carry markup. Escaped, with a test that drives hostile strings through
  the real path: asset name, owner, business unit, title and scanner name all sourced from
  untrusted input.
- `scanner_band()` bucketed values that `float()` accepts but CVSS does not. `nan` compares
  False against every threshold and fell through to "None"; `inf` cleared the Critical
  threshold; negatives were silently swallowed. Only a score between 0 and 10 becomes a
  band now, so an odd value surfaces instead of being hidden, which is what the function
  already claimed to do.
- Tabular intake mapped `raw_severity` to the wrong column whenever an export carried both
  a finding severity and an asset criticality. `criticality` was a severity alias and the
  longest-alias-first tiebreak made it beat `severity`, so a Snyk export recorded
  `PROJECT_CRITICALITY` — the project's business-criticality tag — as the finding's
  severity. `criticality` is no longer a severity alias (asset criticality is modelled
  separately as tier) and the common explicit spellings are matched first.
- `vulnometry --version`, the MCP `serverInfo` handshake and the OpenAPI document all
  reported 0.1.0 on a 0.2.0 install: `__version__` is a second copy of the number in
  `pyproject.toml`, and the 0.2.0 release bumped one and not the other. A test now fails
  the build when the two disagree.
- Dashboard: the Critical/High/Other headers on the rankings table were centred over
  right-aligned counts, so no column lined up.

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
