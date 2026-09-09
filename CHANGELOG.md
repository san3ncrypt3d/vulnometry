# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/), with the addition
that any change to the exposure model bumps `MODEL_VERSION` independently.

## [Unreleased]

### Added

- `vulnometry inventory import EXPORT --map MAPPING.yaml`: build the business inventory
  from an arbitrary CSV/XLSX asset export (a CMDB extract, an application register). The
  mapping file names the columns and the value translations; built-in transforms cover
  multi-value cells, host extraction from URLs and tri-state booleans. Re-running merges,
  keeping fields added by hand. Also usable inline: `--inventory EXPORT --inventory-map MAPPING`.
  Template in `examples/inventory-mapping.yaml`.
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
