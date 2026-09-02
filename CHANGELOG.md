# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semantic versioning](https://semver.org/), with the addition
that any change to the exposure model bumps `MODEL_VERSION` independently.

## [Unreleased]

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
