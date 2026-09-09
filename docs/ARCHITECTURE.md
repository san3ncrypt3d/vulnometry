# Architecture

The shape of the codebase, and the two rules that keep it that way.

## The two rules

**1. One registry, many surfaces.** Every action lives in `src/vulnometry/registry.py`
and nowhere else. MCP, OpenAI function calling, Bedrock Converse, Gemini, the
HTTP service and the CLI are all generated from it. No surface hard-codes a
schema. Adding an action makes it available everywhere simultaneously.

**2. No model produces a number.** Scoring is deterministic and reproducible. An
LLM can explain a verdict; it can never compute one. This is why every command
except `vulnometry ask` works with no inference stack installed at all.

## Layout

```
src/vulnometry/
├── schema.py        Domain types. Weakness, Assessment, ExposureMeasure...
├── config.py        Settings from the environment. Everything optional.
├── net.py           Token buckets, retries, SQLite feed cache.
│
├── inventory.py     Business context: assets, tiers, owners, SLA policy.
├── inventory_import.py  Build an inventory from an arbitrary CSV/XLSX export + a mapping file.
├── exposure.py      The BEI model. See docs/SCORING.md.
├── assessment.py    Orchestrator: fan out to feeds, measure, attach context.
│
├── feeds/           Public data. One module per question.
│   ├── record.py        NVD, falling back to the CVE Program CNA record
│   ├── probability.py   FIRST EPSS
│   ├── catalogue.py     CISA KEV
│   └── advisories.py    OSV + GHSA (fix versions) and exploit discovery
│
├── intake/          Whatever your tools produce -> finding dicts
│   ├── tabular.py       xlsx/csv with header detection
│   ├── scanners.py      Trivy, Grype, Snyk, OSV-Scanner, Dependabot, SARIF
│   └── manifests.py     lockfiles and SBOMs
│
├── report/          Output surfaces
│   ├── console.py       terminal, json, markdown, csv
│   ├── workbook.py      annotated four-sheet xlsx
│   └── dashboard.py     self-contained HTML, inline SVG, zero JS
│
├── providers/       Inference, normalised to one interface
│   ├── base.py          Message / ToolCall / ChatResponse
│   ├── openai_compat.py OpenAI, Ollama, Azure, vLLM, llama.cpp, OpenRouter...
│   ├── anthropic.py  bedrock.py  gemini.py
│   └── __init__.py      model-spec parsing, provider registry
│
├── registry.py      THE ACTION REGISTRY. Single source of truth.
├── analyst.py       The tool-calling loop, written once, vendor-free.
├── surfaces/
│   ├── mcp.py           stdio JSON-RPC, no SDK dependency
│   ├── schemas.py       export the registry in each vendor's dialect
│   └── service.py       FastAPI + OpenAPI
└── cli.py
```

## Data flow

```
scanner export ─┐
lockfile / SBOM ├─> intake ─> [{cve, asset, host, component}]
CVE ids on stdin┘                        │
                                         v
                              inventory.resolve()          <- vulnometry.yaml
                                         │
                                         v
              feeds (concurrent) ─> assessment ─> exposure ─> Assessment
              NVD EPSS KEV OSV GHSA          │
                                             v
                              console │ workbook │ dashboard │ json
```

## Design decisions worth knowing

**Feed failures are isolated, never fatal.** Each feed is fetched inside a guard
that records the problem in `Assessment.gaps` and returns an empty value. A dead
NVD costs you CVSS, not the report. Missing evidence lowers `confidence` rather
than silently scoring as zero.

**The cache is a correctness feature.** The KEV catalogue is a single ~2 MB
document. A 4,000-row import must fetch it once. Without the SQLite cache, bulk
analysis is impossible at polite request rates.

**Client-side rate limiting.** Per-host token buckets throttle us before the
upstream does. NVD gets 5 req/30s anonymous, 50 with a key, and the bucket is
sized accordingly at startup.

**Actions return errors as data.** `invoke()` never raises. A tool-calling model
recovers gracefully from `{"error": "..."}`; it cannot recover from a dropped
connection.

**MCP is hand-rolled.** It is JSON-RPC 2.0 over stdin/stdout, and a tools-only
server needs three methods. Implementing them directly keeps the dependency
list at four packages and avoids SDK churn.

**Tri-state booleans everywhere.** `internet_exposed` is `True`, `False` or
`None`, and all three mean different things to the model. Collapsing unknown
into false is how findings get lost.

## Testing

58 tests, all offline. Rather than mocking functions, `tests/test_pipeline.py`
primes the SQLite feed cache with synthetic upstream payloads, so cache keys,
parsers, the exposure model, SLA policy and rendering are all genuinely
exercised. Only the socket is replaced. CI therefore never depends on NVD
being up.

`tests/test_exposure.py` gets the most attention, because the model is the
product. The tests assert behaviour, not constants: that context can veto, that
threat is asset-independent, that severe-but-unreachable ranks below
mild-but-exploited.
