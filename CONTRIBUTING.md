# Contributing

## Getting set up

```bash
git clone https://github.com/san3ncrypt3d/vulnometry.git
cd vulnometry
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

The suite is entirely offline (it primes the feed cache with synthetic
payloads), so it runs in a couple of seconds and works on a plane.

## The two rules

Almost every review comment comes back to one of these.

**Actions go in `src/vulnometry/registry.py` and nowhere else.** MCP, the OpenAI
schema, Bedrock, Gemini, the HTTP service and the CLI are all generated from
that one list. If you find yourself writing a schema inside a surface, stop.

**No model computes a number.** Scoring stays deterministic. An LLM may narrate
a verdict, never produce one. Every command except `vulnometry ask` must keep working
with no inference stack installed.

## What is most welcome

**Scoring disputes.** These are the best issues this project gets. The weights
in `exposure.py` are reasoned defaults, not empirical constants, and they should
be argued with. Open a "Scoring dispute" issue with the `vulnometry measure` output.
The "How this was measured" block usually shows exactly where we disagree.

**New scanner formats.** `src/vulnometry/intake/scanners.py` is a dictionary of small
parsers. Add a `sniff` clause and a function, plus a test with a realistic
sample. Redact anything sensitive from the sample first.

**Column aliases.** `COLUMN_ALIASES` in `intake/tabular.py` decides whether
somebody's Excel export parses on the first try. If your vendor uses a header we
do not recognise, that is a one-line contribution.

**New feeds.** One module in `feeds/`, returning `schema` types and raising
`FeedError`. It must degrade into `gaps` rather than failing the assessment.

## Standards

- Every new behaviour gets a test. Assert behaviour, not constants:
  `assert exposed.index > internal.index`, not `assert index == 928.9`, so the
  suite survives a weights change that is genuinely an improvement.
- Feed failures degrade; they never raise out of `assess_finding`.
- Changing the exposure model means bumping `MODEL_VERSION` and updating
  `docs/SCORING.md`. Historical measurements have to stay interpretable.
- `ruff check src tests` is clean.
- Comments explain *why*, not *what*. The code already says what.

## Releasing

1. Update `CHANGELOG.md`.
2. Bump the version in `pyproject.toml` and `src/vulnometry/__init__.py`.
3. Tag: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push --tags`. Pushing the tag is what
   publishes to PyPI, via trusted publishing in `.github/workflows/release.yml`. The
   workflow refuses a tag that does not match the version in `pyproject.toml`.
4. Create the GitHub release and paste the matching `CHANGELOG.md` section as the notes.
