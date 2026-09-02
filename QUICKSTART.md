# Quickstart

By the end of this you will have scored a real CVE against a description of your own systems,
and turned a scanner export into a prioritised action plan. Budget about ten minutes.

Steps 1 and 2 work offline. From step 3 onwards you need internet access, because vulnometry
queries public vulnerability feeds.

## 1. Install

You need Python 3.10 or newer. Check with `python3 --version`.

```bash
pip install vulnometry
```

If you would rather work on the code, clone it instead. The install script creates a virtualenv
in `.venv`, installs the package and runs the tests:

```bash
git clone https://github.com/san3ncrypt3d/vulnometry.git
cd vulnometry
./install.sh                   # Windows: .\install.ps1
source .venv/bin/activate      # Windows: .venv\Scripts\activate
```

> If you installed into a virtualenv, the `vulnometry` command only exists while that
> environment is active. Open a new terminal and you will need to activate it again, or you
> will get "command not found".

## 2. Confirm it works

```bash
vulnometry --version
```

That needs no network and no configuration. If you cloned the repository, you can also run the
test suite:

```bash
pytest -q
```

Expect `58 passed` in well under a second. Those tests use synthetic data and never touch the
network, so they work on a plane.

## 3. Confirm it can reach the feeds

```bash
vulnometry doctor
```

This checks the five public data sources, your credentials, your inventory and any model
providers. You want all five feeds reporting `ok`:

```
nvd         ok
epss        ok
cisa-kev    ok
osv         ok
ghsa        ok
```

A failure here is almost always a corporate proxy or a rate limit rather than a bug. Two free
credentials make a large difference:

```bash
export NVD_API_KEY=...      # https://nvd.nist.gov/developers/request-an-api-key
export GITHUB_TOKEN=...     # any GitHub token, no scopes required
```

Without the NVD key you are capped at 5 requests per 30 seconds, so anything beyond about 20
CVEs will crawl. Neither key is required to continue.

## 4. See what it does, using the example estate

Before describing your own systems, try the worked example estate:

```bash
curl -O https://raw.githubusercontent.com/san3ncrypt3d/vulnometry/main/examples/vulnometry.yaml
vulnometry compare CVE-2021-44228
```

If you cloned the repository, it is already there as `examples/vulnometry.yaml`.

`compare` takes one CVE and scores it against every asset in the inventory:

```
CVE-2021-44228: one CVE, 3 answers
Asset            BEI  Verdict     Threat  Reach  Conseq.  Due
checkout-api   928.9  Contain       1.00   0.90     1.00  2026-09-04
internal-wiki  164.5  Schedule      1.00   0.16     0.41  2027-01-06
ml-sandbox       0.0  Accept        1.00   0.00     0.22  -
```

Reading it left to right:

- **BEI** is the Business Exposure Index, 0 to 1000. It is `Threat x Reachability x Consequence`,
  so a zero in any factor takes the whole score to zero.
- **Verdict** is what to do: Contain (>= 700, now), Remediate (>= 400, this sprint),
  Schedule (>= 150, next window), Accept (below that).
- **Threat** is identical on all three rows, because it is a property of the CVE, not of you.
  The entire spread comes from reachability and consequence, which are properties of your estate.
- **Due** is derived from the verdict and your policy, not from the score alone.

To see the reasoning behind a single number:

```bash
vulnometry measure CVE-2021-44228 --asset checkout-api
```

That prints every factor with the evidence that produced it, so you can check the arithmetic or
argue with it.

## 5. Describe what you actually run

This is the step that makes the tool worth using. Without it, everything is scored with
pessimistic defaults and marked "unattributed".

```bash
rm vulnometry.yaml              # remove the example first
vulnometry inventory init       # writes a commented template
```

Open `vulnometry.yaml` and describe a few systems. Only `name` is required:

```yaml
assets:
  - name: checkout-api
    tier: 1                             # 1 mission-critical, 2 important, 3 supporting
    internet_exposed: true
    data_classification: restricted     # public | internal | confidential | restricted
    regimes: [pci-dss]
    owner: payments@example.com
    components: ["org.apache.logging.log4j*"]

  - name: ml-sandbox
    tier: 3
    internet_exposed: false
    deployed: false                     # takes exposure to zero
```

Leave a field out rather than guessing. Unknown is treated as uncertainty, which scores higher
than a confident wrong answer, and that is the safer direction to be wrong in.

Start small. Three or four assets that matter is far more useful than an empty file, and you can
grow it as you go. Check what parsed:

```bash
vulnometry inventory show
```

Vulnometry picks up `vulnometry.yaml` from the working directory automatically. Keep it wherever
you run the tool, or pass `--inventory /path/to/file`.

## 6. Measure something real

```bash
vulnometry compare CVE-2021-44228

vulnometry measure CVE-2021-44228 --lens forensic

vulnometry watch --days 7 --measure      # what was just confirmed as exploited

vulnometry sweep requirements.txt        # your own dependencies
```

`--lens` controls how much evidence to gather:

| Lens | Uses | When |
|---|---|---|
| `signal` (default) | CVE record, EPSS, KEV | Bulk work, thousands of rows |
| `full` | adds OSV and GHSA | When you want the fix version |
| `forensic` | adds public exploit search | Investigating one finding properly |

You can also override the inventory for a one-off question, which is handy for
"what if this were on the gateway":

```bash
vulnometry measure CVE-2021-44228 --tier 1 --internet-exposed --data restricted --regime pci-dss
```

## 7. Run it over a scanner export

Point it at any export you already have.

```bash
vulnometry import scan.xlsx --preview
```

Always start with `--preview`. It shows which columns were detected and costs no API calls, so
you find out straight away if the CVE column was missed. When it looks right:

```bash
vulnometry import scan.xlsx
```

That writes an annotated workbook and an HTML dashboard into the current directory, named after
the input file (`scan-assessed.xlsx` and `scan-dashboard.html`). The workbook has
four sheets: every finding, an action plan sorted by due date, a per-owner workload view, and a
Method sheet explaining how the numbers were produced.

Reads `.xlsx`, `.xls`, `.csv` and `.tsv`, plus native JSON from Trivy, Grype, Snyk, OSV-Scanner,
Dependabot and SARIF.

Open the generated `*-dashboard.html` in any browser. It is a single self-contained file with no
scripts and no external requests, so it is safe to email to someone who will never open a
terminal.

## 8. Wire it into CI (optional)

```bash
vulnometry import scan.xlsx --fail-on contain
```

`--fail-on` exits non-zero when anything reaches the given verdict, so the build fails on
findings that are genuinely exposed rather than on every high CVSS score in a dev dependency.
It is available on `measure` and `import`.

For dependency scanning, `sweep` has no `--fail-on`; filter with `--min-index` and check whether
anything came back. There is a ready-made workflow doing exactly that in
[`examples/ci-workflow.yml`](https://github.com/san3ncrypt3d/vulnometry/blob/main/examples/ci-workflow.yml).

## 9. Wire it into an AI client (optional)

Everything above works with no model at all. If you want one to narrate results:

**Claude Code, Claude Desktop, Cursor, Zed, Cline:**

```bash
claude mcp add vulnometry -- vulnometry serve mcp
```

Start the client from the directory holding your `vulnometry.yaml` so the inventory is picked up.
Run `/mcp` to confirm it shows as connected, then ask something like
*"What do we run, and is CVE-2021-44228 urgent for any of it?"*

For other clients, [`examples/mcp_config.json`](https://github.com/san3ncrypt3d/vulnometry/blob/main/examples/mcp_config.json) has the equivalent JSON.

**Talking to a model directly:**

```bash
vulnometry providers            # what is configured
vulnometry providers --probe    # what actually answers

vulnometry ask "what must ship before Friday?" --model ollama:qwen3
```

A model never computes a score. It reads the same numbers you see and explains them.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `command not found: vulnometry` | The virtualenv is not active. Run `source .venv/bin/activate`. |
| `doctor` shows nvd failing | A proxy, or one of NVD's periodic outages. The CVE Program fallback covers it. |
| Everything is slow | No `NVD_API_KEY`, so you are capped at 5 requests per 30 seconds. |
| `ghsa` failing | No `GITHUB_TOKEN`. Unauthenticated limits are very low. |
| Findings all say "unattributed" | No inventory loaded. Run `vulnometry inventory init` and describe a few assets. |
| Import finds no CVEs | Run `vulnometry import FILE --preview` to see which columns were detected. |
| Scores look too high | Expected for assets you have not described. Unknown context is treated as uncertainty. |
| `ModuleNotFoundError: yaml` | The install did not finish. Re-run `pip install vulnometry`, or `pip install -e ".[dev]"` from a clone. |

## Where next

- [README.md](README.md) for the full feature set and command reference.
- [docs/SCORING.md](docs/SCORING.md) for where every weight and exponent comes from. Read this
  before arguing with a score, then argue with it anyway.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) if you want to add a feed, a scanner format or an
  action.
- `vulnometry --help`, or `vulnometry <command> --help`, for everything else.
