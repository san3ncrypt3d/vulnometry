# Importing the inventory from an asset export

Most teams already keep a list of what they run: a CMDB extract, an application
register, a spreadsheet security maintains by hand. Its columns never match
vulnometry's field names. Rather than retyping it, point vulnometry at the export
and a **mapping file** that says which column is which.

```bash
# freeze the export into a reviewable vulnometry.yaml
vulnometry inventory import assets.csv --map mapping.yaml -o vulnometry.yaml

# or skip the file and use the export directly wherever an inventory is read
vulnometry import scan.xlsx --inventory assets.csv --inventory-map mapping.yaml
vulnometry compare CVE-2021-44228 --inventory assets.csv --inventory-map mapping.yaml
```

`.csv`, `.tsv` and `.xlsx` exports are supported. CSV is decoded as UTF-8, then
Windows-1252, then Latin-1, so exports straight out of Excel work.

---

## A worked example

The files in [`examples/`](../examples) run end to end:

```bash
vulnometry inventory import examples/asset-export.csv \
  --map examples/inventory-mapping.yaml -o vulnometry.yaml --overwrite
```

### The export — `examples/asset-export.csv`

Eight services, with headers that are nothing like vulnometry's:

| Service | Team Contact | Tier | Data Sensitivity | Regulations | Environment URLs | Snyk Targets | Repo | Internet | Handles Card Data | Status |
|---|---|---|---|---|---|---|---|---|---|---|
| storefront-web | web-guild@… | Tier 1 | Confidential | PCI-DSS; GDPR | `https://shop.northwind.example https://shop.eu.northwind.example` | `northwind/storefront-web:package.json` | github.com/northwind/storefront-web | yes | yes | Production |
| checkout-api | payments@… | Tier 1 | Restricted | PCI-DSS | `https://api.northwind.example/checkout` | `northwind/checkout-api:pom.xml`<br>`northwind/checkout-api-e2e:package.json` | github.com/northwind/checkout-api | yes | yes | Production |
| warehouse-sync | ops@… | Tier 2 | Internal | | | `northwind/warehouse-sync:go.mod` | github.com/northwind/warehouse-sync | no | no | Production |
| analytics-dashboard | data@… | Tier 3 | Internal | GDPR | `https://analytics.northwind.example` | | github.com/northwind/analytics-dashboard | no | no | Production |
| partner-portal | partnerships@… | Tier 2 | Confidential | GDPR | `https://partners.northwind.example` | `northwind/partner-portal:yarn.lock` | github.com/northwind/partner-portal | **Partner** | no | Production |
| internal-wiki | it@… | Tier 3 | Internal | None | `https://wiki.corp.northwind.example` | | github.com/northwind/internal-wiki | no | no | Production |
| legacy-invoicing | *(blank)* | *(blank)* | Confidential | SOX | `http://invoicing.corp.northwind.example` | | github.com/northwind/legacy-invoicing | no | no | Decommissioned |
| ml-sandbox | ml@… | Tier 3 | Public | None | | | github.com/northwind/ml-sandbox | no | no | Planned |

### The mapping — `examples/inventory-mapping.yaml`

```yaml
columns:
  name:                [Service, Application, App Name]
  owner:               [Owner, Team Contact]
  tier:                [Criticality, Tier]
  data_classification: [Data Sensitivity, Classification]
  regimes:             Regulations
  hosts:               Environment URLs
  aliases:             [Snyk Targets, Repo]
  internet_exposed:    [Internet, Public, Customer Facing]
  deployed:            Status

values:
  tier:                {"tier 1": 1, "tier 2": 2, "tier 3": 3}
  data_classification: {restricted: restricted, confidential: confidential, internal: internal, public: public}
  regimes:             {"pci-dss": pci-dss, gdpr: gdpr, sox: sox}
  deployed:            {production: "true", active: "true", decommissioned: "false", retired: "false"}

transforms:
  regimes:          split_delimited
  aliases:          split_lines
  hosts:            extract_hosts
  internet_exposed: any_affirmative
  deployed:         mapped
```

### The result — `examples/inventory-from-export.yaml`

```yaml
- name: storefront-web
  tier: 1
  owner: web-guild@northwind.example
  internet_exposed: true
  deployed: true
  data_classification: confidential
  regimes: [pci-dss, gdpr]
  hosts: [shop.northwind.example, shop.eu.northwind.example]
  aliases: [northwind/storefront-web:package.json, github.com/northwind/storefront-web]

- name: legacy-invoicing            # blank Tier -> no 'tier' key at all
  internet_exposed: false
  deployed: false                   # Status "Decommissioned" -> exposure will collapse to 0
  data_classification: confidential
  regimes: [sox]
  hosts: [invoicing.corp.northwind.example]
  aliases: [github.com/northwind/legacy-invoicing]

- name: ml-sandbox                  # Status "Planned" -> 'deployed' left unknown, not false
  tier: 3
  owner: ml@northwind.example
  internet_exposed: false
  data_classification: public
  aliases: [github.com/northwind/ml-sandbox]
```

### How each column was read

| Export column | → field | Mechanism | Note |
|---|---|---|---|
| `Service` | `name` | first non-blank of the candidates | required; a row with no name is skipped |
| `Team Contact` | `owner` | verbatim string | free text; drives the *By owner* workbook sheet |
| `Tier` | `tier` | `values.tier` (`Tier 1` → `1`) | `legacy-invoicing` is blank → left unset (weight 0.65, lower confidence) |
| `Data Sensitivity` | `data_classification` | `values` table | must resolve to public / internal / confidential / restricted |
| `Regulations` | `regimes` | `split_delimited`, then per-token `values` | `None` is dropped; `pci-dss`/`gdpr`/`sox` raise consequence and tighten the due date |
| `Environment URLs` | `hosts` | `extract_hosts` regex | `https://a b https://c` → `[a, c]`; empty cell → no `hosts` key |
| `Snyk Targets` + `Repo` | `aliases` | `split_lines`, both columns concatenated | a Snyk or SARIF finding naming `northwind/checkout-api:pom.xml` now resolves to `checkout-api` |
| `Internet` | `internet_exposed` | `any_affirmative` | `partner-portal` says `Partner` — not blank, not a "no", so treated as **yes** |
| `Status` | `deployed` | `mapped` | only `Production`/`Decommissioned`/… count; `Planned` → unknown |
| `Handles Card Data` | — | not in `columns` | ignored, along with any other unmapped column |

---

## Reference

### Fields you can target

Every field on an asset: `name` (required), `tier`, `owner`, `business_unit`,
`environment`, `internet_exposed`, `deployed`, `data_classification`, `regimes`,
`compensating_controls`, `components`, `hosts`, `aliases`, `notes`.

### Column resolution

- A `columns:` entry is one header name or a list of candidates tried in order.
- Matching normalises case, whitespace and punctuation (`Team Contact` ==
  `team_contact` == `TEAMCONTACT`). It is exact after that — no substring or
  synonym matching. Put every real-world spelling in the candidate list.
- If none of a field's candidates are found, the field is skipped and one
  warning is printed. If none of the `name` candidates are found, the import
  fails.
- Columns not named anywhere in `columns:` are ignored.
- The header row is found by scanning the first 25 rows; a clean export with the
  header on row 1 always works. There is no override for a sheet with a title
  block above the header yet.

### Value translation

| Field | Rule |
|---|---|
| `tier` | `values.tier`, else the built-ins `1/2/3`, `high/medium/low`, `critical/high/moderate/low`. Must land on 1, 2 or 3 — anything else is left unset with a warning. |
| `data_classification` | `values`, else the raw value, lowercased. Must be `public`, `internal`, `confidential` or `restricted` — anything else is left unset with a warning. |
| `regimes` (list) | each token: `values.regimes` if listed, otherwise passed through lowercased. `pci-dss`, `hipaa`, `sox`, `gdpr` change the score; others are recorded only. |
| other list fields | each token: `values.<field>` if listed, otherwise the token unchanged. |
| `owner`, `business_unit`, `environment`, `notes` | `values.<field>` if listed, otherwise verbatim. |
| tri-state (`internet_exposed`, `deployed`) | see transforms below. |

Tokens that mean "nothing recorded" (`none`, `n/a`, `not applicable`,
`not assigned`, `unknown`, `tbd`, `-`, empty) never become list entries.

### Transforms

**List fields** — `split_lines`, `split_delimited` (`;` `,` `/` `|` and
newlines), `split_comma`, `extract_hosts` (pulls `http(s)://` hostnames, or bare
FQDNs if there are no URLs).

**Tri-state fields** — `any_affirmative` (default: yes if any source column is
affirmative; no only if every non-blank value is negative; an unrecognised
non-blank value counts as yes, which over-scores rather than under-scores),
`all_affirmative`, `first` (first non-blank column only), `mapped` (only values
translated to `true`/`false` by `values.<field>` count; everything else,
including blanks, is unknown).

**Booleans** — override the yes/no vocabulary for tri-state fields:

```yaml
booleans:
  true:  [yes, "y", "true", "1", external, live]
  false: [no, "n", "false", "0", internal, retired, ""]
```

Defaults already cover `yes/no`, `y/n`, `true/false`, `1/0` and a few more.

### Re-running: merge vs overwrite

By default a second `inventory import` **merges** into the existing file:

- fields named in `columns:` are refreshed from the export;
- every other field — anything you added by hand, such as
  `compensating_controls` or a manual `deployed: false` — is kept;
- assets in the file but absent from the export are kept and reported;
- the run prints what was added, what changed, and what it left alone.

`--overwrite` replaces the file instead.

### Making findings attach: `aliases`

Scanners name things their own way — a Snyk project, a SARIF `automationId`, a
Jira key. Map those columns to `aliases` and `Inventory.by_name()` resolves
them (globs allowed, e.g. `myorg/*:package.json`), so a finding attaches to the
right asset even when the scan never uses the asset's own name. Without a match,
the finding is scored against pessimistic defaults and flagged unattributed.
