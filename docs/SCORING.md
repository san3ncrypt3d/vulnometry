# The exposure model

The model is one line:

```
BEI = 1000 · Threat^0.8 · Reachability^0.7 · Consequence^0.6
```

This document explains where every part of that comes from, so you can argue
with it. The weights are defensible defaults, not empirical constants.

---

## Why multiply instead of add

Almost every prioritisation scheme is a weighted sum: some CVSS, some EPSS, a
bonus for KEV, maybe a nudge for asset criticality. Sums have a specific failure
mode. A large enough score in one term carries the finding regardless of the
others, so a CVSS 9.8 in a library you do not deploy still lands near the top of
the queue. Teams then patch lab machines while something dull sits on the
payment gateway.

Multiplication makes each factor a veto. If nobody can reach it,
reachability is near zero and the product collapses no matter how frightening
the CVSS score. This needs no special-case rule. There is no "if not
deployed then override" branch anywhere in the code, because the arithmetic
already says it. That matters in a review meeting: you cannot argue about an
exception that does not exist.

The cost is that multiplicative models are unforgiving of missing data, which is
why unknown context is treated as *uncertainty* (a discount) rather than as
*absence* (a zero). See "Unknowns" below.

## Why the exponents

Raw multiplication of three fractions produces very small numbers. A finding
scoring a middling 0.5 on all three would land at 125/1000 and look negligible,
when in fact "moderately likely, moderately reachable, moderately damaging" is a
real problem.

The exponents are all below 1, which pulls each factor toward 1.0 and softens
that collapse. They do not change the ordering within a factor; they change how
steeply the factors trade off against each other.

They are not equal:

| Factor | Exponent | Reasoning |
|---|---|---|
| Threat | 0.8 | Weighted hardest because it is the factor most likely to change tomorrow. A CVE with no exploit today can be in KEV next week. |
| Reachability | 0.7 | Second. It is knowable and fairly stable, and it is where most of the false urgency is eliminated. |
| Consequence | 0.6 | Softest, because it is the factor you are least likely to have recorded accurately, and over-weighting it turns the tool into a tier-1 alarm bell. |

---

## Threat: will anyone try?

Range 0.02 to 1.0. Alternative answers to one question, so the strongest
signal wins rather than accumulating.

**CISA KEV listing → 1.0, immediately.** Observation beats prediction. There is
no partial credit here: if exploitation has been confirmed in the wild, the
question "will anyone try" is settled.

**Otherwise, the greater of:**

- **EPSS, on a concave curve:** `probability ^ 0.35`. The move from 1% to 10%
  changes a decision; the move from 80% to 90% does not. A linear treatment
  gives the second jump the same weight as the first, which is backwards.
- **Exploit maturity:** weaponised 0.78, proof-of-concept 0.55, referenced 0.35.
  "Weaponised" means the discovered artifact looks packaged for reuse, such as a
  Metasploit module or Nuclei template, rather than a one-off script. A very
  popular repository adds a small bump, capped at 0.85.

**No evidence at all → 0.08**, not zero. Absence of a public exploit is not
absence of threat.

**A missing EPSS score is recorded as a gap, not as a low score.** It usually
means the CVE is too new for the model to have scored it, which is the opposite
of reassuring.

## Reachability: can they get to it *here*?

Range 0 to 1. This is the factor that generic feeds cannot compute, and the
reason the inventory exists.

Starts from the CVSS attack vector (network 1.0, adjacent 0.45, local 0.2,
physical 0.05), then applies multipliers:

| Condition | Multiplier |
|---|---|
| High attack complexity | ×0.7 |
| Requires low privileges | ×0.8 |
| Requires high privileges | ×0.55 |
| Requires user interaction | ×0.75 |
| Asset not internet-exposed | ×0.4 |
| Internet exposure unknown | ×0.7 |
| Deployment unconfirmed | ×0.9 |
| Compensating controls present | ×0.45 |
| **Component not deployed** | **→ 0, immediately** |

Compensating controls are deliberately a large discount but not a zero. A WAF
virtual patch genuinely reduces reachability; treating it as a fix is how people
get breached through the one request the rule did not match.

## Consequence: what does it cost us?

Range 0.02 to 1.0.

Starts from the **CVSS impact sub-metrics** (C/I/A), not the base score. The base
score blends consequence with exploitability, which double-counts things already
captured in reachability. Where sub-metrics are absent we fall back to the base
score and say so.

The impact fraction weights the worst single impact at 70% and the average of
all three at 30%. Total compromise of confidentiality alone is worse than three
partial impacts, even though a naive average would rank them equally.

Then, from your inventory:

| Input | Weight |
|---|---|
| Tier 1 (mission-critical) | ×1.0 |
| Tier 2 (business-important) | ×0.72 |
| Tier 3 (supporting) | ×0.45 |
| Tier unknown | ×0.65 |
| Restricted data | ×1.15 |
| Confidential | ×1.0 |
| Internal | ×0.85 |
| Public | ×0.7 |
| In regulatory scope (PCI, HIPAA, SOX, GDPR, ...) | ×1.12 |
| Production environment | ×1.08 |
| Development environment | ×0.7 |

Regulatory scope adds only 12% to the score. It does considerably more to the
**due date**, which is where a compliance obligation actually bites.

---

## Verdicts and dates

| BEI | Verdict | Meaning |
|---:|---|---|
| ≥ 700 | **Contain** | Act now, outside the normal change process |
| ≥ 400 | **Remediate** | Fix within this sprint, ahead of the routine cycle |
| ≥ 150 | **Schedule** | Queue for the next planned maintenance window |
| < 150 | **Accept** | No action warranted; record the decision and move on |

Due dates are policy, derived from the verdict and the asset:

```
base:      Contain 7d · Remediate 30d · Schedule 90d
tier 1     × 0.5
tier 3     × 1.75
regulated  × 0.6
production × 0.8
```

So a Contain verdict on a tier-1, PCI-scope, production asset is 7 × 0.5 × 0.6 ×
0.8 ≈ **2 days**. The same verdict on a tier-3 internal box is about 12. These
live in `src/vulnometry/inventory.py` and are meant to be edited to match your own
remediation policy.

## Unknowns

Every unknown is a discount, never a zero, and never an optimistic assumption:

- Unknown tier scores between tier 1 and tier 3, nearer the middle.
- Unknown internet exposure is discounted 30%, versus 60% for known-internal.
- Unknown deployment is discounted 10%.

Vulnometry will therefore over-score an asset you have not described. That is
deliberate. The alternative, silently treating undescribed assets as safe,
loses findings, which is the more expensive mistake.

`confidence` reports how much of the picture was actually available: `high` when
the CVE record, EPSS score and asset context are all present, `low` when two or
more are missing. Treat a low-confidence number as provisional.

## Versioning

`MODEL_VERSION` in `src/vulnometry/exposure.py` is stamped into every measurement.
Any change to weights, exponents or thresholds bumps it, so historical results
remain interpretable and you can tell whether a score moved because the world
changed or because we did.

## What this model does not do

- It does not verify that the vulnerable code path is reachable in your
  deployment. That is function-level reachability analysis, and commercial tools
  do it by reading your call graph. Vulnometry reasons about network and deployment
  reachability from your inventory, which is coarser.
- It does not know about your patch history, change freeze windows, or which
  team is on holiday.
- The weights are not derived from breach data. Nobody's are, publicly. They are
  reasoned defaults, and the "How this was measured" output exists so you can
  see exactly which one you disagree with.
