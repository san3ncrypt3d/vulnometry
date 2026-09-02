## What this changes

<!-- One or two sentences. -->

## Why

<!-- The problem, not the patch. -->

## Checklist

- [ ] `pytest -q` passes
- [ ] New behaviour has a test
- [ ] If this changes the exposure model, `MODEL_VERSION` in `src/vulnometry/exposure.py` is bumped and `docs/SCORING.md` is updated
- [ ] If this adds an action, it is in `src/vulnometry/registry.py` only; no surface hard-codes a schema
- [ ] Any new feed failure mode degrades into `gaps`, rather than raising
