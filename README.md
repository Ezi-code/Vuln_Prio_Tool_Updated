# Vulnerability Prioritisation Tool

## Overview

This project investigates how vulnerability severity, exploitability
intelligence, and asset criticality can be combined to improve vulnerability
patch prioritisation in resource-constrained organisations. It compares the
integrated model with single-factor baselines under limited remediation budgets.

**Research question:** How does integrating vulnerability severity,
exploitability intelligence, and asset criticality affect prioritisation
effectiveness compared with single-factor approaches in resource-constrained
organisations?

## Priority categories

The four asset-criticality tiers are the operational priority categories:

| Asset tier | Criticality score | Operational queue |
|---|---:|---|
| Critical | 10–12 | Patch now |
| High | 7–9 | Patch next |
| Medium | 4–6 | Scheduled |
| Low | 0–3 | Monitor |

There is no separate three-level threat taxonomy. The same instrument is used
by Stage 2 of the model; a three-label view is display-only if one is needed for
a slide.

## Model

1. **Stage 1 — candidate gate.** A CVE passes if it is in CISA KEV at the cutoff
   or its EPSS is at or above the frozen threshold. The gate is a candidate
   pool, not the final patch list.
2. **Stage 2 — asset criticality.** Candidates are ordered by asset tier.
3. **Stage 3 — severity tie-break.** Within a tier, higher CVSS first; remaining
   ties use EPSS.

The final list has its own capacity. This separation matters when the candidate
gate is wider than the operational budget.

## Evaluation protocol

- Primary operational budget: **10%**.
- Workload sensitivity: **20%** and **30%**.
- Capacity-constrained secondary analysis: **2%** and **5%**.
- Confirmatory metrics use CVEs that were not in KEV at the cutoff (new
  exploitation). Operational rankings include KEV-at-cutoff CVEs and rank them
  first.
- The 2024-06-30 → 2025-06-30 period has already been inspected. Treat those
  results as descriptive. The untouched 2025-06-30 → 2026-06-30 period is the
  planned confirmatory holdout.

See [`docs/THESIS_PROTOCOL.md`](docs/THESIS_PROTOCOL.md) for the full protocol,
freeze rules, and limitations.

## Project structure

```text
data/
  inventories/          example inventories (CSV)
  processed/            vulnerability data
  manifest.json         hashes, provenance notes, validation warnings
docs/
  THESIS_PROTOCOL.md    evaluation protocol and decisions
  USABILITY_TEST.md     practitioner instrument study
  OPTIMIZATION.md       model-optimisation notes
results/                ranked lists and evaluation summaries
src/
  assets.py             criticality instrument and CVE matching
  model.py              Stage 1 gate and ranking
  scoring.py            operational ranked lists and tier queues
  evaluate_model.py     evaluation against baselines
  montecarlo.py         synthetic-inventory Monte Carlo
  ingest.py             NVD, EPSS and KEV ingestion with provenance
  validate_data.py      schema, leakage and manifest checks
templates/
  asset_inventory_template.csv
  criticality_questionnaire.md
model_config.json       frozen model configuration
stage1_config.json      frozen Stage 1 configuration
```

## Installation

```bash
git clone https://github.com/Ezi-code/Vuln_Prio_Tool_Updated.git
cd Vuln_Prio_Tool_Updated
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

This repository uses the `uv` runner in the examples below. A normal virtual
environment with `pandas` and `numpy` installed works as well.

## Quick start

Evaluate the model at the primary 10% budget and the 20%/30% sensitivity
budgets:

```bash
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --budgets 0.10,0.20,0.30 --budget 0.10 \
    --outdir results/thesis_primary
```

Run the capacity-constrained secondary analysis:

```bash
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --budgets 0.02,0.05,0.10 --budget 0.10 \
    --outdir results/thesis_capacity
```

Generate operational lists with one CSV per tier:

```bash
uv run --with pandas --with numpy python src/scoring.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --capacity 500 --top 100 --tier-capacity 100 \
    --outdir results/operational
```

`--capacity` is the final-list size. Leave it unset to write the full ranked
list. `--gate-share` optionally replaces the fixed Stage 1 threshold with a
per-inventory top-*q*% gate; use it only as a clearly labelled sensitivity
analysis.

The same command writes three exploit-focused outputs per inventory:

- `exploits_by_tier_<inventory>.csv` — one row per asset tier, with counts of
  known-exploited CVEs, EPSS-gated CVEs, affected assets, and the top CVEs;
- `asset_exploits_<inventory>.csv` — one row per (asset, CVE) that needs
  action, including `asset_tier`, `priority_queue`, `exploit_status`, and
  `fix_action`;
- `exploit_report_<inventory>.md` — a readable report grouped by asset tier and
  then by individual asset.

`needs_fixing` is true when a CVE is in CISA KEV at the cutoff or passes the
EPSS candidate gate. The after-cutoff evaluation label is not used for the
operational fix decision.

Validate the data and write a manifest:

```bash
uv run --with pandas python src/validate_data.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --write-manifest data/manifest.json
```

Run the tests:

```bash
uv run --with pandas --with numpy --with pytest pytest -q
```

## Inventory template

Start from [`templates/asset_inventory_template.csv`](templates/asset_inventory_template.csv).
Only these columns are required:

- `asset_id`, `asset_name`, `software`
- `exposure`, `data_sensitivity`, `business_function`, `redundancy`

Optional operational columns are `owner`, `patchable`, `maintenance_window`,
`compensating_control`, and `notes`. `software` uses semicolon-separated
`vendor:product` tokens. The four required scores are 0–3 each; the
criticality score is the sum and the tier follows the table above.

Unpatchable assets keep their criticality tier. Record `patchable=no` and the
compensating control; do not lower the tier because patching is difficult. See
[`templates/criticality_questionnaire.md`](templates/criticality_questionnaire.md)
for the anchors and worked examples.

## Data and reproducibility

- `data/manifest.json` records file hashes, row counts, inventory schema, and
  validation warnings.
- `src/ingest.py` records the EPSS snapshot date, EPSS model version, KEV
  release, NVD window, output hash, and row counts in a `.meta.json` sidecar.
- The current processed files predate snapshot sidecars. Rebuild them before a
  confirmatory claim; the manifest states the limitation rather than guessing a
  snapshot date.
- `model_config.json` and `stage1_config.json` are frozen. Do not edit them to
  improve a result.

## Limitations

The results depend on vulnerability-intelligence quality, the asset inventory,
the selectable budget, and the evaluation assumptions. The synthetic
inventories are not a probability sample of real organisations. Later-exploited
CVEs are rare, so intervals are wide. The tool supports research and
decision-making; it does not replace professional security assessment or an
organisation's patch-management policy.

## Further reading

- [`docs/THESIS_PROTOCOL.md`](docs/THESIS_PROTOCOL.md) — evaluation protocol,
  asset-tier decision, holdout discipline, and commands.
- [`docs/USABILITY_TEST.md`](docs/USABILITY_TEST.md) — practitioner study.
- [`docs/OPTIMIZATION.md`](docs/OPTIMIZATION.md) — optimisation history and
  current descriptive results.
