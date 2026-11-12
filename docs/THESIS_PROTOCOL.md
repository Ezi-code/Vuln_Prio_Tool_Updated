# Thesis evaluation protocol

This document is the working protocol for the confirmatory evaluation. It
records the decisions that must stay fixed while the 2025–2026 holdout is being
prepared and scored. If a choice below changes, record the reason and date before
looking at holdout results.

## 1. Priority categories

The four asset-criticality tiers are the priority categories:

| Asset tier | Score | Operational queue |
|---|---:|---|
| Critical | 10–12 | Patch now |
| High | 7–9 | Patch next |
| Medium | 4–6 | Scheduled |
| Low | 0–3 | Monitor |

There is **no separate Critical/Medium/Low threat taxonomy**. The tier comes
from the same four-question, 0–3 instrument used by Stage 2. A three-label view
can be produced for a slide by grouping the four tiers, but it is display-only
and must not change the model, the metrics, or the ranking.

The tier is an asset property. It is not adjusted for vulnerability severity,
patch difficulty, or whether an asset can be patched. Operational constraints
are recorded separately (`patchable`, `compensating_control`,
`maintenance_window`).

## 2. Budgets

| Role | Final-list share |
|---|---|
| Primary | 10% |
| Workload sensitivity | 20%, 30% |
| Capacity-constrained secondary | 2%, 5% |
| Absolute-capacity check | top-N where N is stated |

The 2% result is an extreme capacity case, not the thesis headline. At 2% the
candidate gate and final list can coincide, which prevents Stages 2 and 3 from
changing membership. Report it as a secondary analysis and say so.

No budget is selected after seeing the holdout results. The primary 10% choice
is part of the protocol.

## 3. Stage 1 gate versus final capacity

Stage 1 is a **candidate gate**, not the final patch list. The final list is
chosen by Stage 2 (asset tier) and Stage 3 (CVSS within tier, then EPSS).

- Primary protocol: keep the frozen Stage 1 rule from `stage1_config.json`
  (`EPSS >= 0.04267`, or KEV at the cutoff), then apply the final 10% capacity.
- Gate-breadth sensitivity: run a wider candidate gate (for example top 20% of
  each inventory's EPSS distribution) and the same final capacity. This tests
  whether Stages 2 and 3 improve the final list when Stage 1 is deliberately
  permissive.
- State the gate and the final capacity separately in every table.

The model must not be credited with a coverage number from the gate size when
the displayed operational list is a different size.

## 4. Evaluation versus operations

- **Confirmatory metrics** use Pool B: CVEs that were not in KEV at the cutoff.
  Labels are KEV additions after the cutoff and up to the horizon end.
- **Operational rankings** include KEV-at-cutoff CVEs and place them first. A
  list that omits already-known exploited CVEs is not usable.
- **Exploit reports** answer "what needs fixing in each asset tier?":
  `exploits_by_tier_<inventory>.csv` summarises known-exploited and
  EPSS-gated CVEs per tier, `asset_exploits_<inventory>.csv` gives one row per
  (asset, CVE) that needs action, and `exploit_report_<inventory>.md` is the
  human-readable tier -> asset -> CVE report.
- `needs_fixing` uses only cutoff-time information: CISA KEV at the cutoff or
  the EPSS candidate gate. It does not use the after-cutoff label.
- Report operational coverage including KEV-at-cutoff separately from
  new-exploitation coverage. Do not compare a coverage number that includes
  KEV-at-cutoff with one that excludes it without saying so.

## 5. Metrics

Primary:

- CVE-level recall (coverage) at the final budget;
- precision at the final budget;
- criticality-weighted recall, with weights 1/2/3/4 for Low/Medium/High/Critical;
- workload reduction versus patch-everything and versus CVSS >= 7.0;
- share of the final list on High/Critical assets;
- per-tier recall and precision (the asset-tier table).

Secondary:

- ranking agreement (Spearman rho, top-N overlap);
- by-sector point estimates;
- threshold and criticality-weight sensitivity;
- runtime and memory.

All comparisons are paired by inventory and resample both inventories and
positive CVEs. A difference is only claimed when its interval excludes zero.
Point estimates are reported with intervals, not as a bare percentage.

## 6. Criticality evidence (RQ2)

The four-tier instrument is supported by four separate pieces of evidence:

1. **Rule-based ablation.** Compare the full model with a criticality-off
   variant (`lam=0` / tier ignored) on the development period. The final list
   must be able to change when criticality is removed.
2. **Criticality-weighted recall.** A model that finds the same number of CVEs
   on more critical assets receives a higher score.
3. **Tier-aware gate variants.** Show whether a permissive gate plus tier-first
   ordering outperforms Gate+CVSS at the same final budget.
4. **Inter-rater study.** Practitioners score the same asset profiles with the
   questionnaire. Report absolute agreement, tier agreement (kappa or ICC),
   completion time, and ambiguous anchors.

None of these replaces the holdout result. The holdout remains the confirmatory
test.

## 7. Data and provenance

Before a confirmatory run:

1. Rebuild the training and holdout files from snapshots dated at their
   respective cutoffs. Keep the generated `.meta.json` sidecars.
2. Record the EPSS snapshot date, EPSS model version, KEV release, NVD window,
   row counts, and SHA-256 in the manifest.
3. Run `src/validate_data.py` with the cutoff and horizon and resolve every
   error. Missing snapshot provenance is a warning that blocks a confirmatory
   claim, not a value to fill in by guesswork.
4. Freeze the candidate configuration and record the commit hash.

`src/validate_data.py` writes `data/manifest.json`. The current processed files
predate snapshot metadata, so the manifest records that limitation explicitly.

## 8. Holdout discipline

The 2024-06-30 → 2025-06-30 period has already been inspected. Results from it
are descriptive and can guide implementation, but they are not confirmatory.

The untouched period is 2025-06-30 → 2026-06-30. Before opening it:

- freeze the model, gate, ordering, capacity, inventories, and metric code;
- record the freeze commit;
- write the analysis plan;
- run the holdout once and report the result even if it is unfavourable.

No post-hoc budget selection, future EPSS values, dropped positives,
CVE-specific exceptions, or synthetic-inventory tailoring.

## 9. Reproducible commands

Primary descriptive evaluation (already-viewed period; not confirmatory):

```bash
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --budgets 0.10,0.20,0.30 --budget 0.10 \
    --outdir results/thesis_primary
```

Same period, wider candidate gate (separate Stage 1 from final capacity):

```bash
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --gate-share 0.20 \
    --budgets 0.10,0.20,0.30 --budget 0.10 \
    --outdir results/thesis_wide_gate
```

Capacity-constrained secondary analysis:

```bash
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --budgets 0.02,0.05,0.10 --budget 0.10 \
    --outdir results/thesis_capacity
```

Operational lists with tier queues:

```bash
uv run --with pandas --with numpy python src/scoring.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --capacity 500 --top 100 --tier-capacity 100 \
    --outdir results/operational
```

Data validation and manifest:

```bash
uv run --with pandas python src/validate_data.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --write-manifest data/manifest.json
```

Monte Carlo comparison (default budgets are now 10/20/30; pass the capacity
budgets explicitly when running the secondary analysis):

```bash
uv run --with pandas --with numpy python src/montecarlo.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --gate-share 0.20 --budgets 0.10,0.20,0.30 --n 300 \
    --outdir results/thesis_mc
```

## 10. Known limitations to report

- The 300 synthetic inventories are not a probability sample of real
  organisations. The four hand-written inventories are illustrative, and only
  15 of the 71 later-exploited CVEs match any of them.
- The synthetic inventory generator uses the same four-question instrument, so
  the tier distribution is a design assumption, not an observed population.
- EPSS is time-varying. The existing processed files lack snapshot sidecars;
  the manifest says so.
- The number of later-exploited CVEs is small (71 unique CVEs; mean 10.3 per
  inventory), so intervals are wide. Do not over-read small differences.
- Per-tier precision is low in absolute terms because most CVEs are never
  exploited. The useful comparison is relative and paired by inventory.
- The RQ2 instrument has not yet been tested with practitioners.
