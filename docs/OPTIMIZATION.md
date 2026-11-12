# Model optimization notes

This document records the optimization work that is implemented in the code. It
does **not** replace `model_config.json` or `stage1_config.json`: both remain the
frozen design of the original experiment. The candidate settings below must be
frozen first and then validated on a period that has not been used for any
decisions.

## What changed

- `src/model.py`
  - `gate_cutoff(pool, thr=None, gate_share=None)` supports either the original
    fixed EPSS threshold or a label-free percentile gate.
  - `rank_pool(..., gate_share=None, kev_first=False)` applies the gate and the
    Stage 2/3 ordering in one place.
- `src/scoring.py`
  - Operational output now includes KEV-at-cutoff CVEs and puts them first.
  - `--gate-share` selects the per-inventory percentile gate.
  - `--outdir` lets new output go somewhere other than the existing `results/`.
  - The four asset tiers are exposed as `asset_tier` plus `priority_queue`,
    and one CSV is written per tier.
  - `--capacity` separates the final list size from the Stage 1 candidate gate.
- `src/evaluate_model.py`
  - `--gate-share` evaluates the percentile-gate candidate.
  - Fixed the `--budgets` by-sector crash (the by-sector table now uses the
    first requested budget).
  - Writes a machine-readable `evaluation_<cutoff>_summary.json`.
  - Reports the Stage 1 gate, the final 10% list, and per-asset-tier metrics
    separately.
- `src/validate_data.py`
  - New schema, leakage, sidecar, and manifest checks.
- `src/assets.py`
  - Required/optional inventory columns, `patchable`, queue labels, and
    explicit validation.
- `src/montecarlo.py`
  - `--gate-share` support.
  - Fixed an empty-selection indexing bug that could occur when the top budget
    contained no positive CVE.
  - `--outdir` support.
- `src/optimize_model.py`
  - New development-period comparison of gate designs and ordering variants.
- `src/ingest.py`
  - Records `epss_snapshot_date` and writes a `.meta.json` sidecar.
- `src/baselines.py`
  - Reads the sidecar and warns when the EPSS snapshot is more than 30 days
    older than the evaluation cutoff.
- `src/stage1.py`
  - Fixed a no-op `notna()` filter, guarded the budget criterion, and warns when
    the bootstrap range is too wide to identify a threshold.

## Development-period result

The script was run on the training/development period only:

```bash
uv run --with pandas --with numpy python src/optimize_model.py \
    --train-cutoff 2023-06-30 --test-cutoff 2024-06-30
```

It used 500 random inventories and 37 development positives, so the intervals
are wide. Mean CVE-level recall at the 5% budget:

| Gate | Ordering | R@5% | Difference from current design |
|---|---|---|---|
| fixed `0.04267` | gate -> tier -> CVSS -> EPSS (current) | 0.079 | 0 |
| fixed `0.04267` | tier -> gate -> CVSS -> EPSS | 0.152 | +0.072 |
| top 2% per inventory | gate -> tier -> CVSS -> EPSS | 0.167 | +0.088 |
| top 1% per inventory | gate -> tier -> CVSS -> EPSS | 0.171 | +0.092 |
| top 2% per inventory | tier -> gate -> CVSS -> EPSS | 0.166 | +0.086 |
| top 3% per inventory | tier -> gate -> CVSS -> EPSS | 0.161 | +0.082 |

The label-free top-2% gate with the existing ordering is the candidate that was
approved for testing. The top-1% point estimate is slightly higher at this
budget, but it produces a much smaller urgent list and is less stable at the
smaller budgets; it is a sensitivity variant, not the default recommendation.
Changing to tier-first ordering is a separate design decision already recorded
in `stage2_config.json`; the code supports it, but this work does not change the
frozen ordering.

### Rolling-origin check

The same comparison was repeated on 2022-06-30 to 2023-06-30 (68 development
positives, 500 inventories). The fixed threshold for that run was re-derived
with `src/stage1.py derive` (coverage criterion) to avoid leaking the 2023
threshold:

```bash
uv run --with pandas --with numpy python src/optimize_model.py \
    --train-cutoff 2022-06-30 --test-cutoff 2023-06-30 \
    --fixed-threshold 0.2766 --outdir results/optimized/rolling_2022
```


| Gate | Ordering | R@100 | R@250 | R@500 | R@1000 |
|---|---|---|---|---|---|
| fixed `0.2766` (same period) | gate -> tier -> CVSS -> EPSS | 0.442 | 0.639 | 0.712 | 0.804 |
| fixed 98th pct (same period) | gate -> tier -> CVSS -> EPSS | 0.415 | 0.622 | 0.705 | 0.801 |
| top 2% per inventory | gate -> tier -> CVSS -> EPSS | 0.441 | 0.617 | 0.698 | 0.786 |
| top 3% per inventory | gate -> tier -> CVSS -> EPSS | 0.422 | 0.628 | 0.710 | 0.802 |

The `0.2766` threshold is the coverage rule re-derived on this period with the
same Stage 1 criterion; it gates 3.07% of the list. Against that fair
comparator, the top-2% and top-3% gates are comparable, not uniformly better.
The frozen `0.04267` threshold is deliberately omitted from this table because
it was derived on the 2023-2024 period; using it here would not be a fair
training comparison. The CSV/JSON for this run is in
`results/optimized/rolling_2022/`.

The practical conclusion is that the gate share should match the operational
urgent-list budget. A top-2% gate is sensible when the team can act on about 2%
of each inventory; if the team can act on 5%, compare a top-5% gate directly.
Do not claim a universal recall improvement from the percentile gate.

The 2024-06-30 to 2025-06-30 period had already been viewed. It is therefore
**not** used to choose the candidate. For transparency, the candidate's
descriptive output on that period is saved under `results/optimized/`:
300 inventories, 71 later-exploited CVEs, top-2% gate.

| Budget | Model recall | EPSS/KEV-only recall | CVSS-only recall |
|---|---|---|---|
| 2% | 0.095 | 0.095 | 0.007 |
| 5% | 0.177 | 0.095 | 0.080 |
| 10% | 0.258 | 0.131 | 0.211 |

> Note (Nov 2026): this table is the earlier candidate top-2%-gate run. Under
> the current frozen Stage 1 threshold with capacity as the final list, the
> descriptive 2% result is 0.057 (interval includes 0), the 5% result is 0.106,
> and the 10% result is 0.211. The 2% case is a capacity-constrained secondary
> analysis, not the headline. See `docs/THESIS_PROTOCOL.md`.

The model's urgent list averaged 224 CVEs, 2.0% of the list, with 0.095
coverage. These numbers are descriptive only because this period has already
been inspected. After the candidate is frozen, confirm it once on a new,
untouched period (for example, a 2025-2026 holdout) and report that result
separately.

## Commands

Evaluate the candidate without overwriting the existing result files:

```bash
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --budgets 0.02,0.05,0.10 \
    --gate-share 0.02 \
    --outdir results/optimized
```

Generate operational ranked lists (KEV-at-cutoff CVEs are included and ranked
first; the evaluation pool still excludes them):

```bash
uv run --with pandas --with numpy python src/scoring.py \
    --cutoff 2024-06-30 --gate-share 0.02 \
    --outdir results/optimized
```

Run the Monte Carlo comparison:

```bash
uv run --with pandas --with numpy python src/montecarlo.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --gate-share 0.02 --n 300 \
    --outdir results/optimized
```

Run the tests:

```bash
uv run --with pandas --with numpy --with pytest pytest -q
```

## Data provenance

EPSS is a time-varying score. The processed files used for the original
experiment were built before snapshot metadata was recorded, and the two
processed files disagree on EPSS values for many common CVEs even though both
report the same EPSS model version. Before freezing a new model, rebuild the
training and holdout data from snapshots taken at their respective cutoffs and
keep the generated `.meta.json` sidecars with the data.

New ingests now write:

- an `epss_snapshot_date` column in the processed CSV;
- `<output>.meta.json` with the ingest window, EPSS snapshot date, EPSS model
  version, source row counts, and creation time.

`baselines.load()` prints a warning when the recorded EPSS snapshot is more than
30 days before the cutoff. A stale snapshot is not a model improvement; it is a
data-validity issue.

## Operational versus evaluation output

- **Evaluation:** KEV-at-cutoff CVEs are excluded from the metric pool so the
  metrics measure new exploitation after the cutoff.
- **Operations:** KEV-at-cutoff CVEs are included in the ranked output and put
  first. A ranked list that omits known-exploited CVEs is not a usable
  operational list.

The tracked `results/ranked_*.csv` files have been regenerated with the frozen
`0.04267` threshold and now include KEV-at-cutoff CVEs. The previous copies are
in `results/archive_pre_optimization/`. Candidate top-2% outputs are separate,
under `results/optimized/`.

## Decision update: asset tiers are the priority categories

The four asset-criticality tiers are the final operational priority
categories: **Critical, High, Medium, Low**. There is no separate
Critical/Medium/Low threat taxonomy. The implementation exposes the tier as
`asset_tier` and maps it to a queue label (`Patch now`, `Patch next`,
`Scheduled`, `Monitor`). A three-label slide can group the four tiers for
display, but that grouping is not a model change and is not used for the
metrics.

The Stage 1 gate and the final list are separate:

- Stage 1 produces a **candidate** set.
- Stage 2 orders candidates by asset tier.
- Stage 3 orders within tier by CVSS and then EPSS.
- `--capacity` / the evaluation budget selects the final list.

This matters when the candidate gate is wider than the operational capacity.
At the 2% capacity the gate and final list can coincide, so Stages 2 and 3
cannot change membership; that result is a capacity-constrained secondary
analysis, not the thesis headline.

### Descriptive 10/20/30 result (already-viewed period)

Using the frozen Stage 1 threshold (`0.04267`) and final-list budgets:

| Budget | Model recall | CVSS-only | EPSS/KEV-only |
|---|---:|---:|---:|
| 10% | 0.211 | 0.211 | 0.131 |
| 20% | 0.364 | 0.290 | 0.234 |
| 30% | 0.508 | 0.408 | 0.304 |

The model and CVSS-only are tied at 10%; the model separates at 20% and 30%.
The intervals overlap, so this is descriptive, not a confirmatory claim. The
per-tier table shows the criticality signal: at the 10% final list, recall on
Critical assets is 0.795, on High 0.208, on Medium 0.099, and on Low 0.239.

### Gate-breadth sensitivity

A deliberately wide candidate gate (top 20% of each inventory's EPSS) plus a
10% final list gives Model recall 0.180, CVSS-only 0.211, and EPSS/KEV-only
0.131. The wider gate does not improve the 10% result; it is a stress test of
the gate/capacity separation, not the primary protocol. The primary protocol
keeps the frozen Stage 1 rule and applies the 10% capacity.

### Commands

```bash
# Primary descriptive 10/20/30 protocol
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --budgets 0.10,0.20,0.30 --budget 0.10 \
    --outdir results/thesis_primary

# Gate-breadth sensitivity
uv run --with pandas --with numpy python src/evaluate_model.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --gate-share 0.20 --budgets 0.10,0.20,0.30 --budget 0.10 \
    --outdir results/thesis_wide_gate
```

### Operational output

`src/scoring.py` now writes:

- `ranked_<inventory>.csv` with `asset_tier`, `criticality_score`,
  `priority_queue`, `needs_fixing`, `exploit_status`, `fix_action`, and
  `reason`;
- `tier_<inventory>_<tier>.csv` for each of the four queues;
- `exploits_by_tier_<inventory>.csv`, a per-tier summary of known-exploited
  and EPSS-gated CVEs;
- `asset_exploits_<inventory>.csv`, one row per (asset, CVE) that needs action;
- `exploit_report_<inventory>.md`, the readable tier -> asset -> CVE report;
- a printed tier summary with later-exploited counts.

`needs_fixing` is based on CISA KEV at the cutoff or the EPSS candidate gate,
not on the after-cutoff evaluation label.

The old top-2% headline is retained only as the capacity-constrained case. Do
not compare its coverage with a 10% final list without labelling both sizes.

### Criticality evidence on the synthetic-inventory check

The Monte Carlo run below uses 300 generated inventories, the frozen Stage 1
threshold (`0.04267`), and final-list budgets of 10/20/30%:

```bash
uv run --with pandas --with numpy python src/montecarlo.py \
    --cutoff 2024-06-30 --horizon-end 2025-06-30 \
    --budgets 0.10,0.20,0.30 --n 300 --reps 1000 \
    --outdir results/thesis_mc
```

| Metric at 10% | Model | Gate+CVSS (criticality off) | Tier+CVSS (no gate) |
|---|---:|---:|---:|
| Recall | 0.216 | 0.200 | 0.210 |
| Criticality-weighted recall | 0.251 | 0.147 | 0.288 |
| Share on High/Critical assets | 0.564 | 0.298 | 0.877 |

At 20% the criticality-weighted recall difference is +0.242
[+0.057, +0.364] for the model over Gate+CVSS; at 30% it is +0.298
[+0.083, +0.462]. At 10% the interval still includes zero (-0.049 to +0.219),
so the 10% criticality-weighted advantage is suggestive, not confirmatory.
The plain recall difference against Gate+CVSS is small and its interval
includes zero at every budget. The defensible claim is about the tier mix and
criticality-weighted coverage, not about a large raw-recall gain.

The run is descriptive because the period has already been inspected. The
confirmatory test is the untouched 2025-06-30 → 2026-06-30 holdout.
