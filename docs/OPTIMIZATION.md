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
- `src/evaluate_model.py`
  - `--gate-share` evaluates the percentile-gate candidate.
  - Fixed the `--budgets` by-sector crash (the by-sector table now uses the
    first requested budget).
  - Writes a machine-readable `evaluation_<cutoff>_summary.json`.
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
