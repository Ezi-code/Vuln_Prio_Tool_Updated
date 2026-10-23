"""
threshold.py - Derive the EPSS threshold on a TRAINING period (section 5.6).

Train : EPSS/KEV as of --train-cutoff; labels = KEV additions between the
        train cutoff and the test cutoff (nothing after the test cutoff).
Test  : done later by scoring.py with the chosen --epss-threshold.

Because exploited CVEs are very rare, Youden's J always favours a tiny
threshold, so this script reports three views and does NOT pick for you:
  1. a threshold grid (urgent-set size, coverage, precision)
  2. thresholds that give a fixed workload budget (1/2/5/10 % of the pool)
  3. the same with a CVSS >= 7.0 filter added (VMC-style chaining)

Prepare the training data first (windows are cached, so this is quick):
    python src/ingest.py --start 2021-01-01 --end 2023-06-30 \
        --epss-date 2023-06-30 --out data/processed/vulns_train.csv
Then:
    python src/threshold.py --train-cutoff 2023-06-30 --test-cutoff 2024-06-30
"""
import argparse

import numpy as np
import pandas as pd

from baselines import load

GRID = [0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.088, 0.2, 0.5]
BUDGETS = [0.01, 0.02, 0.05, 0.10]


def metrics(pool, mask):
    pos = int(pool["exploited_after"].sum())
    tp = int(pool.loc[mask, "exploited_after"].sum())
    n_flag = int(mask.sum())
    neg = len(pool) - pos
    return {"urgent size": n_flag,
            "% of pool": round(100 * n_flag / len(pool), 2),
            "found": tp,
            "coverage": round(tp / pos, 3) if pos else float("nan"),
            "precision": round(tp / n_flag, 4) if n_flag else float("nan"),
            "Youden J": round(tp / pos - (n_flag - tp) / neg, 3) if pos else float("nan")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-data", default="data/processed/vulns_train.csv")
    ap.add_argument("--train-cutoff", required=True)
    ap.add_argument("--test-cutoff", required=True)
    a = ap.parse_args()

    df = load(a.train_data, a.train_cutoff, horizon_end=a.test_cutoff)
    pool = df[~df["kev_at_cutoff"]].copy()          # known KEV excluded
    pos = int(pool["exploited_after"].sum())
    print(f"Training pool: {len(pool)} CVEs, {pos} exploited between "
          f"{a.train_cutoff} and {a.test_cutoff}")
    if pos < 20:
        print("WARNING: few training positives; results will be unstable.")
    pd.set_option("display.width", 200)

    rows = [{"threshold": t, **metrics(pool, pool["epss"] >= t)} for t in GRID]
    print("\n1) EPSS threshold grid")
    print(pd.DataFrame(rows).set_index("threshold").to_string())

    print("\n2) Threshold that flags a fixed share of the pool "
          "(EPSS only)  |  3) same, plus CVSS >= 7.0")
    rows = []
    for b in BUDGETS:
        t = float(np.quantile(pool["epss"], 1 - b))
        m1 = metrics(pool, pool["epss"] >= t)
        m2 = metrics(pool, (pool["epss"] >= t) & (pool["cvss"] >= 7.0))
        rows.append({"budget": f"{int(b*100)}%", "threshold": round(t, 5),
                     "size": m1["urgent size"], "coverage": m1["coverage"],
                     "size (+CVSS>=7)": m2["urgent size"],
                     "coverage (+CVSS>=7)": m2["coverage"]})
    print(pd.DataFrame(rows).set_index("budget").to_string())
    print("\nPick a rule (e.g. 'smallest threshold within a 5% workload "
          "budget'), justify it in the thesis, then run:\n"
          "  python src/scoring.py --cutoff <test cutoff> --epss-threshold <value>")


if __name__ == "__main__":
    main()
