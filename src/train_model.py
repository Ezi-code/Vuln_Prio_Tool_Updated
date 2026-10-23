"""
train_model.py - Calibrate and freeze the model (Objective 1 / RQ1).

No machine learning (section 5.3). "Training" = fixing the model's few
parameters on a TRAINING period, then freezing them before the test period:

  1. Stage 1 EPSS threshold (section 5.2.1: "re-derived on this study's data").
     Pre-stated rule: the smallest threshold whose urgent list stays within
     the workload budget (default 5% of the pool).
  2. Stage 2 criticality weight and Stage 1 threshold are then VARIED, as the
     sensitivity analysis of section 5.6 prescribes, on randomly generated
     inventories from the training period. This answers "how should the
     signals be staged and weighted" (Objective 1). Weights come from the
     specified design, not from optimization (section 8.2), so the grid is
     reported and not used to pick winners automatically.

Writes model_config.json. Commit/save it BEFORE touching the test period.

Usage:
    python src/train_model.py --train-cutoff 2023-06-30 --test-cutoff 2024-06-30
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from assets import explode_products
from baselines import load
from model import rank_pool
from montecarlo import (BUDGETS, CATALOGUE, bootstrap, build_pool,
                        sample_inventory, token_cve_sets)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-data", default="data/processed/vulns_train.csv")
    ap.add_argument("--train-cutoff", required=True)
    ap.add_argument("--test-cutoff", required=True,
                    help="training labels stop here; nothing later is used")
    ap.add_argument("--budget", type=float, default=0.05,
                    help="Stage 1 workload budget (share of the pool)")
    ap.add_argument("--n", type=int, default=300, help="random inventories")
    ap.add_argument("--reps", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="model_config.json")
    a = ap.parse_args()
    pd.set_option("display.width", 220)
    rng = np.random.default_rng(a.seed)

    df = load(a.train_data, a.train_cutoff, horizon_end=a.test_cutoff)
    df["products"] = df["products"].fillna("")
    base = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    P = int(base["exploited_after"].sum())
    print(f"Training pool: {len(base)} CVEs, {P} exploited between "
          f"{a.train_cutoff} and {a.test_cutoff}")

    # ---------------------------------------------- 1) Stage 1 threshold
    q = lambda share: float(base["epss"].quantile(1 - share))
    thr = round(q(a.budget), 5)
    flagged = base["epss"] >= thr
    cov = base.loc[flagged, "exploited_after"].sum() / P
    print(f"\nStage 1 rule: smallest threshold within a {a.budget:.0%} budget "
          f"-> EPSS >= {thr}  (flags {flagged.mean():.2%} of the pool, "
          f"finds {cov:.1%} of the training positives)")
    grid = np.unique(base["epss"].quantile(np.linspace(0.5, 0.9995, 300)))
    pos = base["exploited_after"].to_numpy()
    j = [(pos & (base["epss"] >= t).to_numpy()).sum() / P
         - ((~pos) & (base["epss"] >= t).to_numpy()).sum() / (~pos).sum()
         for t in grid]
    tj = float(grid[int(np.argmax(j))])
    print(f"For comparison, Youden's J peaks at EPSS >= {tj:.5f} "
          f"(flags {(base['epss'] >= tj).mean():.2%} of the pool)")

    # ------------------------------ 2) sensitivity on training inventories
    rule_name = f"{a.budget:.0%} budget (RULE)"
    thresholds = {"gate off": 0.0, "2% budget": q(0.02), rule_name: thr,
                  "10% budget": q(0.10), "VMC 0.088": 0.088}
    lams = {"lam=0 (no criticality)": 0.0, "lam=0.5": 0.5, "lam=1": 1.0,
            "lam=2": 2.0, "strict tiers (SPEC)": None}

    tokens = {t for _, opts, *_ in CATALOGUE for o in opts for t in o}
    sets = token_cve_sets(explode_products(base), tokens)
    pos_ids = base.loc[base["exploited_after"], "cve_id"].to_numpy()
    pos_index = {c: i for i, c in enumerate(pos_ids)}

    cfgs = [(tn, t, ln, lam) for tn, t in thresholds.items() for ln, lam in lams.items()]
    Pm, Fm, shares = [], {(f"{c[0]}|{c[2]}", b): [] for c in cfgs for b in BUDGETS}, []
    for _ in range(a.n):
        pool = build_pool(base, sample_inventory(rng), sets)
        if pool is None or pool["exploited_after"].sum() == 0:
            continue
        n = len(pool)
        present = np.zeros(P)
        present[pool.loc[pool["exploited_after"], "cve_id"].map(pos_index).to_numpy()] = 1.0
        Pm.append(present)
        shares.append({tn: float((pool["epss"] >= t).mean()) for tn, t in thresholds.items()})
        for tn, t, ln, lam in cfgs:
            order = rank_pool(pool, t, lam)
            for b in BUDGETS:
                top = order.head(max(1, int(round(b * n))))
                f = np.zeros(P)
                hit = top.loc[top["exploited_after"], "cve_id"]
                if len(hit):
                    f[hit.map(pos_index).to_numpy()] = 1.0
                Fm[(f"{tn}|{ln}", b)].append(f)
    M = np.array(Pm)
    F = {k: np.array(v) for k, v in Fm.items()}
    print(f"\nRandom training inventories used: {len(M)} (mean positives per "
          f"inventory {M.sum(1).mean():.1f})")
    boot, pt = bootstrap(F, M, M, a.reps, rng)

    print("\nWorkload: mean share of an organization's CVE list that passes Stage 1")
    print(pd.Series(pd.DataFrame(shares).mean()).map("{:.1%}".format).to_string())

    for b in BUDGETS:
        tab = pd.DataFrame({ln: {tn: pt[("recall", f"{tn}|{ln}", b)] for tn in thresholds}
                            for ln in lams}).round(3)
        print(f"\nRecall in the top {b:.0%} of an organization's list "
              f"(rows: Stage 1 threshold, columns: criticality weight)")
        print(tab.to_string())

    key0 = f"{rule_name}|strict tiers (SPEC)"
    b = 0.05
    print(f"\nEvery cell minus the specified design at the top {b:.0%}; a CI that "
          f"excludes 0 holds up")
    rows = {}
    for tn in thresholds:
        rows[tn] = {}
        for ln in lams:
            k = f"{tn}|{ln}"
            d = boot[("recall", k, b)] - boot[("recall", key0, b)]
            lo, hi = np.percentile(d, [2.5, 97.5])
            rows[tn][ln] = f"{pt[('recall', k, b)] - pt[('recall', key0, b)]:+.3f} [{lo:+.3f},{hi:+.3f}]"
    print(pd.DataFrame(rows).T.to_string())

    try:
        epss_version = str(pd.read_csv(a.train_data, usecols=["epss_model_version"],
                                       nrows=1).iloc[0, 0])
    except (ValueError, IndexError):
        epss_version = "unknown"
    cfg = {
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "note": "Frozen before the test period. Do not edit after viewing test results.",
        "train_data": a.train_data, "train_data_sha256_16": sha(a.train_data),
        "train_cutoff": a.train_cutoff, "label_horizon_end": a.test_cutoff,
        "train_pool": int(len(base)), "train_positives": P,
        "epss_model_version": epss_version,
        "stage1": {"rule": f"smallest EPSS threshold within {a.budget:.0%} of the pool",
                   "epss_threshold": thr, "also_in_kev_at_cutoff": True,
                   "youden_j_threshold_for_reference": round(tj, 5)},
        "stage2": {"tier_order": ["Low", "Medium", "High", "Critical"],
                   "weighting": "strict tiers (specified design)"},
        "stage3": {"within_tier": "CVSS base score", "remaining_ties": "EPSS"},
        "budgets_evaluated": list(BUDGETS),
        "inventories": {"n": a.n, "seed": a.seed,
                        "catalogue_sha256_12": hashlib.sha256(repr(CATALOGUE).encode()).hexdigest()[:12]},
    }
    Path(a.out).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(f"\nFrozen configuration written to {a.out}")


if __name__ == "__main__":
    main()
