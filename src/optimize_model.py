"""
optimize_model.py - Development-period comparison of Stage 1 gate designs and
Stage 2/3 ordering variants.

This is the training-only experiment recommended by the optimization review:
  * fixed EPSS threshold (the frozen design)
  * fixed 98th-percentile threshold
  * label-free top 1/2/3/5% of each inventory's EPSS distribution
  * four orderings of gate, criticality tier, CVSS and EPSS

It writes a CSV and a JSON summary under results/ and never edits the frozen
model_config.json or stage1_config.json. Use the development period only; do
not use the untouched test period to choose a winner.

Usage:
    python src/optimize_model.py --train-cutoff 2023-06-30 --test-cutoff 2024-06-30
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from assets import explode_products
from baselines import load
from evaluate_model import SECTORS, sample_inventory
from model import gate_cutoff
from montecarlo import (CATALOGUE, bootstrap, build_pool, fmt,
                        token_cve_sets)


ORDERS = {
    "gate>tier>cvss>epss": ["gate", "tier_rank", "cvss", "epss"],
    "tier>gate>cvss>epss": ["tier_rank", "gate", "cvss", "epss"],
    "gate>epss>tier>cvss": ["gate", "epss", "tier_rank", "cvss"],
    "gate>cvss>epss>tier": ["gate", "cvss", "epss", "tier_rank"],
}
CURRENT = ("fixed threshold", "gate>tier>cvss>epss")


def read_fixed_threshold(path):
    cfg = json.loads(Path(path).read_text())
    if "stage1" in cfg and "epss_threshold" in cfg["stage1"]:
        return float(cfg["stage1"]["epss_threshold"])
    if "epss_threshold" in cfg:
        return float(cfg["epss_threshold"])
    raise SystemExit(f"{path}: could not find an EPSS threshold")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-data", default="data/processed/vulns_train.csv")
    ap.add_argument("--train-cutoff", required=True)
    ap.add_argument("--test-cutoff", required=True,
                    help="development labels stop here; this is NOT the final test period")
    ap.add_argument("--config", default="model_config.json",
                    help="config supplying the frozen fixed threshold")
    ap.add_argument("--fixed-threshold", type=float, default=None,
                    help="override the fixed threshold (useful when deriving it "
                         "on the same development period for a fair comparison)")
    ap.add_argument("--n", type=int, default=500, help="random inventories")
    ap.add_argument("--reps", type=int, default=1000, help="bootstrap replicates")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--ns", default="100,250,500,1000")
    ap.add_argument("--primary-n", type=int, default=500,
                    help="budget used when naming the preferred variant")
    ap.add_argument("--outdir", default="results")
    a = ap.parse_args()
    pd.set_option("display.width", 260)
    rng = np.random.default_rng(a.seed)
    NS = tuple(int(x) for x in a.ns.split(","))
    if a.primary_n not in NS:
        raise SystemExit("--primary-n must be one of --ns")
    outdir = Path(a.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = load(a.train_data, a.train_cutoff, a.test_cutoff)
    df["products"] = df["products"].fillna("")
    base = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    P = int(base["exploited_after"].sum())
    if a.fixed_threshold is not None:
        fixed_thr = float(a.fixed_threshold)
        fixed_src = "command line"
    else:
        fixed_thr = read_fixed_threshold(a.config)
        fixed_src = f"config {a.config}"
    fixed_q98 = float(base["epss"].quantile(0.98))
    print(f"Development pool: {len(base)} CVEs, {P} exploited between "
          f"{a.train_cutoff} and {a.test_cutoff}")
    print(f"Fixed threshold: {fixed_thr:.5f} ({fixed_src}); training 98th "
          f"percentile: {fixed_q98:.5f}")
    if a.fixed_threshold is None:
        print("  If the config threshold was derived on a different period, "
              "treat that row as a frozen-model simulation, not a fair "
              "training comparator.")
    if P == 0:
        raise SystemExit("No later-exploited CVEs in this development period.")
    if P < 50:
        print(f"WARNING: only {P} development positives; the comparison will be noisy.\n")

    gates = {
        "fixed threshold": {"thr": fixed_thr},
        "fixed 98th pct": {"thr": fixed_q98},
        "top 1%": {"gate_share": 0.01},
        "top 2%": {"gate_share": 0.02},
        "top 3%": {"gate_share": 0.03},
        "top 5%": {"gate_share": 0.05},
    }

    tokens = {t for _, opts, *_ in CATALOGUE for o in opts for t in o}
    sets = token_cve_sets(explode_products(base), tokens)
    pos_ids = base.loc[base["exploited_after"], "cve_id"].to_numpy()
    pos_index = {c: i for i, c in enumerate(pos_ids)}

    keys = [(g, o, N) for g in gates for o in ORDERS for N in NS]
    F = {k: [] for k in keys}
    Pm = []
    gate_stats = {g: {"share": [], "coverage": []} for g in gates}
    secs = list(SECTORS)
    used = 0
    for i in range(a.n):
        pool = build_pool(base, sample_inventory(rng, SECTORS[secs[i % len(secs)]]), sets)
        if pool is None or pool["exploited_after"].sum() == 0:
            continue
        used += 1
        n = len(pool)
        present = np.zeros(P)
        present[pool.loc[pool["exploited_after"], "cve_id"].map(pos_index).to_numpy(dtype=int)] = 1.0
        Pm.append(present)
        for gname, params in gates.items():
            cutoff = gate_cutoff(pool, params.get("thr"), params.get("gate_share"))
            gate = pool["kev_at_cutoff"] | (pool["epss"] >= cutoff)
            gate_stats[gname]["share"].append(float(gate.mean()))
            gate_stats[gname]["coverage"].append(
                float(pool.loc[gate, "exploited_after"].sum() / present.sum()))
            p = pool.assign(gate=gate)
            for oname, cols in ORDERS.items():
                o = p.sort_values(cols, ascending=False, kind="stable")
                for N in NS:
                    top = o.head(max(1, N))
                    f = np.zeros(P)
                    hit = top.loc[top["exploited_after"], "cve_id"]
                    if len(hit):
                        f[hit.map(pos_index).to_numpy()] = 1.0
                    F[(gname, oname, N)].append(f)

    if used == 0:
        raise SystemExit("No generated inventory contained a later-exploited CVE.")
    M = np.array(Pm)
    Fa = {k: np.array(v) for k, v in F.items()}
    print(f"Inventories used: {used} of {a.n}; mean positives per inventory "
          f"{M.sum(1).mean():.1f}")

    print("\nGate size and coverage (mean over inventories):")
    print(pd.DataFrame({
        g: {"share of list": f"{np.mean(v['share']):.2%}",
            "positive coverage": f"{np.mean(v['coverage']):.1%}"}
        for g, v in gate_stats.items()}).T.to_string())

    boot, pt = bootstrap(Fa, M, M, a.reps, rng)
    rows = []
    for gname in gates:
        for oname in ORDERS:
            for N in NS:
                key = ("recall", gname, oname, N)
                point = float(pt[key])
                lo, hi = np.nanpercentile(boot[key], [2.5, 97.5])
                d = boot[key] - boot[("recall", *CURRENT, N)]
                dlo, dhi = np.nanpercentile(d, [2.5, 97.5])
                rows.append({
                    "gate": gname, "order": oname, "N": N,
                    "recall": point, "ci_lo": float(lo), "ci_hi": float(hi),
                    "diff_vs_current": point - float(pt[("recall", *CURRENT, N)]),
                    "diff_lo": float(dlo), "diff_hi": float(dhi),
                })
    R = pd.DataFrame(rows)

    print("\nRecall by variant (mean [95% CI over inventories]):")
    for N in NS:
        sub = R[R["N"] == N].sort_values("recall", ascending=False)
        print(f"\n  N = {N}")
        for _, r in sub.iterrows():
            mark = " <- current" if (r["gate"], r["order"]) == CURRENT else ""
            print(f"    {r['gate']:<18s} {r['order']:<22s} "
                  f"{fmt(r['recall'], boot[('recall', r['gate'], r['order'], N)]).replace('+', '')}"
                  f"{mark}")

    print(f"\nDifference from the current design at N = {a.primary_n} "
          f"(a CI above zero means the variant wins):")
    primary = R[R["N"] == a.primary_n].sort_values("diff_vs_current", ascending=False)
    print(primary[["gate", "order", "recall", "diff_vs_current",
                   "diff_lo", "diff_hi"]].to_string(index=False))

    best = primary.iloc[0]
    print(f"\nBest development-period variant at N = {a.primary_n}: "
          f"{best['gate']} / {best['order']} "
          f"(recall {best['recall']:.3f}, diff {best['diff_vs_current']:+.3f} "
          f"[{best['diff_lo']:+.3f}, {best['diff_hi']:+.3f}])")
    print("Do not freeze this on the strength of one development period. Check "
          "rolling-origin periods and then evaluate once on an untouched holdout.")

    csv_path = outdir / f"model_optimization_{a.train_cutoff}.csv"
    R.to_csv(csv_path, index=False)
    summary = {
        "created": pd.Timestamp.now().isoformat(timespec="seconds"),
        "train_data": a.train_data, "train_cutoff": a.train_cutoff,
        "label_horizon_end": a.test_cutoff, "config": a.config,
        "fixed_threshold": fixed_thr, "fixed_threshold_source": fixed_src,
        "fixed_98th_percentile": fixed_q98,
        "n_inventories": int(used), "development_positives": P,
        "gate_stats": {g: {"share": float(np.mean(v["share"])),
                           "coverage": float(np.mean(v["coverage"]))}
                       for g, v in gate_stats.items()},
        "best_at_primary_n": {"n": a.primary_n, **best.to_dict()},
        "note": "Development-period comparison only; do not tune on the holdout.",
    }
    json_path = outdir / f"model_optimization_{a.train_cutoff}.json"
    json_path.write_text(json.dumps(summary, indent=2, default=float),
                         encoding="utf-8")
    print(f"\nCSV:  {csv_path}\nJSON: {json_path}")


if __name__ == "__main__":
    main()
