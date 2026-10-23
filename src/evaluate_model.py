"""
evaluate_model.py - Objective 3 / RQ3: the FROZEN model against the baselines,
using exactly the metrics of sections 3.1, 5.4 and 5.5.

Metrics
  Coverage            Recall@N with Precision@N
  Workload reduction  urgent-list size vs patch-everything and vs CVSS>=7.0,
                      with the share of later-exploited CVEs each list covers
  Ranking agreement   Spearman's rho and top-N overlap between the model and
                      each baseline
  Feasibility         time to match and rank an inventory on this machine
Baselines (5.5): CVSS-only, EPSS/KEV-only, FIFO (+ a random reference row).
Validation (5.6): KEV/EPSS frozen at the cutoff; labels = KEV additions after
the cutoff, up to --horizon-end. The threshold is read from model_config.json
and is NOT changed here. Inventories vary in size and sector. Intervals
resample inventories AND the later-exploited CVEs; every claim is a paired
difference against a named baseline.

Usage:
    python src/evaluate_model.py --cutoff 2024-06-30 --horizon-end 2025-06-30

For a period scored with a different EPSS model version, re-apply the frozen
RULE (label-free) instead of the frozen number:
    python src/evaluate_model.py --data data/processed/vulns_2025.csv \
        --cutoff 2025-06-30 --horizon-end 2026-06-30 --rederive-threshold
"""
import argparse
import json
import os
import platform
import time
from pathlib import Path

import numpy as np
import pandas as pd

from assets import TIER_RANK, explode_products, tier_from_total
from baselines import load, rank_cvss_only, rank_epss_kev_only, rank_fifo
from model import rank_pool
from montecarlo import (CATALOGUE, bootstrap, build_pool, ci, fmt,
                        token_cve_sets)

NAMES = [c[0] for c in CATALOGUE]
SECTORS = {  # relative weight of each asset type (workstations always present)
    "NGO office": {"File server": 3, "Mail server": 2, "Web server": 2, "Database": 1,
                   "Firewall / VPN": 2, "Router / Wi-Fi": 2, "NAS / backup": 2,
                   "Virtualization": .5, "DevOps / collaboration": .3, "Linux server": .5},
    "Clinic": {"File server": 3, "Mail server": 1, "Web server": 1, "Database": 3,
               "Firewall / VPN": 2, "Router / Wi-Fi": 2, "NAS / backup": 3,
               "Virtualization": 1, "DevOps / collaboration": .2, "Linux server": .5},
    "School / university": {"File server": 2, "Mail server": 2, "Web server": 3, "Database": 2,
                            "Firewall / VPN": 2, "Router / Wi-Fi": 2, "NAS / backup": 1,
                            "Virtualization": 2, "DevOps / collaboration": 2, "Linux server": 3},
    "Retail SME": {"File server": 1, "Mail server": 1, "Web server": 3, "Database": 2,
                   "Firewall / VPN": 2, "Router / Wi-Fi": 3, "NAS / backup": 1,
                   "Virtualization": .5, "DevOps / collaboration": .3, "Linux server": 1},
}
STRATS = ["Model", "CVSS-only", "EPSS/KEV-only", "FIFO", "Random"]
BASES = ["CVSS-only", "EPSS/KEV-only", "FIFO"]


def sample_inventory(rng, weights):
    k = int(rng.integers(6, 13))
    others = list(range(1, len(CATALOGUE)))
    p = np.array([weights.get(NAMES[i], 1.0) for i in others], float)
    picks = [0] + list(rng.choice(others, size=min(k - 1, len(others)),
                                  replace=False, p=p / p.sum()))
    assets = []
    for i in picks:
        _, options, ex, se, fu, re_ = CATALOGUE[i]
        tokens = options[int(rng.integers(len(options)))]
        ans = [int(rng.integers(lo, hi + 1)) for lo, hi in (ex, se, fu, re_)]
        assets.append((tokens, TIER_RANK[tier_from_total(sum(ans))]))
    return assets


def positions(order, n):
    pos = np.empty(n)
    pos[order.index.to_numpy()] = np.arange(n)
    return pos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/vulns.csv")
    ap.add_argument("--cutoff", required=True)
    ap.add_argument("--horizon-end", default=None)
    ap.add_argument("--config", default="model_config.json")
    ap.add_argument("--rederive-threshold", action="store_true")
    ap.add_argument("--budget", type=float, default=0.05)
    ap.add_argument("--ns", default="50,100,250,500,1000")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--reps", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--sensitivity", action="store_true",
                    help="section 5.6: vary Stage 1 threshold and criticality weight (descriptive only)")
    a = ap.parse_args()
    pd.set_option("display.width", 240)
    rng = np.random.default_rng(a.seed)
    NS = tuple(int(x) for x in a.ns.split(","))

    cfg = json.loads(Path(a.config).read_text())
    df = load(a.data, a.cutoff, a.horizon_end)
    df["products"] = df["products"].fillna("")
    base = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    if a.rederive_threshold:
        thr = float(base["epss"].quantile(1 - a.budget))
        how = f"frozen RULE re-applied to this period (top {a.budget:.0%} of the pool)"
    else:
        thr = float(cfg["stage1"]["epss_threshold"])
        how = f"frozen number from {a.config} (created {cfg['created']})"
    pos_ids = base.loc[base["exploited_after"], "cve_id"].to_numpy()
    pos_index = {c: i for i, c in enumerate(pos_ids)}
    P = len(pos_ids)
    print(f"Test pool: {len(base)} CVEs, {P} later-exploited (labels to "
          f"{a.horizon_end or 'today'}). EPSS threshold {thr:.5f}: {how}")

    tokens = {t for _, opts, *_ in CATALOGUE for o in opts for t in o}
    sets = token_cve_sets(explode_products(base), tokens)

    rows, Pm, sector_of = [], [], []
    keys = [(s, N) for s in STRATS for N in NS] + \
           [("UrgModel", 0), ("UrgCVSS7", 0), ("UrgAll", 0)]
    if a.rederive_threshold:   # EPSS scales differ between model versions: use pool shares
        q = lambda share: float(base["epss"].quantile(1 - share))
        SENS_T = {"gate off": 0.0, "top 20%": q(0.20), "top 10%": q(0.10),
                  f"top {a.budget:.0%} (RULE)": thr, "top 2%": q(0.02),
                  "top 1%": q(0.01), "top 0.5%": q(0.005)}
    else:
        SENS_T = {"gate off": 0.0, "0.005": 0.005, f"{thr:.5f} (FROZEN)": thr,
                  "0.05": 0.05, "0.1": 0.1, "0.2": 0.2, "0.5": 0.5}
    SENS_L = {"lam=0": 0.0, "lam=0.5": 0.5, "lam=1": 1.0, "strict (SPEC)": None}
    SENS_N = (250, 500)
    if a.sensitivity:
        keys += [(f"S|{tn}|{ln}", N) for tn in SENS_T for ln in SENS_L for N in SENS_N]
        keys += [(f"U|{tn}", 0) for tn in SENS_T]
    sens_share = {tn: [] for tn in SENS_T}
    Fm = {k: [] for k in keys}
    prec = {(s, N): [] for s in STRATS for N in NS}
    rho = {b: [] for b in BASES}
    ovl = {(b, N): [] for b in BASES for N in (100, 250)}
    t_match, t_rank, sizes = [], [], []
    sec_names = list(SECTORS)
    for i in range(a.n):
        sector = sec_names[i % len(sec_names)]
        t0 = time.perf_counter()
        pool = build_pool(base, sample_inventory(rng, SECTORS[sector]), sets)
        t1 = time.perf_counter()
        if pool is None or pool["exploited_after"].sum() == 0:
            continue
        n = len(pool)
        present = np.zeros(P)
        idx = pool.loc[pool["exploited_after"], "cve_id"].map(pos_index).to_numpy()
        present[idx] = 1.0
        t2 = time.perf_counter()
        model_o = rank_pool(pool, thr, None)
        t3 = time.perf_counter()
        orders = {"Model": model_o, "CVSS-only": rank_cvss_only(pool),
                  "EPSS/KEV-only": rank_epss_kev_only(pool), "FIFO": rank_fifo(pool)}
        t_match.append(t1 - t0); t_rank.append(t3 - t2); sizes.append(n)
        Pm.append(present); sector_of.append(sector)

        def found_of(mask_or_top):
            f = np.zeros(P)
            ids = mask_or_top.loc[mask_or_top["exploited_after"], "cve_id"]
            if len(ids):
                f[ids.map(pos_index).to_numpy()] = 1.0
            return f

        for s, o in orders.items():
            for N in NS:
                top = o.head(N)
                Fm[(s, N)].append(found_of(top))
                prec[(s, N)].append(top["exploited_after"].sum() / max(len(top), 1))
        for N in NS:
            Fm[("Random", N)].append(present * min(N, n) / n)
            prec[("Random", N)].append(pool["exploited_after"].mean())
        pm = positions(model_o, n)
        for b in BASES:
            pb = positions(orders[b], n)
            rho[b].append(float(np.corrcoef(pm, pb)[0, 1]))
            for N in (100, 250):
                ovl[(b, N)].append(len(np.intersect1d(
                    model_o.index[:N], orders[b].index[:N])) / N)
        gate = pool["kev_at_cutoff"] | (pool["epss"] >= thr)
        urg = {"UrgModel": gate, "UrgCVSS7": pool["cvss"] >= 7.0,
               "UrgAll": pd.Series(True, index=pool.index)}
        row = {"sector": sector, "pool": n, "positives": int(present.sum())}
        for k, m in urg.items():
            Fm[(k, 0)].append(found_of(pool[m]))
            row[k] = int(m.sum())
        if a.sensitivity:
            for tn, t in SENS_T.items():
                m = pool["kev_at_cutoff"] | (pool["epss"] >= t)
                Fm[(f"U|{tn}", 0)].append(found_of(pool[m]))
                sens_share[tn].append(float(m.mean()))
                for ln, lam in SENS_L.items():
                    o = rank_pool(pool, t, lam)
                    for N in SENS_N:
                        Fm[(f"S|{tn}|{ln}", N)].append(found_of(o.head(N)))
        rows.append(row)

    res = pd.DataFrame(rows)
    M = np.array(Pm)
    F = {k: np.array(v) for k, v in Fm.items()}
    print(f"Inventories used: {len(res)} of {a.n} ({res['sector'].value_counts().to_dict()}); "
          f"pool {res['pool'].min()}-{res['pool'].max()} CVEs, mean positives "
          f"{res['positives'].mean():.1f}")
    boot, pt = bootstrap(F, M, M, a.reps, rng)

    f2 = lambda m, arr: fmt(m, arr).replace("+", "")
    print("\n=== 1. COVERAGE: Recall@N, mean [95% CI] (inventories and positives resampled) ===")
    print(pd.DataFrame({f"R@{N}": {s: f2(pt[("recall", s, N)], boot[("recall", s, N)])
                                    for s in STRATS} for N in NS}).to_string())
    print("\n--- Model MINUS each baseline (a CI that excludes 0 holds up) ---")
    print(pd.DataFrame({f"R@{N}": {b: fmt(pt[("recall", "Model", N)] - pt[("recall", b, N)],
                                         boot[("recall", "Model", N)] - boot[("recall", b, N)])
                                    for b in BASES + ["Random"]} for N in NS}).to_string())
    print("\n=== Precision@N, mean [95% CI over inventories] ===")
    print(pd.DataFrame({f"P@{N}": {s: ci(np.array(prec[(s, N)]), rng) for s in STRATS}
                        for N in NS}).to_string())

    print("\n=== 2. WORKLOAD: urgent-list size and coverage of later-exploited CVEs ===")
    allv = res["UrgAll"].to_numpy(float)
    wl = {}
    for lab, k in (("Model urgent list (Stage 1)", "UrgModel"), ("CVSS >= 7.0 list", "UrgCVSS7"),
                   ("Patch everything", "UrgAll")):
        wl[lab] = {"mean size": f"{res[k].mean():.0f}",
                   "% of list": f"{100 * (res[k] / res['UrgAll']).mean():.1f}%",
                   "coverage": f2(pt[("recall", k, 0)], boot[("recall", k, 0)])}
    print(pd.DataFrame(wl).T.to_string())
    print("Workload reduction achieved by the model's urgent list, mean [95% CI over inventories]:")
    print(f"  vs patch-everything: {ci(1 - res['UrgModel'].to_numpy() / allv, rng)}")
    print(f"  vs CVSS >= 7.0     : {ci(1 - res['UrgModel'].to_numpy() / res['UrgCVSS7'].to_numpy(), rng)}")
    print("  (EPSS/KEV-only filtering flags the same set as Stage 1, so its urgent list is identical.)")

    print("\n=== 3. RANKING AGREEMENT of the model with each baseline (mean [95% CI]) ===")
    print(pd.DataFrame({
        "Spearman rho": {b: ci(np.array(rho[b]), rng) for b in BASES},
        "top-100 overlap": {b: ci(np.array(ovl[(b, 100)]), rng) for b in BASES},
        "top-250 overlap": {b: ci(np.array(ovl[(b, 250)]), rng) for b in BASES}}).to_string())

    tm, tr = np.array(t_match) * 1000, np.array(t_rank) * 1000
    print("\n=== 4. COMPUTATIONAL FEASIBILITY (no GPU, no paid feeds) ===")
    print(f"Machine: {platform.platform()}, {os.cpu_count()} CPU threads, Python {platform.python_version()}")
    print(f"Matching an inventory to its CVEs: median {np.median(tm):.0f} ms, max {tm.max():.0f} ms")
    print(f"Ranking one inventory ({int(np.min(sizes))}-{int(np.max(sizes))} CVEs): "
          f"median {np.median(tr):.0f} ms, max {tr.max():.0f} ms")

    if a.sensitivity:
        print("\n=== SENSITIVITY (section 5.6): descriptive only; the frozen design is NOT changed by it ===")
        print("Stage 1 threshold: share of an organization's list flagged, coverage of later-exploited CVEs, and lift over random")
        rows_s = {}
        for tn in SENS_T:
            sh, cov = float(np.mean(sens_share[tn])), pt[("recall", f"U|{tn}", 0)]
            rows_s[tn] = {"share of list": f"{sh:.1%}",
                          "coverage": f2(cov, boot[("recall", f"U|{tn}", 0)]),
                          "lift (coverage/share)": (f"{cov / sh:.1f}x" if sh > 0 else "n/a")}
        print(pd.DataFrame(rows_s).T.to_string())
        for N in SENS_N:
            print(f"\nRecall@{N}: rows = Stage 1 threshold, columns = criticality weight")
            print(pd.DataFrame({ln: {tn: round(pt[("recall", f"S|{tn}|{ln}", N)], 3)
                                     for tn in SENS_T} for ln in SENS_L}).to_string())

    print("\n=== By sector: Recall@250 (point estimates) ===")
    sec = pd.DataFrame({s: [F[(s, 250)][i].sum() / M[i].sum() for i in range(len(M))]
                        for s in STRATS})
    sec["sector"] = sector_of
    print(sec.groupby("sector").mean().round(3).to_string())

    Path("results").mkdir(exist_ok=True)
    res.to_csv(f"results/evaluation_{a.cutoff}.csv", index=False)
    print(f"\nPer-inventory sizes saved to results/evaluation_{a.cutoff}.csv")
    print("5. Instrument usability: practitioner review (not computable here).")


if __name__ == "__main__":
    main()
