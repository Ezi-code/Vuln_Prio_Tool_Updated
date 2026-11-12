"""
evaluate_model.py - Objective 3 / RQ3: the FROZEN model against the baselines,
using exactly the metrics of sections 3.1, 5.4 and 5.5.

Metrics
  Coverage            Recall@N with Precision@N
  Workload reduction  Stage 1 candidate-gate size versus the final operational
                      list, and coverage of later-exploited CVEs
  Ranking agreement   Spearman's rho and top-N overlap between the model and
                      each baseline
  Feasibility         time to match and rank an inventory on this machine
  Asset tiers         recall/precision for each of the four priority categories
Baselines (5.5): CVSS-only, EPSS/KEV-only, FIFO (+ a random reference row).
Validation (5.6): KEV/EPSS frozen at the cutoff; labels = KEV additions after
the cutoff, up to --horizon-end. By default the threshold is read from
model_config.json and is NOT changed here. --gate-share optionally replaces it
with a label-free, per-inventory top-q% EPSS gate (the candidate experiment).
Inventories vary in size and sector. Intervals resample inventories AND the
later-exploited CVEs; every claim is a paired difference against a named
baseline.

Usage:
    python src/evaluate_model.py --cutoff 2024-06-30 --horizon-end 2025-06-30
    python src/evaluate_model.py --cutoff 2024-06-30 --horizon-end 2025-06-30 \
        --budgets 0.10,0.20,0.30 --budget 0.10
    python src/evaluate_model.py --cutoff 2024-06-30 --horizon-end 2025-06-30 \
        --gate-share 0.20 --outdir results/thesis_wide_gate

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

from assets import TIER_RANK, TIERS, explode_products, tier_from_total
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


def kN(N, n):
    """N items, or a share N<1 of an n-item list (predefined patching budget)."""
    return max(1, int(round(N * n))) if isinstance(N, float) else N


def nlabel(N):
    return f"{N:.0%}" if isinstance(N, float) else str(N)


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
    ap.add_argument("--gate-share", type=float, default=None,
                    help="Label-free Stage 1 alternative: gate the top share "
                         "of each inventory's EPSS distribution (e.g. 0.02). "
                         "Overrides the fixed threshold for the Model row.")
    ap.add_argument("--outdir", default="results",
                    help="Directory for per-inventory and summary outputs")
    ap.add_argument("--budget", type=float, default=0.10,
                    help="Final operational list share for the workload table "
                         "and tier summary (default: 0.10)")
    ap.add_argument("--ns", default="50,100,250,500,1000")
    ap.add_argument("--budgets", default="0.10,0.20,0.30",
                    help="predefined patching budgets as shares of each list, "
                         "e.g. 0.1,0.2,0.3 (replaces --ns; pass '' to use "
                         "absolute --ns values)")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--reps", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--sensitivity", action="store_true",
                    help="section 5.6: vary Stage 1 threshold and criticality weight (descriptive only)")
    a = ap.parse_args()
    if a.gate_share is not None and not 0 < a.gate_share < 1:
        raise SystemExit("--gate-share must be between 0 and 1 (e.g. 0.02)")
    pd.set_option("display.width", 240)
    rng = np.random.default_rng(a.seed)
    NS = (tuple(float(x) for x in a.budgets.split(",")) if a.budgets
          else tuple(int(x) for x in a.ns.split(",")))
    outdir = Path(a.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    cfg = json.loads(Path(a.config).read_text())
    df = load(a.data, a.cutoff, a.horizon_end)
    df["products"] = df["products"].fillna("")
    base = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    if a.rederive_threshold:
        share = float(cfg["stage1"].get("pool_share_at_threshold", a.budget))
        thr = float(base["epss"].quantile(1 - share))
        how = f"frozen Stage 1 pool share re-applied to this period (top {share:.2%} of the pool, label-free)"
    else:
        thr = float(cfg["stage1"]["epss_threshold"])
        how = f"frozen number from {a.config} (created {cfg['created']})"
    if a.gate_share is not None:
        gate_label = f"per-inventory top {a.gate_share:.1%} EPSS gate (label-free)"
    else:
        gate_label = f"fixed EPSS threshold {thr:.5f}: {how}"
    pos_ids = base.loc[base["exploited_after"], "cve_id"].to_numpy()
    pos_index = {c: i for i, c in enumerate(pos_ids)}
    P = len(pos_ids)
    print(f"Test pool: {len(base)} CVEs, {P} later-exploited (labels to "
          f"{a.horizon_end or 'today'}). Model gate: {gate_label}")
    if a.gate_share is not None:
        print(f"  (fixed threshold {thr:.5f} is retained for the sensitivity table only)")

    tokens = {t for _, opts, *_ in CATALOGUE for o in opts for t in o}
    sets = token_cve_sets(explode_products(base), tokens)

    rows, Pm, sector_of = [], [], []
    tier_rows = []
    keys = [(s, N) for s in STRATS for N in NS] + \
           [("UrgModel", 0), ("UrgModelTop", 0), ("UrgCVSS7", 0),
            ("UrgAll", 0)]
    if a.rederive_threshold:   # EPSS scales differ between model versions: use pool shares
        q = lambda share: float(base["epss"].quantile(1 - share))
        SENS_T = {"gate off": 0.0, "top 20%": q(0.20), "top 10%": q(0.10),
                  "Stage 1 share (FROZEN)": thr, "top 2%": q(0.02),
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
        model_o = rank_pool(pool, thr, None, gate_share=a.gate_share)
        t3 = time.perf_counter()
        orders = {"Model": model_o, "CVSS-only": rank_cvss_only(pool),
                  "EPSS/KEV-only": rank_epss_kev_only(pool), "FIFO": rank_fifo(pool)}
        t_match.append(t1 - t0); t_rank.append(t3 - t2); sizes.append(n)
        Pm.append(present); sector_of.append(sector)

        def found_of(mask_or_top):
            obj = (pool.loc[mask_or_top] if isinstance(mask_or_top, pd.Series)
                   else mask_or_top)
            f = np.zeros(P)
            ids = obj.loc[obj["exploited_after"], "cve_id"]
            if len(ids):
                f[ids.map(pos_index).to_numpy()] = 1.0
            return f

        for s, o in orders.items():
            for N in NS:
                top = o.head(kN(N, n))
                Fm[(s, N)].append(found_of(top))
                prec[(s, N)].append(top["exploited_after"].sum() / max(len(top), 1))
        for N in NS:
            Fm[("Random", N)].append(present * min(kN(N, n), n) / n)
            prec[("Random", N)].append(pool["exploited_after"].mean())
        pm = positions(model_o, n)
        for b in BASES:
            pb = positions(orders[b], n)
            rho[b].append(float(np.corrcoef(pm, pb)[0, 1]))
            for N in (100, 250):
                ovl[(b, N)].append(len(np.intersect1d(
                    model_o.index[:N], orders[b].index[:N])) / N)
        if a.gate_share is not None:
            gate_cut = float(pool["epss"].quantile(1 - a.gate_share))
        else:
            gate_cut = thr
        gate = pool["kev_at_cutoff"] | (pool["epss"] >= gate_cut)
        top_model = model_o.head(kN(a.budget, n))
        urg = {"UrgModel": gate, "UrgModelTop": top_model,
               "UrgCVSS7": pool["cvss"] >= 7.0,
               "UrgAll": pd.Series(True, index=pool.index)}
        row = {"sector": sector, "pool": n, "positives": int(present.sum())}
        for k, m in urg.items():
            Fm[(k, 0)].append(found_of(m))
            row[k] = int(m.sum()) if isinstance(m, pd.Series) else int(len(m))
        for N in NS:
            top = model_o.head(kN(N, n))
            for tier in TIERS:
                pos_mask = pool["exploited_after"] & (pool["tier_rank"] == TIER_RANK[tier])
                found_mask = top["exploited_after"] & (top["tier_rank"] == TIER_RANK[tier])
                tier_rows.append({
                    "sector": sector, "budget": N, "asset_tier": tier,
                    "positives": int(pos_mask.sum()),
                    "found": int(found_mask.sum()),
                    "top_items": int((top["tier_rank"] == TIER_RANK[tier]).sum()),
                    "top_size": int(len(top)),
                })
        if a.sensitivity:
            for tn, t in SENS_T.items():
                m = pool["kev_at_cutoff"] | (pool["epss"] >= t)
                Fm[(f"U|{tn}", 0)].append(found_of(pool[m]))
                sens_share[tn].append(float(m.mean()))
                for ln, lam in SENS_L.items():
                    o = rank_pool(pool, t, lam)
                    for N in SENS_N:
                        Fm[(f"S|{tn}|{ln}", N)].append(found_of(o.head(kN(N, n))))
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
    print(pd.DataFrame({f"R@{nlabel(N)}": {s: f2(pt[("recall", s, N)], boot[("recall", s, N)])
                                    for s in STRATS} for N in NS}).to_string())
    print("\n--- Model MINUS each baseline (a CI that excludes 0 holds up) ---")
    print(pd.DataFrame({f"R@{nlabel(N)}": {b: fmt(pt[("recall", "Model", N)] - pt[("recall", b, N)],
                                         boot[("recall", "Model", N)] - boot[("recall", b, N)])
                                    for b in BASES + ["Random"]} for N in NS}).to_string())
    print("\n=== Precision@N, mean [95% CI over inventories] ===")
    print(pd.DataFrame({f"P@{nlabel(N)}": {s: ci(np.array(prec[(s, N)]), rng) for s in STRATS}
                        for N in NS}).to_string())

    print("\n=== 2. WORKLOAD: urgent-list size and coverage of later-exploited CVEs ===")
    allv = res["UrgAll"].to_numpy(float)
    wl = {}
    for lab, k in (
        ("Stage 1 candidate gate", "UrgModel"),
        (f"Model top {a.budget:.0%} (final list)", "UrgModelTop"),
        ("CVSS >= 7.0 list", "UrgCVSS7"),
        ("Patch everything", "UrgAll"),
    ):
        wl[lab] = {"mean size": f"{res[k].mean():.0f}",
                   "% of list": f"{100 * (res[k] / res['UrgAll']).mean():.1f}%",
                   "coverage": f2(pt[("recall", k, 0)], boot[("recall", k, 0)])}
    print(pd.DataFrame(wl).T.to_string())
    print("Workload reduction achieved by the final model list, mean [95% CI over inventories]:")
    print(f"  vs patch-everything: {ci(1 - res['UrgModelTop'].to_numpy() / allv, rng)}")
    print(f"  vs CVSS >= 7.0     : {ci(1 - res['UrgModelTop'].to_numpy() / res['UrgCVSS7'].to_numpy(), rng)}")
    print("  (The Stage 1 candidate gate is reported separately; it may be wider than the final list.)")

    tier_df = pd.DataFrame(tier_rows)
    tier_summary = {}
    if len(tier_df):
        for N in NS:
            d = tier_df[tier_df["budget"] == N]
            total_pos = int(d["positives"].sum())
            total_found = int(d["found"].sum())
            rows_t = {}
            for tier in TIERS:
                t = d[d["asset_tier"] == tier]
                pos, found = int(t["positives"].sum()), int(t["found"].sum())
                top_items = int(t["top_items"].sum())
                rows_t[tier] = {
                    "positives": pos,
                    "found": found,
                    "recall": float(found / pos) if pos else float("nan"),
                    "share_of_positives": float(pos / total_pos) if total_pos else float("nan"),
                    "share_of_found": float(found / total_found) if total_found else float("nan"),
                    "top_items": top_items,
                    "precision": float(found / top_items) if top_items else float("nan"),
                }
            tier_summary[nlabel(N)] = rows_t
        primary = a.budget
        primary_key = nlabel(primary)
        if primary_key not in tier_summary:
            primary_key = nlabel(NS[0])
        print(f"\n=== 3. ASSET TIERS AS PRIORITY CATEGORIES: Model at {primary_key} final list ===")
        print(pd.DataFrame(tier_summary[primary_key]).T.to_string())

    print("\n=== 4. RANKING AGREEMENT of the model with each baseline (mean [95% CI]) ===")
    print(pd.DataFrame({
        "Spearman rho": {b: ci(np.array(rho[b]), rng) for b in BASES},
        "top-100 overlap": {b: ci(np.array(ovl[(b, 100)]), rng) for b in BASES},
        "top-250 overlap": {b: ci(np.array(ovl[(b, 250)]), rng) for b in BASES}}).to_string())

    tm, tr = np.array(t_match) * 1000, np.array(t_rank) * 1000
    print("\n=== 5. COMPUTATIONAL FEASIBILITY (no GPU, no paid feeds) ===")
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

    ref_n = NS[0]
    print(f"\n=== By sector: Recall @ {nlabel(ref_n)} (point estimates) ===")
    sec = pd.DataFrame({s: [F[(s, ref_n)][i].sum() / M[i].sum() for i in range(len(M))]
                        for s in STRATS})
    sec["sector"] = sector_of
    sec_summary = sec.groupby("sector").mean().round(3)
    print(sec_summary.to_string())

    res.to_csv(outdir / f"evaluation_{a.cutoff}.csv", index=False)

    def mean_ci(arr):
        lo, hi = np.nanpercentile(arr, [2.5, 97.5])
        return {"mean": float(np.nanmean(arr)),
                "ci95": [float(lo), float(hi)]}

    summary = {
        "created": pd.Timestamp.now().isoformat(timespec="seconds"),
        "data": a.data, "config": a.config,
        "cutoff": a.cutoff, "horizon_end": a.horizon_end,
        "fixed_threshold": float(thr), "gate_share": a.gate_share,
        "gate_label": gate_label,
        "inventories": int(len(res)),
        "pool": {"min": int(res["pool"].min()),
                 "max": int(res["pool"].max()),
                 "mean": float(res["pool"].mean())},
        "positives": {"global": int(P),
                      "mean_per_inventory": float(res["positives"].mean())},
        "recall": {s: {nlabel(N): {"point": float(pt[("recall", s, N)]),
                                    "ci95": [float(x) for x in np.nanpercentile(
                                        boot[("recall", s, N)], [2.5, 97.5])]}
                       for N in NS} for s in STRATS},
        "precision": {s: {nlabel(N): mean_ci(np.array(prec[(s, N)]))
                          for N in NS} for s in STRATS},
        "workload": {
            "stage1_gate_mean_size": float(res["UrgModel"].mean()),
            "stage1_gate_pct_of_list": float(100 * (res["UrgModel"] / res["UrgAll"]).mean()),
            "stage1_gate_coverage": float(pt[("recall", "UrgModel", 0)]),
            "model_top_budget": float(a.budget),
            "model_top_mean_size": float(res["UrgModelTop"].mean()),
            "model_top_pct_of_list": float(100 * (res["UrgModelTop"] / res["UrgAll"]).mean()),
            "model_top_coverage": float(pt[("recall", "UrgModelTop", 0)]),
            "cvss7_mean_size": float(res["UrgCVSS7"].mean()),
            "cvss7_pct_of_list": float(100 * (res["UrgCVSS7"] / res["UrgAll"]).mean()),
            "cvss7_coverage": float(pt[("recall", "UrgCVSS7", 0)]),
        },
        "by_asset_tier": tier_summary,
        "ranking": {
            "spearman": {b: mean_ci(np.array(rho[b])) for b in BASES},
            "top100_overlap": {b: mean_ci(np.array(ovl[(b, 100)])) for b in BASES},
            "top250_overlap": {b: mean_ci(np.array(ovl[(b, 250)])) for b in BASES},
        },
        "timing_ms": {
            "match_median": float(np.median(tm)),
            "rank_median": float(np.median(tr)),
        },
        "by_sector": sec_summary.to_dict(orient="index"),
    }
    (outdir / f"evaluation_{a.cutoff}_summary.json").write_text(
        json.dumps(summary, indent=2, default=float), encoding="utf-8")
    print(f"\nPer-inventory sizes saved to {outdir / f'evaluation_{a.cutoff}.csv'}")
    print(f"Full metrics summary saved to {outdir / f'evaluation_{a.cutoff}_summary.json'}")
    print("5. Instrument usability: practitioner review (not computable here).")


if __name__ == "__main__":
    main()
