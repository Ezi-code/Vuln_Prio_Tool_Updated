"""
stage1.py - Stage 1, the Threat Gate (section 5.2.1), built and evaluated on its own.

  A CVE is FLAGGED if it is in KEV (as of the cutoff) OR its EPSS score is at or
  above a threshold. Unflagged CVEs are deprioritized, not discarded.

Threshold: "follows the VMC method but is re-derived on this study's data".
VMC balances EFFICIENCY (share of flagged CVEs really exploited) against
COVERAGE (share of exploited CVEs flagged). With very rare exploitation the
literal F1 balance picks an almost empty gate, so `derive` makes the criterion
an explicit choice (f1, coverage, youden or budget), prints what each would
pick, and uses TRAINING data only. A bootstrap over the exploited CVEs shows how
stable the choice is, and the threshold is also stored as a share of the pool
so it can be re-applied when the EPSS model version changes.

Two commands:
  derive   -> trade-off curve on the training period, picks the threshold,
              writes stage1_config.json
  evaluate -> Stage 1 alone on a period: efficiency, coverage, workload,
              against CVSS>=7.0, EPSS>=0.088 (VMC) and patch-everything

    python src/stage1.py derive --train-cutoff 2023-06-30 --test-cutoff 2024-06-30 \
        --criterion coverage --target-coverage 0.5
    python src/stage1.py evaluate --data data/processed/vulns_train.csv \
        --cutoff 2023-06-30 --horizon-end 2024-06-30
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

from baselines import load

VMC_THRESHOLD = 0.088


# ------------------------------------------------------------- the gate itself
def apply_stage1(df, thr):
    """Add stage1_flag and a plain-language stage1_reason. Needs kev_at_cutoff,
    epss, and (optionally) kev_date_added. Missing EPSS is treated as 0 (not
    flagged unless in KEV); has_epss tells which rows lacked a score."""
    out = df.copy()
    out["stage1_flag"] = out["kev_at_cutoff"] | (out["epss"] >= thr)

    def why(r):
        if r["kev_at_cutoff"]:
            d = r.get("kev_date_added")
            d = f" (added {d:%Y-%m-%d})" if pd.notna(d) else ""
            return f"In the CISA KEV catalog{d}"
        if r["epss"] >= thr:
            return f"EPSS {r['epss']:.4f} is at or above the threshold {thr:.4f}"
        return f"Not flagged: not in KEV and EPSS {r['epss']:.4f} is below {thr:.4f}"
    out["stage1_reason"] = out.apply(why, axis=1)
    return out


# --------------------------------------------------------- trade-off and VMC rule
def make_grid(epss):
    shares = np.logspace(np.log10(0.0005), np.log10(0.5), 140)
    g = np.unique(np.concatenate([np.quantile(epss, 1 - shares), [VMC_THRESHOLD]]))
    return g[g > 0]


def tradeoff(pool, grid):
    pos = pool["exploited_after"].to_numpy()
    e = pool["epss"].to_numpy()
    P, N = int(pos.sum()), len(pool)
    rows = []
    for t in grid:
        f = e >= t
        n, tp = int(f.sum()), int((f & pos).sum())
        rows.append({"threshold": t, "flagged": n, "share": n / N,
                     "efficiency": tp / n if n else np.nan, "coverage": tp / P,
                     "f1": 2 * tp / (n + P) if n + P else 0.0,
                     "lift": (tp / P) / (n / N) if n else np.nan})
    return pd.DataFrame(rows)


def f1_optimum(tab):
    best = tab["f1"].max()
    return tab.loc[tab["f1"] >= best - 1e-12].iloc[0]   # smallest threshold at the maximum


def pick(tab, criterion, target=0.5, budget=0.05):
    """Choose a threshold from the trade-off table by an explicit criterion:
       f1       maximum F1 of efficiency and coverage (literal VMC-style balance)
       coverage the strictest threshold that still reaches a target coverage
       youden   maximum of (coverage - share of pool flagged)
       budget   the loosest threshold whose list stays within a share of the pool"""
    if criterion == "f1":
        return f1_optimum(tab)
    if criterion == "youden":
        return tab.loc[(tab["coverage"] - tab["share"]).idxmax()]
    if criterion == "coverage":
        ok = tab[tab["coverage"] >= target]
        return ok.loc[ok["threshold"].idxmax()] if len(ok) else tab.iloc[0]
    ok = tab[tab["share"] <= budget]
    return ok.iloc[0] if len(ok) else tab.iloc[0]


def bootstrap_choice(pool, grid, criterion, target, reps, rng):
    """Resample the exploited CVEs and re-pick the threshold each time
    (the budget rule uses no labels, so it has no sampling spread)."""
    if criterion == "budget":
        return None
    pe = pool.loc[pool["exploited_after"], "epss"].to_numpy()
    P, N = len(pe), len(pool)
    nflag = np.array([(pool["epss"].to_numpy() >= t).sum() for t in grid])
    out = np.empty(reps)
    for i in range(reps):
        s_ = pe[rng.integers(0, P, P)]
        tp = (s_[:, None] >= grid[None, :]).sum(0)
        if criterion == "f1":
            j = int(np.argmax(2 * tp / (nflag + P)))
        elif criterion == "youden":
            j = int(np.argmax(tp / P - nflag / N))
        else:
            ok = np.where(tp / P >= target)[0]
            j = int(ok.max()) if len(ok) else 0
        out[i] = grid[j]
    return out


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()[:16]


def pretty(df):
    f = df.copy()
    for c in ("share",):
        f[c] = (100 * f[c]).map("{:.2f}%".format)
    for c in ("efficiency", "coverage"):
        f[c] = (100 * f[c]).map("{:.2f}%".format)
    f["f1"] = f["f1"].map("{:.4f}".format)
    f["lift"] = f["lift"].map("{:.1f}x".format)
    f["threshold"] = f["threshold"].map("{:.4f}".format)
    return f


# ------------------------------------------------------------------- derive
def cmd_derive(a):
    rng = np.random.default_rng(a.seed)
    df = load(a.train_data, a.train_cutoff, horizon_end=a.test_cutoff)
    pool = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    P = int(pool["exploited_after"].sum())
    print(f"Training pool: {len(pool)} CVEs (known-KEV excluded), {P} exploited between "
          f"{a.train_cutoff} and {a.test_cutoff}")
    print(f"KEV at cutoff (always flagged by Stage 1): {int(df['kev_at_cutoff'].sum())}; "
          f"CVEs with no EPSS score (never flagged unless in KEV): {int((~df['has_epss']).sum())}")
    grid = make_grid(pool["epss"].to_numpy())
    tab = tradeoff(pool, grid)

    crits = {"f1": "F1 of efficiency and coverage",
             "coverage": f"strictest gate keeping coverage >= {a.target_coverage:.0%}",
             "youden": "maximum of coverage minus share flagged",
             "budget": f"loosest gate within {a.budget:.0%} of the pool"}
    rows = []
    for c, label in crits.items():
        r = pick(tab, c, a.target_coverage, a.budget)
        rows.append({"criterion": c, "rule": label, "EPSS threshold": f"{r['threshold']:.4f}",
                     "% of pool flagged": f"{100 * r['share']:.2f}%",
                     "coverage": f"{100 * r['coverage']:.1f}%",
                     "efficiency": f"{100 * r['efficiency']:.2f}%", "lift": f"{r['lift']:.1f}x",
                     "urgent items per 10,000 CVEs": int(round(r["share"] * 10000))})
    v = tab[tab["threshold"] == VMC_THRESHOLD].iloc[0]
    rows.append({"criterion": "(VMC value)", "rule": "0.088 from the VMC paper",
                 "EPSS threshold": "0.0880", "% of pool flagged": f"{100 * v['share']:.2f}%",
                 "coverage": f"{100 * v['coverage']:.1f}%", "efficiency": f"{100 * v['efficiency']:.2f}%",
                 "lift": f"{v['lift']:.1f}x", "urgent items per 10,000 CVEs": int(round(v["share"] * 10000))})
    pd.set_option("display.width", 250)
    print("\nWhat each criterion would choose on the training period:")
    print(pd.DataFrame(rows).set_index("criterion").to_string())

    best = pick(tab, a.criterion, a.target_coverage, a.budget)
    show = tab.iloc[::max(1, len(tab) // 20)].copy()
    show = pd.concat([show, tab[tab["threshold"] == VMC_THRESHOLD],
                      tab[tab["threshold"] == best["threshold"]]]).drop_duplicates("threshold")
    show = show.sort_values("threshold")
    show.insert(0, "mark", ["<- SELECTED" if t == best["threshold"] else
                            ("<- VMC 0.088" if t == VMC_THRESHOLD else "") for t in show["threshold"]])
    print("\nEfficiency-coverage trade-off on the training period:")
    print(pretty(show).to_string(index=False))

    print(f"\nSELECTED criterion: {a.criterion} ({crits[a.criterion]}) -> EPSS >= {best['threshold']:.4f}")
    print(f"  flags {best['share']:.2%} of the pool, efficiency {best['efficiency']:.2%}, "
          f"coverage {best['coverage']:.1%}, lift {best['lift']:.1f}x over random")
    boots = bootstrap_choice(pool, grid, a.criterion, a.target_coverage, a.reps, rng)
    if boots is None:
        spread = None
        print("  (the budget rule uses no labels, so it has no sampling spread)")
    else:
        lo, med, hi = np.percentile(boots, [2.5, 50, 97.5])
        spread = [round(float(x), 5) for x in (med, lo, hi)]
        print(f"  stability: over {a.reps} resamples of the exploited CVEs the chosen threshold had "
              f"median {med:.4f}, 95% range [{lo:.4f}, {hi:.4f}]")
        if hi - lo > 0.10:
            print("  WARNING: the 95% range spans more than 0.10. This threshold "
                  "is not well identified by the available positives; prefer a "
                  "label-free workload/percentile rule, or pool more periods.")
    try:
        ver = str(pd.read_csv(a.train_data, usecols=["epss_model_version"], nrows=1).iloc[0, 0])
    except (ValueError, IndexError):
        ver = "unknown"
    cfg = {"created": datetime.datetime.now().isoformat(timespec="seconds"),
           "stage": "Stage 1 threat gate (section 5.2.1)",
           "criterion": a.criterion, "rule": crits[a.criterion],
           "target_coverage": a.target_coverage, "budget": a.budget,
           "train_data": a.train_data, "train_data_sha256_16": sha(a.train_data),
           "train_cutoff": a.train_cutoff, "label_horizon_end": a.test_cutoff,
           "train_pool": int(len(pool)), "train_positives": P, "epss_model_version": ver,
           "epss_threshold": round(float(best["threshold"]), 5),
           "pool_share_at_threshold": round(float(best["share"]), 6),
           "efficiency_at_threshold": round(float(best["efficiency"]), 5),
           "coverage_at_threshold": round(float(best["coverage"]), 4),
           "bootstrap_threshold_median_and_95pct_range": spread,
           "policy": {"kev": "flagged if listed in KEV on or before the cutoff",
                      "missing_epss": "treated as 0, so not flagged unless in KEV",
                      "unflagged": "deprioritized, never discarded"},
           "reference": {"vmc_threshold": VMC_THRESHOLD}}
    Path(a.out).write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    print(f"\nWritten to {a.out}. Agree the criterion with your supervisor before using it anywhere else.")


# ----------------------------------------------------------------- evaluate
def cmd_evaluate(a):
    rng = np.random.default_rng(a.seed)
    cfg = json.loads(Path(a.config).read_text())
    df = load(a.data, a.cutoff, a.horizon_end)
    pool = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    if a.use_share:
        thr = float(pool["epss"].quantile(1 - cfg["pool_share_at_threshold"]))
        how = f"the stored pool share {cfg['pool_share_at_threshold']:.2%} re-applied to this period's EPSS scores (label-free)"
    else:
        thr = float(cfg["epss_threshold"])
        how = f"the frozen number from {a.config}"
    try:
        ver = str(pd.read_csv(a.data, usecols=["epss_model_version"], nrows=1).iloc[0, 0])
        if ver != cfg["epss_model_version"] and not a.use_share:
            print(f"WARNING: this period uses EPSS {ver} but the threshold was derived on "
                  f"{cfg['epss_model_version']}. Re-run with --use-share.")
    except (ValueError, IndexError):
        ver = "unknown"
    pos = pool["exploited_after"].to_numpy()
    P, N = int(pos.sum()), len(pool)
    print(f"Period cutoff {a.cutoff} (labels to {a.horizon_end}); EPSS model {ver}")
    print(f"Pool {N} CVEs (known-KEV excluded), {P} exploited later; Stage 1 threshold {thr:.5f} from {how}")
    print(f"KEV at cutoff (always flagged, not scored): {int(df['kev_at_cutoff'].sum())}; no EPSS score: {int((~df['has_epss']).sum())}")

    methods = {"Stage 1 (this study)": pool["epss"] >= thr,
               "EPSS >= 0.088 (VMC value)": pool["epss"] >= VMC_THRESHOLD,
               "CVSS >= 7.0": pool["cvss"] >= 7.0,
               "VMC chain: EPSS>=0.088 and CVSS>=7.0": (pool["epss"] >= VMC_THRESHOLD) & (pool["cvss"] >= 7.0),
               "Patch everything": pd.Series(True, index=pool.index)}
    pe_idx = np.where(pos)[0]
    rows = []
    n_all = N
    n_cvss = int(methods["CVSS >= 7.0"].sum())
    for name, m in methods.items():
        mk = m.to_numpy()
        n = int(mk.sum()); tp = int((mk & pos).sum())
        boots_cov, boots_eff = [], []
        for _ in range(a.reps):
            s = rng.integers(0, P, P)
            tpb = mk[pe_idx[s]].sum()
            boots_cov.append(tpb / P); boots_eff.append(tpb / n if n else np.nan)
        cl, ch = np.percentile(boots_cov, [2.5, 97.5])
        el, eh = np.nanpercentile(boots_eff, [2.5, 97.5])
        rows.append({"method": name, "urgent size": n, "% of pool": f"{100 * n / N:.2f}%",
                     "exploited found": f"{tp}/{P}",
                     "coverage [95% CI]": f"{100 * tp / P:.1f}% [{100 * cl:.1f}, {100 * ch:.1f}]",
                     "efficiency [95% CI]": f"{100 * tp / n:.2f}% [{100 * el:.2f}, {100 * eh:.2f}]" if n else "n/a",
                     "lift": f"{(tp / P) / (n / N):.1f}x" if n else "n/a",
                     "fewer urgent than patch-all": f"{100 * (1 - n / n_all):.1f}%",
                     "fewer than CVSS>=7": f"{100 * (1 - n / n_cvss):.1f}%"})
    pd.set_option("display.width", 250)
    print("\nStage 1 alone (global pool, not per organization):")
    print(pd.DataFrame(rows).set_index("method").to_string())
    print("Lift = coverage / share of pool flagged; 1.0x is no better than flagging at random.")
    print("Note: KEV-at-cutoff CVEs are always flagged operationally but are "
          "excluded from this table so it measures new exploitation only.")

    # load() fills missing EPSS with 0 and records missingness in has_epss, so
    # filtering on epss.notna() would silently drop no rows. Keep all rows;
    # KEV-at-cutoff rows must remain in the operational flag list.
    flagged = apply_stage1(df.reset_index(drop=True), thr)
    flagged = flagged[flagged["stage1_flag"]]
    Path("results").mkdir(exist_ok=True)
    out = f"results/stage1_flags_{a.cutoff}.csv"
    flagged[["cve_id", "published", "cvss", "epss", "kev_at_cutoff", "exploited_after",
             "stage1_reason"]].to_csv(out, index=False)
    print(f"\n{len(flagged)} flagged CVEs with their plain-language reasons saved to {out}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("--train-data", default="data/processed/vulns_train.csv")
    d.add_argument("--train-cutoff", required=True)
    d.add_argument("--test-cutoff", required=True, help="training labels stop here")
    d.add_argument("--criterion", required=True, choices=["f1", "coverage", "youden", "budget"],
                   help="how to pick the threshold (a deliberate choice; see the printed comparison)")
    d.add_argument("--target-coverage", type=float, default=0.5,
                   help="used by --criterion coverage")
    d.add_argument("--budget", type=float, default=0.05,
                   help="used by --criterion budget (share of the pool)")
    d.add_argument("--reps", type=int, default=1000)
    d.add_argument("--seed", type=int, default=42)
    d.add_argument("--out", default="stage1_config.json")
    e = sub.add_parser("evaluate")
    e.add_argument("--data", default="data/processed/vulns.csv")
    e.add_argument("--cutoff", required=True)
    e.add_argument("--horizon-end", default=None)
    e.add_argument("--config", default="stage1_config.json")
    e.add_argument("--use-share", action="store_true",
                   help="re-apply the stored pool share instead of the number (use when the EPSS model version differs)")
    e.add_argument("--reps", type=int, default=1000)
    e.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    {"derive": cmd_derive, "evaluate": cmd_evaluate}[a.cmd](a)


if __name__ == "__main__":
    main()
