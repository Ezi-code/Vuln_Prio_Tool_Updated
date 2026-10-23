"""
criteria_analysis.py - Objective 2 / RQ2: which criteria reliably indicate
asset criticality where asset-management maturity is low?

Computable parts (this script):
  1. Influence   how much each of the four criteria drives the tier
                 (tier changes when it is dropped, corrected item-total
                 correlation, Cronbach's alpha).
  2. Stability   how well the tier survives answer errors, as a rater would
                 make (exact agreement, within one tier, weighted kappa), for
                 the full instrument and for each three-question version.
  3. Validity    do higher tiers / higher criterion levels correspond to
                 products whose CVEs are later exploited more often?

IMPORTANT LIMITS. The answers are SIMULATED from asset-type assumptions in the
catalogue (e.g. a firewall is internet-facing), so parts 1-2 describe the
instrument's mechanics and part 3 shows whether product types that score high
are the ones attackers later exploit. None of this is evidence of how real IT
staff answer. Real reliability needs practitioners rating the same systems
(inter-rater / test-retest agreement) in the review of section 5.4.

Usage (training period by default, so the test period is not inspected again):
    python src/criteria_analysis.py --cutoff 2023-06-30 --horizon-end 2024-06-30 \
        --data data/processed/vulns_train.csv
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from assets import TIER_RANK, TIERS, explode_products, tier_from_total
from baselines import load
from evaluate_model import SECTORS
from montecarlo import CATALOGUE, token_cve_sets

CRIT = ["exposure", "data_sensitivity", "business_function", "redundancy"]
NAMES = [c[0] for c in CATALOGUE]


def sample_assets(rng, weights):
    k = int(rng.integers(6, 13))
    others = list(range(1, len(CATALOGUE)))
    p = np.array([weights.get(NAMES[i], 1.0) for i in others], float)
    picks = [0] + list(rng.choice(others, size=min(k - 1, len(others)),
                                  replace=False, p=p / p.sum()))
    out = []
    for i in picks:
        name, options, ex, se, fu, re_ = CATALOGUE[i]
        tokens = options[int(rng.integers(len(options)))]
        out.append({"type": name, "tokens": tokens,
                    "ans": [int(rng.integers(lo, hi + 1)) for lo, hi in (ex, se, fu, re_)]})
    return out


def tiers_of(totals):
    return np.array([TIER_RANK[tier_from_total(t)] for t in totals])


def wkappa(a, b, k=4):
    O = np.zeros((k, k))
    np.add.at(O, (a, b), 1)
    O /= O.sum()
    E = np.outer(O.sum(1), O.sum(0))
    W = np.abs(np.subtract.outer(np.arange(k), np.arange(k))) / (k - 1)
    den = (W * E).sum()
    return 1 - (W * O).sum() / den if den > 0 else float("nan")


def noisy(ans, p, rng):
    step = rng.choice([-1, 1], size=ans.shape) * (rng.random(ans.shape) < p)
    return np.clip(ans + step, 0, 3)


def pct(v):
    lo, hi = np.nanpercentile(v, [2.5, 97.5])
    return f"[{lo:.3f}, {hi:.3f}]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/vulns_train.csv")
    ap.add_argument("--cutoff", required=True)
    ap.add_argument("--horizon-end", default=None)
    ap.add_argument("--n", type=int, default=300, help="random inventories")
    ap.add_argument("--reps", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    pd.set_option("display.width", 220)
    rng = np.random.default_rng(a.seed)

    df = load(a.data, a.cutoff, a.horizon_end)
    df["products"] = df["products"].fillna("")
    base = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    pos_ids = base.loc[base["exploited_after"], "cve_id"].to_numpy()
    tokens = {t for _, opts, *_ in CATALOGUE for o in opts for t in o}
    sets = token_cve_sets(explode_products(base), tokens)
    print(f"Pool {len(base)} CVEs, {len(pos_ids)} later-exploited (labels to "
          f"{a.horizon_end or 'today'})")

    rows, secs = [], list(SECTORS)
    for i in range(a.n):
        for asset in sample_assets(rng, SECTORS[secs[i % len(secs)]]):
            arrs = [sets[t] for t in asset["tokens"] if len(sets[t])]
            ids = np.unique(np.concatenate(arrs)) if arrs else np.array([])
            rows.append({"type": asset["type"], **dict(zip(CRIT, asset["ans"])),
                         "n_cves": len(ids),
                         "n_pos": int(np.isin(ids, pos_ids).sum()) if len(ids) else 0})
    A = pd.DataFrame(rows)
    ans = A[CRIT].to_numpy()
    A["total"] = ans.sum(1)
    A["tier"] = tiers_of(A["total"])
    print(f"Simulated assets: {len(A)} (from {a.n} inventories)")

    # ---- 1. influence
    print("\n=== 1. INFLUENCE of each criterion on the tier ===")
    full = A["tier"].to_numpy()
    infl = {}
    for j, c in enumerate(CRIT):
        reduced = (A["total"] - A[c]) * 12 / 9
        t_red = tiers_of(reduced)
        infl[c] = {"tier changes if dropped": f"{np.mean(t_red != full):.1%}",
                   "item-total corr.": f"{np.corrcoef(A[c], A['total'] - A[c])[0, 1]:.2f}"}
    print(pd.DataFrame(infl).T.to_string())
    k = len(CRIT)
    alpha = k / (k - 1) * (1 - ans.var(0, ddof=1).sum() / A["total"].var(ddof=1))
    print(f"Cronbach's alpha of the four questions: {alpha:.2f} "
          "(partly determined by the catalogue assumptions)")

    # ---- 2. stability under answer errors
    print("\n=== 2. STABILITY of the tier when answers contain errors ===")
    print("Each answer is shifted by one point with probability p; the noisy tier is compared with the true tier.")
    out = {}
    for p in (0.1, 0.2, 0.3):
        ex, w1, kp = [], [], []
        for _ in range(a.reps // 5):
            r = rng.integers(0, len(A), len(A))
            nt = tiers_of(noisy(ans[r], p, rng).sum(1))
            tt = full[r]
            ex.append(np.mean(nt == tt)); w1.append(np.mean(np.abs(nt - tt) <= 1))
            kp.append(wkappa(tt, nt))
        out[f"p={p}"] = {"exact agreement": f"{np.mean(ex):.3f} {pct(ex)}",
                         "within one tier": f"{np.mean(w1):.3f} {pct(w1)}",
                         "weighted kappa": f"{np.mean(kp):.3f} {pct(kp)}"}
    print(pd.DataFrame(out).T.to_string())

    # ---- 3. validity against later exploitation
    print("\n=== 3. VALIDITY: later-exploited share of an asset's CVEs, by tier and criterion level ===")
    V = A[A["n_cves"] > 0].reset_index(drop=True)

    def rate(mask):
        d = V.loc[mask]
        return d["n_pos"].sum() / d["n_cves"].sum() if len(d) and d["n_cves"].sum() else np.nan

    def boot_rate(mask_fn, reps):
        out = []
        for _ in range(reps):
            r = V.iloc[rng.integers(0, len(V), len(V))]
            m = mask_fn(r)
            out.append(r.loc[m, "n_pos"].sum() / max(r.loc[m, "n_cves"].sum(), 1))
        return out

    t_rows = {}
    for t in range(4):
        b = boot_rate(lambda r, t=t: r["tier"] == t, a.reps // 2)
        t_rows[TIERS[t]] = {"assets": int((V["tier"] == t).sum()),
                            "exploited per 10,000 CVEs": f"{1e4 * rate(V['tier'] == t):.1f} "
                                                         f"[{1e4 * np.nanpercentile(b, 2.5):.1f}, {1e4 * np.nanpercentile(b, 97.5):.1f}]"}
    print(pd.DataFrame(t_rows).T.to_string())
    print("\nHigh (answer 2-3) versus low (0-1) on each criterion: rate ratio with 95% CI over assets")
    c_rows = {}
    for c in CRIT:
        hi, lo = V[c] >= 2, V[c] <= 1
        rat = []
        for _ in range(a.reps // 2):
            r = V.iloc[rng.integers(0, len(V), len(V))]
            h, l = r[c] >= 2, r[c] <= 1
            rh = r.loc[h, "n_pos"].sum() / max(r.loc[h, "n_cves"].sum(), 1)
            rl = r.loc[l, "n_pos"].sum() / max(r.loc[l, "n_cves"].sum(), 1)
            rat.append(rh / rl if rl > 0 else np.nan)
        c_rows[c] = {"assets high / low": f"{int(hi.sum())} / {int(lo.sum())}",
                     "rate ratio": f"{rate(hi) / rate(lo):.2f} "
                                   f"[{np.nanpercentile(rat, 2.5):.2f}, {np.nanpercentile(rat, 97.5):.2f}]"}
    print(pd.DataFrame(c_rows).T.to_string())
    print("(A ratio above 1 whose interval excludes 1 means assets scored high on that criterion hold more later-exploited CVEs.)")

    Path("results").mkdir(exist_ok=True)
    A.to_csv("results/criteria_assets.csv", index=False)
    print("\nPer-asset table saved to results/criteria_assets.csv")
    print("Real reliability (inter-rater, test-retest) and usability need practitioners: section 5.4.")


if __name__ == "__main__":
    main()
