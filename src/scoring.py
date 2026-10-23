"""
scoring.py - The three-stage prioritization model (section 5.2.1) and its
evaluation against the baselines on each inventory.

  Stage 1 Threat gate : in KEV at the cutoff, OR EPSS >= threshold
  Stage 2 Criticality : order by the asset's tier (Critical > High > Medium > Low)
  Stage 3 Tie-break   : within a tier, higher CVSS first
  (Any remaining ties are broken by EPSS, a documented implementation choice.)
  Non-gated CVEs are deprioritized, not discarded.

Usage (venv active):
    python src/assets.py
    python src/scoring.py --cutoff 2024-06-30
    python src/scoring.py --cutoff 2024-06-30 --epss-threshold 0.088
"""
import argparse
from pathlib import Path

import pandas as pd

from assets import explode_products, load_inventory, match_vulns
from baselines import (load, rank_cvss_only, rank_epss_kev_only, rank_fifo,
                       recall_at_n)


# ----------------------------------------------------------------- model
def apply_model(pairs, thr):
    """Rank (CVE, asset) pairs, then keep each CVE once at its most critical
    asset. Returns one row per CVE, best first."""
    p = pairs.copy()
    p["gate"] = p["kev_at_cutoff"] | (p["epss"] >= thr)
    p = p.sort_values(["gate", "tier_rank", "cvss", "epss"],
                      ascending=[False, False, False, False], kind="stable")
    return p.drop_duplicates("cve_id").reset_index(drop=True)


def explain(r, thr):
    if r["kev_at_cutoff"]:
        why = f"listed in CISA KEV (added {r['kev_date_added']:%Y-%m-%d})"
    elif r["gate"]:
        why = f"EPSS {r['epss']:.3f} is above the {thr} threshold"
    else:
        why = "not in KEV and EPSS below threshold (deprioritized)"
    return (f"{why}; affects {r['asset_name']} (tier {r['tier']}); "
            f"CVSS {r['cvss']:.1f}")


# ------------------------------------------------------------ evaluation
def cve_level(pairs):
    return pairs.drop_duplicates("cve_id").reset_index(drop=True)


def recall_table(pairs, thr, ns):
    cves = cve_level(pairs)
    total = int(cves["exploited_after"].sum())
    ranked = {
        "Model": apply_model(pairs, thr),
        "CVSS-only": rank_cvss_only(cves),
        "EPSS/KEV-only": rank_epss_kev_only(cves),
        "FIFO": rank_fifo(cves),
    }
    rows = []
    for name, r in ranked.items():
        rows.append({"strategy": name,
                     **{f"R@{n}": recall_at_n(r, n) for n in ns}})
    rows.append({"strategy": "Random (expected)",
                 **{f"R@{n}": min(n, len(cves)) / len(cves) for n in ns}})
    return pd.DataFrame(rows).set_index("strategy").round(3), ranked["Model"], total


def urgent_table(pairs, thr):
    cves = cve_level(pairs)
    total = int(cves["exploited_after"].sum())
    gate = cves["kev_at_cutoff"] | (cves["epss"] >= thr)
    sets = {"Model urgent set (Stage 1 gate)": gate,
            "CVSS >= 7.0": cves["cvss"] >= 7.0,
            "Patch everything": pd.Series(True, index=cves.index)}
    rows = []
    for name, m in sets.items():
        found = int(cves.loc[m, "exploited_after"].sum())
        rows.append({"urgent set": name, "size": int(m.sum()),
                     "% of pool": round(100 * m.mean(), 1),
                     "exploited found": found,
                     "coverage": round(found / total, 3) if total else float("nan")})
    return pd.DataFrame(rows).set_index("urgent set")


def run(df, args):
    prod_df = explode_products(df)
    inv_files = sorted(Path(args.inventories).glob("*.csv"))
    if not inv_files:
        raise SystemExit("No inventories found. Run: python src/assets.py")
    ns = tuple(int(x) for x in args.ns.split(","))
    Path("results").mkdir(exist_ok=True)
    pd.set_option("display.width", 200)

    for f in inv_files:
        inv = load_inventory(f)
        print(f"\n################ {f.stem}  ({len(inv)} assets) ################")
        pairs = match_vulns(df, prod_df, inv)
        if pairs.empty:
            print("  no matching CVEs")
            continue
        # Pool B only: CVEs already in KEV at the cutoff are known threats
        pool = pairs[~pairs["kev_at_cutoff"]].copy()
        n_cve, pos = pool["cve_id"].nunique(), \
            int(cve_level(pool)["exploited_after"].sum())
        print(f"  pool (excl. KEV-at-cutoff): {n_cve} CVEs, {pos} exploited "
              f"after cutoff, EPSS threshold {args.epss_threshold}")
        if pos == 0:
            print("  no positives in this pool, skipping")
            continue
        table, model_rank, _ = recall_table(pool, args.epss_threshold, ns)
        print("\n  Recall@N (CVE level)"); print(table.to_string())
        print("\n  Urgent-set size and coverage")
        print(urgent_table(pool, args.epss_threshold).to_string())

        top = model_rank.head(100).copy()
        top["reason"] = top.apply(lambda r: explain(r, args.epss_threshold), axis=1)
        top[["cve_id", "asset_name", "tier", "cvss", "epss", "gate",
             "exploited_after", "reason"]].to_csv(
            f"results/ranked_{f.stem}.csv", index=False)

    if args.sweep:
        print("\n######## EPSS threshold sensitivity (all inventories pooled) ########")
        print("NOTE: sensitivity analysis only. Do not pick the final threshold "
              "from this table; derive it on a separate training period.")
        allp = pd.concat([match_vulns(df, prod_df, load_inventory(f))
                          for f in inv_files], ignore_index=True)
        allp = allp[~allp["kev_at_cutoff"]]
        rows = []
        for t in (float(x) for x in args.sweep.split(",")):
            u = urgent_table(allp, t).iloc[0]
            rows.append({"threshold": t, "urgent size": u["size"],
                         "% of pool": u["% of pool"],
                         "exploited found": u["exploited found"],
                         "coverage": u["coverage"]})
        print(pd.DataFrame(rows).set_index("threshold").to_string())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cutoff", required=True)
    ap.add_argument("--data", default="data/processed/vulns.csv")
    ap.add_argument("--horizon-end", default=None,
                    help="Only count KEV additions up to this date (YYYY-MM-DD)")
    ap.add_argument("--inventories", default="data/inventories")
    ap.add_argument("--epss-threshold", type=float, default=0.088)
    ap.add_argument("--ns", default="25,50,100,250,500")
    ap.add_argument("--sweep", default="0.001,0.005,0.01,0.05,0.088,0.2",
                    help="Comma-separated thresholds ('' to skip)")
    a = ap.parse_args()
    df = load(a.data, a.cutoff, a.horizon_end)
    df["products"] = df["products"].fillna("")
    run(df, a)


if __name__ == "__main__":
    main()
