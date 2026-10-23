"""
diagnose.py - Which products do the later-exploited CVEs belong to, and how
selective is the EPSS threshold inside each inventory compared with the
whole database?

Usage:
    python src/diagnose.py --cutoff 2024-06-30 --horizon-end 2025-06-30 --epss-threshold 0.005
"""
import argparse
from pathlib import Path

import pandas as pd

from assets import explode_products, load_inventory, match_vulns
from baselines import load


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cutoff", required=True)
    ap.add_argument("--horizon-end", default=None)
    ap.add_argument("--data", default="data/processed/vulns.csv")
    ap.add_argument("--inventories", default="data/inventories")
    ap.add_argument("--epss-threshold", type=float, default=0.005)
    a = ap.parse_args()
    pd.set_option("display.width", 200)

    df = load(a.data, a.cutoff, a.horizon_end)
    df["products"] = df["products"].fillna("")
    pool = df[~df["kev_at_cutoff"]].copy()
    pos = pool[pool["exploited_after"]]
    print(f"Pool: {len(pool)} CVEs, {len(pos)} exploited after cutoff\n")

    # 1) where do the positives live?
    pp = explode_products(pos)
    pp = pp[pp["product"] != ""].copy()
    pp["vendor"] = pp["product"].str.split(":").str[0]
    n_noprod = len(pos) - pp["cve_id"].nunique()
    print(f"Positives with no product data in NVD: {n_noprod}")
    print("\nTop vendors among later-exploited CVEs (CVEs per vendor):")
    print(pp.drop_duplicates(["cve_id", "vendor"]).groupby("vendor").size()
          .sort_values(ascending=False).head(15).to_string())

    # 2) how many positives touch ANY inventory product?
    all_prod = explode_products(pool)
    covered = set()
    inv_files = sorted(Path(a.inventories).glob("*.csv"))
    rows = []
    for f in inv_files:
        pairs = match_vulns(pool, all_prod, load_inventory(f))
        ids = set(pairs["cve_id"])
        covered |= ids
        sub = pool[pool["cve_id"].isin(ids)]
        rows.append({"inventory": f.stem, "CVEs": len(sub),
                     "positives": int(sub["exploited_after"].sum()),
                     f"% with EPSS>={a.epss_threshold}":
                         round(100 * (sub["epss"] >= a.epss_threshold).mean(), 1)})
    rows.append({"inventory": "WHOLE DATABASE", "CVEs": len(pool),
                 "positives": len(pos),
                 f"% with EPSS>={a.epss_threshold}":
                     round(100 * (pool["epss"] >= a.epss_threshold).mean(), 1)})
    print(f"\nPositives that match at least one inventory product: "
          f"{int(pool[pool['cve_id'].isin(covered)]['exploited_after'].sum())} "
          f"of {len(pos)}")
    print("\nSelectivity of the EPSS threshold:")
    print(pd.DataFrame(rows).set_index("inventory").to_string())


if __name__ == "__main__":
    main()
