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
    python src/scoring.py --cutoff 2024-06-30 --gate-share 0.02 \
        --outdir results/optimized
"""
import argparse
from pathlib import Path

import pandas as pd

from assets import explode_products, load_inventory, match_vulns
from baselines import (load, rank_cvss_only, rank_epss_kev_only, rank_fifo,
                       recall_at_n)
from model import gate_cutoff, rank_pool


# ----------------------------------------------------------------- model
def apply_model(pairs, thr, gate_share=None):
    """Rank (CVE, asset) pairs, then keep each CVE once at its most critical
    asset. Returns one row per CVE, best first.

    KEV-at-cutoff CVEs are kept in the operational ranking and placed first;
    the evaluation functions below use the Pool B subset (no known KEV) so the
    metrics measure new exploitation rather than already-known threats.
    """
    ranked = rank_pool(pairs, thr, None, gate_share=gate_share,
                       kev_first=True)
    return ranked.drop_duplicates("cve_id").reset_index(drop=True)


def explain(r, thr, gate_share=None):
    if r["kev_at_cutoff"]:
        why = f"listed in CISA KEV (added {r['kev_date_added']:%Y-%m-%d})"
    elif r["gate"]:
        if gate_share is not None:
            why = (f"EPSS {r['epss']:.3f} is in the top {gate_share:.1%} "
                   f"of this inventory")
        else:
            why = f"EPSS {r['epss']:.3f} is above the {thr} threshold"
    else:
        why = "not in KEV and EPSS below threshold (deprioritized)"
    return (f"{why}; affects {r['asset_name']} (tier {r['tier']}); "
            f"CVSS {r['cvss']:.1f}")


# ------------------------------------------------------------ evaluation
def cve_level(pairs):
    return pairs.drop_duplicates("cve_id").reset_index(drop=True)


def recall_table(pairs, thr, ns, gate_share=None):
    cves = cve_level(pairs)
    total = int(cves["exploited_after"].sum())
    ranked = {
        "Model": apply_model(pairs, thr, gate_share=gate_share),
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


def urgent_table(pairs, thr, gate_share=None):
    cves = cve_level(pairs)
    total = int(cves["exploited_after"].sum())
    cutoff = gate_cutoff(cves, thr, gate_share)
    gate = cves["kev_at_cutoff"] | (cves["epss"] >= cutoff)
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
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    gate_share = getattr(args, "gate_share", None)
    gate_label = (f"top {gate_share:.1%} of each inventory's EPSS"
                  if gate_share is not None
                  else f"EPSS threshold {args.epss_threshold}")
    pd.set_option("display.width", 200)

    for f in inv_files:
        inv = load_inventory(f)
        print(f"\n################ {f.stem}  ({len(inv)} assets) ################")
        pairs = match_vulns(df, prod_df, inv)
        if pairs.empty:
            print("  no matching CVEs")
            continue

        # Operational ranking: known KEV first, then the model's order.
        operational = apply_model(pairs, args.epss_threshold,
                                  gate_share=gate_share)
        top = operational.head(100).copy()
        top["reason"] = top.apply(
            lambda r: explain(r, args.epss_threshold, gate_share), axis=1)
        cols = ["cve_id", "asset_name", "tier", "cvss", "epss", "gate",
                "kev_at_cutoff", "exploited_after", "reason"]
        if "kev_date_added" in top.columns:
            cols.insert(7, "kev_date_added")
        out = outdir / f"ranked_{f.stem}.csv"
        top[cols].to_csv(out, index=False)
        n_kev = int(operational["kev_at_cutoff"].sum())
        print(f"  operational top-100 written to {out} "
              f"({n_kev} KEV-at-cutoff CVEs in this inventory; ranked first)")

        # Evaluation pool B: CVEs not already in KEV at the cutoff.
        pool = pairs[~pairs["kev_at_cutoff"]].copy()
        n_cve, pos = pool["cve_id"].nunique(), \
            int(cve_level(pool)["exploited_after"].sum())
        print(f"  pool (excl. KEV-at-cutoff): {n_cve} CVEs, {pos} exploited "
              f"after cutoff, gate = {gate_label}")
        if pos == 0:
            print("  no positives in this pool; metrics skipped")
            continue
        table, _, _ = recall_table(pool, args.epss_threshold, ns,
                                   gate_share=gate_share)
        print("\n  Recall@N (CVE level)"); print(table.to_string())
        print("\n  Urgent-set size and coverage")
        print(urgent_table(pool, args.epss_threshold,
                           gate_share=gate_share).to_string())

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
    ap.add_argument("--gate-share", type=float, default=None,
                    help="Label-free alternative to --epss-threshold: gate the "
                         "top share of each inventory's EPSS distribution "
                         "(e.g. 0.02 = top 2%%).")
    ap.add_argument("--ns", default="25,50,100,250,500")
    ap.add_argument("--outdir", default="results",
                    help="Directory for ranked_*.csv outputs")
    ap.add_argument("--sweep", default="0.001,0.005,0.01,0.05,0.088,0.2",
                    help="Comma-separated thresholds ('' to skip)")
    a = ap.parse_args()
    if a.gate_share is not None and not 0 < a.gate_share < 1:
        raise SystemExit("--gate-share must be between 0 and 1 (e.g. 0.02)")
    df = load(a.data, a.cutoff, a.horizon_end)
    df["products"] = df["products"].fillna("")
    run(df, a)



if __name__ == "__main__":
    main()
