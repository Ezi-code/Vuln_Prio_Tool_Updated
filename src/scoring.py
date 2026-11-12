"""
scoring.py - The three-stage prioritization model (section 5.2.1) and its
evaluation against the baselines on each inventory.

  Stage 1 Threat gate : in KEV at the cutoff, OR EPSS >= threshold
  Stage 2 Criticality : order by the asset's tier (Critical > High > Medium > Low)
  Stage 3 Tie-break   : within a tier, higher CVSS first
  (Any remaining ties are broken by EPSS, a documented implementation choice.)
  Non-gated CVEs are deprioritized, not discarded.

The four asset tiers are the operational priority categories.  The output also
contains a queue label from QUEUE_BY_TIER and one CSV per tier.  Stage 1 is a
candidate gate; --capacity selects the final list.

Usage (venv active):
    python src/assets.py
    python src/scoring.py --cutoff 2024-06-30
    python src/scoring.py --cutoff 2024-06-30 --epss-threshold 0.04267
    python src/scoring.py --cutoff 2024-06-30 --gate-share 0.20 \
        --capacity 500 --outdir results/operational
"""
import argparse
from pathlib import Path

import pandas as pd

from assets import (QUEUE_BY_TIER, TIERS, explode_products, load_inventory,
                    match_vulns)
from baselines import (load, rank_cvss_only, rank_epss_kev_only, rank_fifo,
                       recall_at_n)
from model import gate_cutoff, rank_pool


# ----------------------------------------------------------------- model
def add_priority_fields(ranked):
    """Expose the asset tier as the priority category and add the operational
    queue label.  This is deliberately the SAME four-tier instrument used by
    Stage 2; there is no second three-level threat taxonomy.
    """
    out = ranked.copy()
    out["asset_tier"] = out["tier"]
    out["priority_queue"] = out["asset_tier"].map(QUEUE_BY_TIER)
    return out


def add_exploit_fields(ranked):
    """Add a plain-language exploit status and an explicit fix flag.

    ``needs_fixing`` means the CVE is either known-exploited at the cutoff
    (CISA KEV) or passed the EPSS candidate gate.  It does not use the
    after-cutoff evaluation label.  The final capacity may still contain
    below-gate rows, which are marked for monitoring rather than fixing.
    """
    out = ranked.copy()
    kev = out["kev_at_cutoff"].fillna(False).astype(bool)
    gate = out["gate"].fillna(False).astype(bool)
    out["needs_fixing"] = kev | gate
    out["exploit_status"] = [
        "Known exploited (CISA KEV at cutoff)" if k
        else "High exploitation likelihood (EPSS gate)" if g
        else "Below gate (monitor)"
        for k, g in zip(kev, gate)
    ]
    out["fix_action"] = [
        "Fix immediately (known exploited)" if k
        else "Patch by asset-tier queue" if g
        else "Monitor / backlog"
        for k, g in zip(kev, gate)
    ]
    return out


def apply_model(pairs, thr, gate_share=None, capacity=None):
    """Rank (CVE, asset) pairs, then keep each CVE once at its most critical
    asset. Returns one row per CVE, best first.

    KEV-at-cutoff CVEs are kept in the operational ranking and placed first;
    the evaluation functions below use the Pool B subset (no known KEV) so the
    metrics measure new exploitation rather than already-known threats.

    `capacity` is an optional final-list size.  The Stage 1 gate may be wider
    than this, which is what allows Stages 2 and 3 to change membership.
    """
    ranked = rank_pool(pairs, thr, None, gate_share=gate_share,
                       kev_first=True)
    ranked = ranked.drop_duplicates("cve_id").reset_index(drop=True)
    ranked = add_priority_fields(ranked)
    ranked = add_exploit_fields(ranked)
    if capacity is not None:
        ranked = ranked.head(capacity).reset_index(drop=True)
    return ranked


def explain(r, thr, gate_share=None):
    if r["kev_at_cutoff"]:
        d = r.get("kev_date_added")
        when = f" (added {d:%Y-%m-%d})" if pd.notna(d) else ""
        why = f"listed in CISA KEV{when}"
    elif r["gate"]:
        if gate_share is not None:
            why = (f"EPSS {r['epss']:.3f} is in the top {gate_share:.1%} "
                   f"of this inventory")
        else:
            why = f"EPSS {r['epss']:.3f} is above the {thr} threshold"
    else:
        why = "not in KEV and EPSS below threshold (deprioritized)"
    extra = ""
    if str(r.get("patchable", "")).lower() == "no":
        extra = "; asset marked unpatchable - apply compensating control"
    return (f"{why}; affects {r['asset_name']} "
            f"(asset tier {r['asset_tier']}, "
            f"criticality {r['criticality_score']}/12; "
            f"{r['priority_queue']}); CVSS {r['cvss']:.1f}{extra}")


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


def urgent_table(pairs, thr, gate_share=None, capacity=None):
    cves = cve_level(pairs)
    total = int(cves["exploited_after"].sum())
    cutoff = gate_cutoff(cves, thr, gate_share)
    gate = cves["kev_at_cutoff"] | (cves["epss"] >= cutoff)
    sets = {"Model urgent set (Stage 1 gate)": gate}
    if capacity is not None:
        final_ids = apply_model(pairs, thr, gate_share=gate_share,
                                capacity=capacity)["cve_id"]
        sets["Model final list (capacity)"] = cves["cve_id"].isin(final_ids)
    sets["CVSS >= 7.0"] = cves["cvss"] >= 7.0
    sets["Patch everything"] = pd.Series(True, index=cves.index)
    rows = []
    for name, m in sets.items():
        found = int(cves.loc[m, "exploited_after"].sum())
        rows.append({"urgent set": name, "size": int(m.sum()),
                     "% of pool": round(100 * m.mean(), 1),
                     "exploited found": found,
                     "coverage": round(found / total, 3) if total else float("nan")})
    return pd.DataFrame(rows).set_index("urgent set")


def tier_summary(ranked, top_n=None):
    """Summarise the four asset tiers as operational priority categories.

    Counts are for the full ranked CVE list; when `top_n` is supplied, the
    table also shows how many of those items fall in the displayed top list.
    """
    total = len(ranked)
    shown = ranked.head(top_n) if top_n is not None else ranked
    rows = []
    for tier in TIERS:
        sub = ranked[ranked["asset_tier"] == tier]
        rows.append({
            "asset_tier": tier,
            "priority_queue": QUEUE_BY_TIER[tier],
            "cves": int(len(sub)),
            "% of ranked": round(100 * len(sub) / total, 1) if total else 0.0,
            f"in top {top_n}": int((shown["asset_tier"] == tier).sum())
            if top_n is not None else int(len(sub)),
            "unpatchable": int((sub["patchable"] == "no").sum())
            if "patchable" in sub.columns else 0,
            "mean_cvss": round(float(sub["cvss"].mean()), 2) if len(sub) else float("nan"),
            "mean_epss": round(float(sub["epss"].mean()), 4) if len(sub) else float("nan"),
        })
    return pd.DataFrame(rows).set_index("asset_tier")


def tier_exploit_summary(ranked, examples=5):
    """One row per asset tier: how many exploits need action and which ones.

    This is the concise answer to "what needs fixing in each tier?".  It uses
    only information available at the cutoff: CISA KEV membership and the EPSS
    gate.  The after-cutoff label is not used.
    """
    rows = []
    for tier in TIERS:
        sub = ranked[ranked["asset_tier"] == tier]
        actionable = sub[sub["needs_fixing"]]
        kev = actionable[actionable["kev_at_cutoff"]]
        gated = actionable[actionable["gate"] & ~actionable["kev_at_cutoff"]]
        rows.append({
            "asset_tier": tier,
            "priority_queue": QUEUE_BY_TIER[tier],
            "cves_in_final": int(len(sub)),
            "known_exploited": int(len(kev)),
            "epss_gated_only": int(len(gated)),
            "needs_fixing": int(len(actionable)),
            "assets_affected": int(actionable["asset_id"].nunique()),
            "unpatchable": int((actionable["patchable"] == "no").sum())
            if "patchable" in actionable.columns else 0,
            "top_cves": "; ".join(actionable["cve_id"].head(examples).astype(str)),
            "top_assets": "; ".join(
                actionable["asset_name"].drop_duplicates().head(examples).astype(str)
            ),
        })
    return pd.DataFrame(rows).set_index("asset_tier")


def asset_exploit_list(ranked):
    """One row per (asset, CVE) that needs action, grouped by asset tier.

    The output is deliberately asset-centric: a practitioner can hand the
    Critical rows to the owner of each affected system.
    """
    from assets import OPTIONAL_COLUMNS  # local import keeps module startup small

    cols = ["asset_id", "asset_name", "asset_tier", "criticality_score",
            "priority_queue", "patchable", "owner", "maintenance_window",
            "compensating_control", "cve_id", "matched_product",
            "exploit_status", "fix_action", "cvss", "epss",
            "kev_date_added", "reason"]
    if ranked.empty:
        return pd.DataFrame(columns=cols)
    out = ranked.loc[ranked["needs_fixing"]].copy()
    out = out.sort_values(["tier_rank", "asset_id"],
                          ascending=[False, True], kind="stable")
    cols = [c for c in cols if c in out.columns]
    cols += [c for c in OPTIONAL_COLUMNS if c in out.columns and c not in cols]
    return out[cols].reset_index(drop=True)


def exploit_report_markdown(ranked, inventory_name, per_asset=10):
    """Human-readable report: tier -> asset -> CVE -> why it needs action."""
    lines = [
        f"# Exploit priorities: {inventory_name}",
        "",
        "Generated from CISA KEV at the cutoff plus the EPSS candidate gate.",
        "The after-cutoff evaluation label is not used in this operational report.",
        "",
    ]
    for tier in reversed(TIERS):  # Critical first
        sub = ranked[(ranked["asset_tier"] == tier) & ranked["needs_fixing"]]
        lines.append(f"## {tier} — {QUEUE_BY_TIER[tier]}")
        if sub.empty:
            lines.append("")
            lines.append("No CVEs need action in this tier within the final list.")
            lines.append("")
            continue
        lines.append("")
        lines.append(f"{len(sub)} CVE(s) across {sub['asset_id'].nunique()} asset(s).")
        lines.append("")
        for asset_id, group in sub.groupby("asset_id", sort=False):
            row0 = group.iloc[0]
            patch = str(row0.get("patchable", "") or "unknown")
            owner = str(row0.get("owner", "") or "unassigned")
            lines.append(f"### {row0['asset_name']} ({asset_id}) — {tier}")
            lines.append(f"Owner: {owner}; patchable: {patch}. "
                         f"Criticality: {row0['criticality_score']}/12.")
            lines.append("")
            for _, r in group.head(per_asset).iterrows():
                lines.append(
                    f"- **{r['cve_id']}** — {r['exploit_status']}; "
                    f"CVSS {r['cvss']:.1f}, EPSS {r['epss']:.3f}. "
                    f"{r.get('reason', '')}"
                )
            if len(group) > per_asset:
                lines.append(
                    f"- ... {len(group) - per_asset} more CVE(s) in the CSV."
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def tier_outputs(ranked, outdir, stem, columns, per_tier=100):
    """Write one CSV per asset tier, preserving the same ranked order."""
    paths = {}
    for tier in TIERS:
        sub = ranked[ranked["asset_tier"] == tier].head(per_tier)
        path = Path(outdir) / f"{stem}_{tier.lower()}.csv"
        sub[columns].to_csv(path, index=False)
        paths[tier] = path
    return paths


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
        capacity = getattr(args, "capacity", None)
        operational = apply_model(pairs, args.epss_threshold,
                                  gate_share=gate_share,
                                  capacity=capacity)
        operational["reason"] = operational.apply(
            lambda r: explain(r, args.epss_threshold, gate_share), axis=1)
        top_n = int(getattr(args, "top", 100))
        top = operational.head(top_n).copy()
        cols = ["cve_id", "asset_id", "asset_name", "matched_product",
                "asset_tier", "criticality_score", "priority_queue",
                "needs_fixing", "exploit_status", "fix_action",
                "tier_rank", "cvss", "epss", "gate", "kev_at_cutoff",
                "kev_date_added", "owner", "patchable",
                "maintenance_window", "compensating_control", "reason"]
        cols = [c for c in cols if c in top.columns]
        out = outdir / f"ranked_{f.stem}.csv"
        top[cols].to_csv(out, index=False)
        n_kev = int(operational["kev_at_cutoff"].sum())
        print(f"  operational top-{len(top)} written to {out} "
              f"({n_kev} KEV-at-cutoff CVEs in this inventory; ranked first)")

        print("\n  Asset tiers as priority categories")
        print(tier_summary(operational, top_n=len(top)).to_string())
        tier_paths = tier_outputs(
            operational, outdir, f"tier_{f.stem}", cols,
            per_tier=int(getattr(args, "tier_capacity", 100)))
        if tier_paths:
            print("  tier queues: " + ", ".join(
                f"{t}={p.name}" for t, p in tier_paths.items()))

        # Explicit answer to "what needs fixing in each tier?" and "which
        # exploits affect each asset?".
        print("\n  Exploits needing action, by asset tier")
        ex_summary = tier_exploit_summary(operational)
        print(ex_summary.to_string())
        ex_path = outdir / f"exploits_by_tier_{f.stem}.csv"
        ex_summary.to_csv(ex_path)
        print(f"  tier exploit summary written to {ex_path}")

        asset_list = asset_exploit_list(operational)
        asset_path = outdir / f"asset_exploits_{f.stem}.csv"
        asset_list.to_csv(asset_path, index=False)
        print(f"  per-asset exploit list written to {asset_path} "
              f"({len(asset_list)} asset/CVE rows)")

        report_path = outdir / f"exploit_report_{f.stem}.md"
        report_path.write_text(
            exploit_report_markdown(operational, f.stem), encoding="utf-8")
        print(f"  human-readable exploit report written to {report_path}")

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
                           gate_share=gate_share,
                           capacity=capacity).to_string())

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
    ap.add_argument("--epss-threshold", type=float, default=0.04267,
                    help="Frozen Stage 1 EPSS threshold (default: 0.04267)")
    ap.add_argument("--gate-share", type=float, default=None,
                    help="Label-free alternative to --epss-threshold: gate the "
                         "top share of each inventory's EPSS distribution "
                         "(e.g. 0.02 = top 2%%).")
    ap.add_argument("--ns", default="25,50,100,250,500")
    ap.add_argument("--top", type=int, default=100,
                    help="Rows in the main ranked CSV (default: 100)")
    ap.add_argument("--capacity", type=int, default=None,
                    help="Optional final-list capacity. The Stage 1 gate may be "
                         "wider; Stage 2/3 then select this final list.")
    ap.add_argument("--tier-capacity", type=int, default=100,
                    help="Maximum rows per asset-tier queue CSV (default: 100)")
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
