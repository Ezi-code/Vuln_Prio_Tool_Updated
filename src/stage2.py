"""
stage2.py - Stage 2 (criticality amplification) and Stage 3 (CVSS tie-break),
trained on the DEVELOPMENT period with Stage 1 already frozen.

Section 5.2.1: flagged CVEs are weighted by the criticality tier of the affected
asset (Low, Medium, High, Critical); within a tier, higher CVSS comes first.
Supervisor: "compare selected staging orders and criticality-weight
configurations; the chosen configuration will then be tested against predefined
baseline methods", with parameters selected on a development period.

What this script does (no machine learning):
  1. Reads the frozen Stage 1 threshold from stage1_config.json.
  2. Generates random inventories (varying size and sector) on the development period.
  3. Compares configurations: the specified design (S1>S2>S3, strict tiers),
     weighted variants, other staging orders, and Stage 1 alone.
  4. Applies a rule stated in advance: KEEP the specified design unless an
     alternative has higher recall at the primary budget with a paired 95%
     interval that excludes zero.
  5. Writes stage2_config.json and the combined model_config.json.

Stage 2 only reorders the flagged CVEs, so it can matter only for budgets
smaller than the Stage 1 list; the budgets below include small ones for that reason.

    python src/stage2.py --train-cutoff 2023-06-30 --test-cutoff 2024-06-30
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
from evaluate_model import SECTORS, positions, sample_inventory
from model import rank_pool
from montecarlo import CATALOGUE, bootstrap, build_pool, token_cve_sets


def _sort(p, thr, cols):
    q = p.assign(gate=p["kev_at_cutoff"] | (p["epss"] >= thr))
    return q.sort_values(cols, ascending=False, kind="stable")


SPEC = "S1>S2>S3 strict tiers (SPEC)"
VARIANTS = {
    SPEC: lambda p, t: rank_pool(p, t, None),
    "S1>S2>S3 weight 1": lambda p, t: rank_pool(p, t, 1.0),
    "S1>S2>S3 weight 0.5": lambda p, t: rank_pool(p, t, 0.5),
    "S1>S3>S2 (CVSS first, tier breaks ties)": lambda p, t: _sort(p, t, ["gate", "cvss", "tier_rank", "epss"]),
    "S2>S1>S3 (tier first)": lambda p, t: _sort(p, t, ["tier_rank", "gate", "cvss", "epss"]),
    "S1>S3 (no criticality)": lambda p, t: rank_pool(p, t, 0.0),
    "S1 only (EPSS order)": lambda p, t: _sort(p, t, ["gate", "epss"]),
}


def fmt(point, arr, sign=False):
    lo, hi = np.nanpercentile(arr, [2.5, 97.5])
    f = "{:+.3f}" if sign else "{:.3f}"
    return f"{f.format(point)} [{f.format(lo)}, {f.format(hi)}]"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-data", default="data/processed/vulns_train.csv")
    ap.add_argument("--train-cutoff", required=True)
    ap.add_argument("--test-cutoff", required=True, help="development labels stop here")
    ap.add_argument("--stage1-config", default="stage1_config.json")
    ap.add_argument("--budgets", default="0.01,0.02,0.05,0.10,0.20,0.30",
                    help="shares of each organization's list")
    ap.add_argument("--primary", type=float, default=0.05,
                    help="budget used by the decision rule (must be in --budgets)")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--reps", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="stage2_config.json")
    ap.add_argument("--model-out", default="model_config.json")
    a = ap.parse_args()
    pd.set_option("display.width", 250)
    rng = np.random.default_rng(a.seed)
    BUD = tuple(float(x) for x in a.budgets.split(","))
    assert a.primary in BUD, "--primary must be one of --budgets"

    cfg1 = json.loads(Path(a.stage1_config).read_text())
    thr = float(cfg1["epss_threshold"])
    if cfg1["train_cutoff"] != a.train_cutoff:
        print(f"WARNING: Stage 1 was derived with cutoff {cfg1['train_cutoff']}, not {a.train_cutoff}")
    df = load(a.train_data, a.train_cutoff, horizon_end=a.test_cutoff)
    df["products"] = df["products"].fillna("")
    base = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    pos_ids = base.loc[base["exploited_after"], "cve_id"].to_numpy()
    pos_index = {c: i for i, c in enumerate(pos_ids)}
    P = len(pos_ids)
    print(f"Development pool: {len(base)} CVEs, {P} exploited between {a.train_cutoff} and {a.test_cutoff}")
    print(f"Stage 1 frozen: EPSS >= {thr} (criterion '{cfg1['criterion']}', from {a.stage1_config})")

    tokens = {t for _, opts, *_ in CATALOGUE for o in opts for t in o}
    sets = token_cve_sets(explode_products(base), tokens)

    secs = list(SECTORS)
    Pm, gate_share, desc = [], [], []
    F = {(v, b): [] for v in VARIANTS for b in BUD}
    for i in range(a.n):
        pool = build_pool(base, sample_inventory(rng, SECTORS[secs[i % len(secs)]]), sets)
        if pool is None or pool["exploited_after"].sum() == 0:
            continue
        n = len(pool)
        present = np.zeros(P)
        present[pool.loc[pool["exploited_after"], "cve_id"].map(pos_index).to_numpy()] = 1.0
        Pm.append(present)
        orders = {v: fn(pool, thr) for v, fn in VARIANTS.items()}
        for v, o in orders.items():
            for b in BUD:
                top = o.head(max(1, int(round(b * n))))
                f = np.zeros(P)
                hit = top.loc[top["exploited_after"], "cve_id"]
                if len(hit):
                    f[hit.map(pos_index).to_numpy()] = 1.0
                F[(v, b)].append(f)
        gate = pool["kev_at_cutoff"] | (pool["epss"] >= thr)
        k5 = max(1, int(round(a.primary * n)))
        ps, p1 = positions(orders[SPEC], n), positions(orders["S1 only (EPSS order)"], n)
        desc.append({"gate_share": float(gate.mean()),
                     "rho_vs_S1only": float(np.corrcoef(ps, p1)[0, 1]),
                     "overlap_top5": len(np.intersect1d(orders[SPEC].index[:k5],
                                                         orders["S1 only (EPSS order)"].index[:k5])) / k5,
                     "hc_spec": float((orders[SPEC].head(k5)["tier_rank"] >= 2).mean()),
                     "hc_s1only": float((orders["S1 only (EPSS order)"].head(k5)["tier_rank"] >= 2).mean())})
    M = np.array(Pm)
    Fa = {k: np.array(v) for k, v in F.items()}
    D = pd.DataFrame(desc)
    print(f"Inventories used: {len(M)} of {a.n}; mean later-exploited CVEs per inventory {M.sum(1).mean():.1f}")
    boot, pt = bootstrap(Fa, M, M, a.reps, rng)

    print("\n=== What Stage 2 does to an organization's list (descriptive) ===")
    print(f"Share of the list passing Stage 1: {D['gate_share'].mean():.1%}")
    print(f"Order agreement, Stage 1 only vs specified design: Spearman rho {D['rho_vs_S1only'].mean():.2f}, "
          f"top-{a.primary:.0%} overlap {D['overlap_top5'].mean():.1%}")
    print(f"Share of the top {a.primary:.0%} on High or Critical assets: specified design "
          f"{D['hc_spec'].mean():.1%} vs Stage 1 only {D['hc_s1only'].mean():.1%}")

    print("\n=== Recall by configuration and budget (share of an organization's list reviewed), mean [95% CI] ===")
    print(pd.DataFrame({f"top {b:.0%}": {v: fmt(pt[("recall", v, b)], boot[("recall", v, b)]) for v in VARIANTS}
                        for b in BUD}).to_string())
    print(f"\n=== Each alternative MINUS the specified design (CI excluding 0 holds up) ===")
    print(pd.DataFrame({f"top {b:.0%}": {v: fmt(pt[("recall", v, b)] - pt[("recall", SPEC, b)],
                                               boot[("recall", v, b)] - boot[("recall", SPEC, b)], True)
                                         for v in VARIANTS if v != SPEC} for b in BUD}).to_string())

    better = []
    for v in VARIANTS:
        if v == SPEC:
            continue
        d = boot[("recall", v, a.primary)] - boot[("recall", SPEC, a.primary)]
        if np.percentile(d, 2.5) > 0:
            better.append(v)
    print(f"\nDECISION RULE (stated in advance): keep the specified design unless an alternative beats it "
          f"at the top {a.primary:.0%} with a paired 95% interval above zero.")
    if better:
        print(f"RESULT: alternatives that beat it: {better}. Discuss with your supervisor before changing the design.")
        decision = f"alternatives better at primary budget: {better}"
    else:
        print("RESULT: no alternative beats the specified design with an interval above zero. "
              "The specified design (S1>S2>S3, strict tiers) is retained.")
        decision = "specified design retained"

    now = datetime.datetime.now().isoformat(timespec="seconds")
    design = {"order": "Stage 1 gate > Stage 2 criticality tier > Stage 3 CVSS",
              "stage2_weighting": "strict tiers (specified design)",
              "tier_order": ["Low", "Medium", "High", "Critical"],
              "stage3_within_tier": "CVSS base score; remaining ties by EPSS"}
    s2 = {"created": now, "stage": "Stage 2 and Stage 3 (section 5.2.1)",
          "development_data": a.train_data, "development_data_sha256_16": sha(a.train_data),
          "train_cutoff": a.train_cutoff, "label_horizon_end": a.test_cutoff,
          "development_positives": P, "stage1_config": a.stage1_config,
          "configurations_compared": list(VARIANTS), "budgets": list(BUD),
          "primary_budget": a.primary, "decision_rule": "keep the specified design unless an alternative "
          "beats it at the primary budget with a paired 95% interval above zero",
          "decision": decision, "design": design,
          "inventories": {"n_used": int(len(M)), "seed": a.seed, "sectors": list(SECTORS),
                          "catalogue_sha256_12": hashlib.sha256(repr(CATALOGUE).encode()).hexdigest()[:12]}}
    Path(a.out).write_text(json.dumps(s2, indent=2), encoding="utf-8")
    model = {"created": now, "note": "Frozen before the untouched test period. Do not edit after viewing test results.",
             "train_data": a.train_data, "train_cutoff": a.train_cutoff, "label_horizon_end": a.test_cutoff,
             "epss_model_version": cfg1["epss_model_version"],
             "stage1": {"source": a.stage1_config, "criterion": cfg1["criterion"], "rule": cfg1["rule"],
                        "epss_threshold": thr, "pool_share_at_threshold": cfg1["pool_share_at_threshold"],
                        "also_in_kev_at_cutoff": True},
             "stage2": {"tier_order": design["tier_order"], "weighting": design["stage2_weighting"]},
             "stage3": {"within_tier": "CVSS base score", "remaining_ties": "EPSS"},
             "stage2_decision": decision, "stage2_config": a.out}
    Path(a.model_out).write_text(json.dumps(model, indent=2), encoding="utf-8")
    print(f"\nWritten: {a.out} and {a.model_out}. Commit both before touching any later period.")


if __name__ == "__main__":
    main()
