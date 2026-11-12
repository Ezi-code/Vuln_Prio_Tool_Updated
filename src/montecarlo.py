"""
montecarlo.py - Evaluate the model on many randomly generated inventories.

Each random inventory has 6-12 assets drawn from a catalogue of typical
small-organization asset types (workstations, mail, web, database, firewall,
routers, virtualization, NAS/backup, DevOps, Linux servers). Software and the
four criticality answers are sampled within plausible ranges. By default the
EPSS threshold is FIXED (chosen on the training period); --gate-share switches
to the label-free per-inventory percentile gate. Nothing is tuned here.

Per inventory we measure, within that organization's own CVE pool and at
workload budgets (default 10%, 20% and 30%; pass --budgets to reproduce the
capacity-constrained 2%/5% analysis):
  recall            share of later-exploited CVEs found in the top budget
  weighted recall   same, but each positive weighted by its asset's tier
                    (Low=1, Medium=2, High=3, Critical=4)
  % on High/Crit.   share of the top budget that sits on High/Critical assets
Results are averaged across inventories with bootstrap 95% intervals.

Strategies: Model = gate -> tier -> CVSS (proposed). Ablations: Gate+CVSS
(no criticality, VMC-style chain) and Tier+CVSS (criticality, no EPSS gate).

Usage:
    python src/montecarlo.py --cutoff 2024-06-30 --horizon-end 2025-06-30 \
        --gate-share 0.20 --budgets 0.10,0.20,0.30 --n 300
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from assets import TIER_RANK, explode_products, tier_from_total
from baselines import load

# (asset type, [alternative software lists], exposure, sensitivity, function, redundancy)
# each of the last four is an inclusive (low, high) range for the 0-3 answer
CATALOGUE = [
    ("Workstations", [["microsoft:windows_10", "microsoft:office", "google:chrome", "adobe:acrobat_reader"],
                      ["microsoft:windows_11", "microsoft:office", "microsoft:edge_chromium", "mozilla:firefox"],
                      ["microsoft:windows_10", "microsoft:windows_11", "microsoft:office", "google:chrome"]],
     (0, 1), (0, 2), (0, 2), (0, 1)),
    ("File server", [["microsoft:windows_server_2019"], ["microsoft:windows_server_2022"],
                     ["linux:linux_kernel", "samba:samba"]],
     (0, 1), (1, 3), (1, 3), (1, 3)),
    ("Mail server", [["microsoft:exchange_server"], ["zimbra:collaboration"], ["roundcube:webmail"]],
     (2, 3), (2, 3), (2, 3), (2, 3)),
    ("Web server", [["apache:http_server", "php:php", "wordpress:wordpress"],
                    ["f5:nginx", "php:php", "drupal:drupal"],
                    ["microsoft:internet_information_services"],
                    ["apache:tomcat"], ["joomla:joomla", "php:php", "apache:http_server"]],
     (2, 3), (0, 2), (0, 3), (1, 3)),
    ("Database", [["oracle:mysql"], ["mariadb:mariadb"], ["postgresql:postgresql"],
                  ["microsoft:sql_server", "microsoft:windows_server_2019"]],
     (0, 1), (2, 3), (2, 3), (1, 3)),
    ("Firewall / VPN", [["fortinet:fortios"], ["paloaltonetworks:pan-os"], ["sonicwall:sonicos"],
                        ["cisco:adaptive_security_appliance_software"], ["ivanti:connect_secure"],
                        ["citrix:netscaler_gateway"]],
     (3, 3), (1, 2), (3, 3), (2, 3)),
    ("Router / Wi-Fi", [["mikrotik:routeros"], ["dlink:"], ["tp-link:"], ["zyxel:"],
                        ["draytek:"], ["cisco:ios_xe"], ["netgear:"]],
     (1, 3), (0, 1), (1, 2), (1, 3)),
    ("Virtualization", [["vmware:esxi"], ["vmware:esxi", "vmware:vcenter_server"]],
     (0, 1), (1, 3), (2, 3), (2, 3)),
    ("NAS / backup", [["synology:diskstation_manager"], ["qnap:qts"], ["veeam:backup"],
                      ["linux:linux_kernel", "samba:samba"]],
     (0, 2), (2, 3), (1, 3), (0, 2)),
    ("DevOps / collaboration", [["atlassian:confluence"], ["jenkins:jenkins"], ["gitlab:gitlab"],
                                ["grafana:grafana"]],
     (1, 3), (1, 3), (1, 2), (1, 2)),
    ("Linux server", [["linux:linux_kernel", "openbsd:openssh", "openssl:openssl"],
                      ["debian:debian_linux", "openssl:openssl"],
                      ["canonical:ubuntu_linux", "openbsd:openssh"]],
     (0, 2), (1, 2), (1, 3), (1, 3)),
]
BUDGETS = (0.02, 0.05, 0.10)
STRATS = ["Model", "Gate+CVSS", "Tier+CVSS", "EPSS-only", "CVSS-only", "FIFO", "Random"]


def token_cve_sets(prod_df, tokens):
    sets = {}
    for t in sorted(tokens):
        sets[t] = prod_df.loc[prod_df["product"].str.startswith(t), "cve_id"].unique()
    return sets


def sample_inventory(rng):
    k = int(rng.integers(6, 13))
    others = list(range(1, len(CATALOGUE)))
    picks = [0] + list(rng.choice(others, size=min(k - 1, len(others)), replace=False))
    assets = []
    for i in picks:
        _, options, ex, se, fu, re_ = CATALOGUE[i]
        tokens = options[int(rng.integers(len(options)))]
        ans = [int(rng.integers(lo, hi + 1)) for lo, hi in (ex, se, fu, re_)]
        assets.append((tokens, TIER_RANK[tier_from_total(sum(ans))]))
    return assets


def build_pool(base, assets, token_sets):
    parts = []
    for tokens, tr in assets:
        arrs = [token_sets[t] for t in tokens if len(token_sets[t])]
        if arrs:
            ids = np.unique(np.concatenate(arrs))
            parts.append(pd.DataFrame({"cve_id": ids, "tier_rank": tr}))
    if not parts:
        return None
    m = pd.concat(parts).groupby("cve_id", as_index=False)["tier_rank"].max()
    return base.merge(m, on="cve_id")


def eval_pool(pool, thr, pos_index, n_pos, gate_share=None, budgets=BUDGETS):
    n = len(pool)
    pos = pool["exploited_after"].to_numpy()
    w = (pool["tier_rank"] + 1).to_numpy()
    P, WP = pos.sum(), (w * pos).sum()
    if P == 0:
        return None
    if gate_share is not None:
        cutoff = float(pool["epss"].quantile(1 - gate_share))
    else:
        cutoff = thr
    pool = pool.assign(gate=pool["epss"] >= cutoff)
    orders = {
        "Model": pool.sort_values(["gate", "tier_rank", "cvss", "epss"],
                                  ascending=False, kind="stable"),
        "Gate+CVSS": pool.sort_values(["gate", "cvss", "epss"],
                                      ascending=False, kind="stable"),
        "Tier+CVSS": pool.sort_values(["tier_rank", "cvss", "epss"],
                                      ascending=False, kind="stable"),
        "EPSS-only": pool.sort_values("epss", ascending=False, kind="stable"),
        "CVSS-only": pool.sort_values(["cvss", "published"],
                                      ascending=[False, True], kind="stable"),
        "FIFO": pool.sort_values("published", kind="stable"),
    }
    # which global positives are present here, and their tier weights
    pp = pool.loc[pool["exploited_after"], ["cve_id", "tier_rank"]]
    pidx = pp["cve_id"].map(pos_index).to_numpy(dtype=int)
    present = np.zeros(n_pos)
    wt = np.zeros(n_pos)
    present[pidx] = 1.0
    wt[pidx] = pp["tier_rank"].to_numpy() + 1.0

    out = {"pool": n, "positives": int(P), "gate_share": float(pool["gate"].mean())}
    found = {}
    hc_base = float((pool["tier_rank"] >= 2).mean())
    for b in budgets:
        k = max(1, int(round(b * n)))
        for s_, o in orders.items():
            top = o.head(k)
            tw = (top["tier_rank"] + 1).to_numpy()
            tp = top["exploited_after"].to_numpy()
            out[f"{s_}|{b}|recall"] = tp.sum() / P
            out[f"{s_}|{b}|wrecall"] = (tw * tp).sum() / WP
            out[f"{s_}|{b}|hc"] = float((top["tier_rank"] >= 2).mean())
            f = np.zeros(n_pos)
            hit = top.loc[top["exploited_after"], "cve_id"].map(pos_index)
            if len(hit):
                f[hit.to_numpy(dtype=int)] = 1.0
            found[(s_, b)] = f
        out[f"Random|{b}|recall"] = k / n
        out[f"Random|{b}|wrecall"] = k / n
        out[f"Random|{b}|hc"] = hc_base
        found[("Random", b)] = present * (k / n)   # expected found fraction
    return out, {"present": present, "wt": wt, "found": found}


def ci(v, rng, reps=2000):
    v = np.asarray(v, dtype=float)
    means = v[rng.integers(0, len(v), (reps, len(v)))].mean(axis=1)
    lo, hi = np.percentile(means, [2.5, 97.5])
    return f"{v.mean():.3f} [{lo:.3f}, {hi:.3f}]"


def bootstrap(F, M, WT, reps, rng):
    """Two-way bootstrap: resample inventories AND the positive CVEs."""
    n, P = M.shape
    FW = {key: v * WT for key, v in F.items()}
    res = {(m,) + key: np.empty(reps) for key in F for m in ("recall", "wrecall")}
    for i in range(reps):
        r = rng.integers(0, n, n)
        w = rng.multinomial(P, np.full(P, 1.0 / P)).astype(float)
        den, denw = M[r] @ w, WT[r] @ w
        v1, v2 = den > 0, denw > 0
        for key in F:
            res[("recall",) + key][i] = ((F[key][r] @ w)[v1] / den[v1]).mean()
            res[("wrecall",) + key][i] = ((FW[key][r] @ w)[v2] / denw[v2]).mean()
    pt = {}
    for key in F:
        pt[("recall",) + key] = float((F[key].sum(1) / M.sum(1)).mean())
        pt[("wrecall",) + key] = float((FW[key].sum(1) / WT.sum(1)).mean())
    return res, pt


def fmt(point, arr):
    lo, hi = np.nanpercentile(arr, [2.5, 97.5])
    return f"{point:+.3f} [{lo:+.3f}, {hi:+.3f}]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cutoff", required=True)
    ap.add_argument("--horizon-end", default=None)
    ap.add_argument("--data", default="data/processed/vulns.csv")
    ap.add_argument("--epss-threshold", type=float, default=0.04267,
                    help="Frozen Stage 1 EPSS threshold (default: 0.04267)")
    ap.add_argument("--gate-share", type=float, default=None,
                    help="Label-free alternative: gate the top share of each "
                         "inventory's EPSS distribution (e.g. 0.02).")
    ap.add_argument("--budgets", default="0.10,0.20,0.30",
                    help="Comma-separated final-list shares, e.g. "
                         "0.02,0.05,0.10,0.20,0.30")
    ap.add_argument("--outdir", default="results",
                    help="Directory for montecarlo.csv")
    ap.add_argument("--n", type=int, default=300, help="random inventories")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--reps", type=int, default=2000, help="bootstrap replicates")
    a = ap.parse_args()
    if a.gate_share is not None and not 0 < a.gate_share < 1:
        raise SystemExit("--gate-share must be between 0 and 1 (e.g. 0.02)")
    pd.set_option("display.width", 220)
    rng = np.random.default_rng(a.seed)
    BUD = tuple(float(x) for x in a.budgets.split(","))
    if not BUD or any(not 0 < b <= 1 for b in BUD):
        raise SystemExit("--budgets must be comma-separated shares in (0, 1]")

    df = load(a.data, a.cutoff, a.horizon_end)
    df["products"] = df["products"].fillna("")
    base = df[~df["kev_at_cutoff"]].reset_index(drop=True)
    gate_label = (f"top {a.gate_share:.1%} of each inventory's EPSS (label-free)"
                  if a.gate_share is not None
                  else f"EPSS threshold {a.epss_threshold} (fixed)")
    print(f"Base pool: {len(base)} CVEs, {int(base['exploited_after'].sum())} "
          f"exploited after cutoff. Gate: {gate_label}.")

    tokens = {t for _, opts, *_ in CATALOGUE for o in opts for t in o}
    sets = token_cve_sets(explode_products(base), tokens)
    empty = [t for t, ids in sets.items() if len(ids) == 0]
    if empty:
        print("Catalogue tokens with no CVEs (fix or ignore): " + ", ".join(empty))

    pos_ids = base.loc[base["exploited_after"], "cve_id"].to_numpy()
    pos_index = {c: i for i, c in enumerate(pos_ids)}
    n_pos = len(pos_ids)
    rows, Pm, Wm = [], [], []
    Fm = {(s_, b): [] for s_ in STRATS for b in BUD}
    for _ in range(a.n):
        pool = build_pool(base, sample_inventory(rng), sets)
        r = (eval_pool(pool, a.epss_threshold, pos_index, n_pos,
                       gate_share=a.gate_share, budgets=BUD)
             if pool is not None else None)
        if r:
            out, arr = r
            rows.append(out); Pm.append(arr["present"]); Wm.append(arr["wt"])
            for key, v in arr["found"].items():
                Fm[key].append(v)
    res = pd.DataFrame(rows)
    outdir = Path(a.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    res.to_csv(outdir / "montecarlo.csv", index=False)
    print(f"\nInventories generated: {a.n}; with at least one positive: {len(res)}")
    print(f"Mean pool size {res['pool'].mean():.0f} CVEs; mean positives "
          f"{res['positives'].mean():.1f}; mean share passing the gate "
          f"{100 * res['gate_share'].mean():.1f}%")

    M, WT = np.array(Pm), np.array(Wm)
    F = {key: np.array(v) for key, v in Fm.items()}
    boot, pt = bootstrap(F, M, WT, a.reps, rng)

    for metric, title in (("recall", "Recall (share of later-exploited CVEs found)"),
                          ("wrecall", "Criticality-weighted recall")):
        print(f"\n=== {title}; mean [95% CI, resampling inventories AND positives] ===")
        print(pd.DataFrame({
            f"top {int(b*100)}%": {s_: fmt(pt[(metric, s_, b)], boot[(metric, s_, b)]).replace("+", "")
                                    for s_ in STRATS} for b in BUD}).to_string())
        print(f"\n--- {title}: Model MINUS each alternative "
              f"(a CI that excludes 0 holds up under resampling) ---")
        print(pd.DataFrame({
            f"top {int(b*100)}%": {s_: fmt(pt[(metric, 'Model', b)] - pt[(metric, s_, b)],
                                           boot[(metric, 'Model', b)] - boot[(metric, s_, b)])
                                    for s_ in STRATS if s_ != "Model"} for b in BUD}).to_string())

    print("\n=== Share of the top list on High/Critical assets; mean [95% CI, inventories only] ===")
    print(pd.DataFrame({
        f"top {int(b*100)}%": {s_: ci(res[f'{s_}|{b}|hc'], rng) for s_ in STRATS}
        for b in BUD}).to_string())


if __name__ == "__main__":
    main()
