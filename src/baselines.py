"""
baselines.py - The three baseline prioritization strategies and the
Recall@N / Precision@N metrics used to compare them.

Baselines (from section 5.5 of the proposal):
  a) CVSS-only      : highest CVSS score first
  b) EPSS/KEV-only  : KEV members first, then highest EPSS
  c) FIFO           : oldest published CVE first (patch in discovery order)

Temporal hold-out (section 5.6):
  - Only CVEs published on or before the cutoff date are ranked.
  - KEV membership AT the cutoff (kev_date_added <= cutoff) is a model input.
  - Ground truth = CVEs added to KEV AFTER the cutoff date.

Usage (venv active, from the project folder):
    python src/baselines.py --cutoff 2024-02-28
"""
import argparse
import json
from pathlib import Path

import pandas as pd


def read_meta(path):
    """Read the optional <data>.meta.json sidecar written by ingest.py."""
    p = Path(path)
    for candidate in (p.with_suffix(".meta.json"),
                      p.with_suffix(p.suffix + ".meta.json")):
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return {}
    return {}


def load(path="data/processed/vulns.csv", cutoff=None, horizon_end=None):
    df = pd.read_csv(path)
    df["published"] = pd.to_datetime(df["published"], errors="coerce")
    df["kev_date_added"] = pd.to_datetime(df["kev_date_added"], errors="coerce")

    # drop rejected CVEs
    df = df[~df["description"].fillna("").str.contains("REJECT", case=False)]

    cutoff = pd.Timestamp(cutoff)
    meta = read_meta(path)
    snap = meta.get("epss_snapshot_date")
    if snap:
        try:
            snap_ts = pd.Timestamp(snap)
            if snap_ts < cutoff - pd.Timedelta(days=30):
                print(f"WARNING: EPSS snapshot {snap_ts:%Y-%m-%d} is more than "
                      f"30 days before the cutoff {cutoff:%Y-%m-%d}. EPSS is a "
                      f"time-varying score; use a snapshot as of the cutoff.\n")
        except (TypeError, ValueError):
            pass
    newest = df["published"].max()
    if newest < cutoff - pd.Timedelta(days=14):
        print(f"WARNING: newest CVE in the data is {newest:%Y-%m-%d}, but the "
              f"cutoff is {cutoff:%Y-%m-%d}. Re-run ingest.py with --end "
              f"{cutoff:%Y-%m-%d} first, or these results are not valid.\n")
    df = df[df["published"] <= cutoff + pd.Timedelta(days=1)].copy()

    df["kev_at_cutoff"] = df["kev_date_added"].notna() & \
                          (df["kev_date_added"] <= cutoff)
    df["exploited_after"] = df["kev_date_added"].notna() & \
                            (df["kev_date_added"] > cutoff)
    if horizon_end is not None:  # only count KEV additions up to this date
        df["exploited_after"] &= df["kev_date_added"] <= pd.Timestamp(horizon_end)

    df["has_cvss"] = df["cvss"].notna()
    df["has_epss"] = df["epss"].notna()
    df["cvss"] = df["cvss"].fillna(0.0)
    df["epss"] = df["epss"].fillna(0.0)
    return df.reset_index(drop=True)


# ---------------------------------------------------------- baselines
def rank_cvss_only(df):
    return df.sort_values(["cvss", "published"], ascending=[False, True])


def rank_epss_kev_only(df):
    return df.sort_values(["kev_at_cutoff", "epss"], ascending=[False, False])


def rank_fifo(df):
    return df.sort_values("published", ascending=True)


BASELINES = {
    "CVSS-only": rank_cvss_only,
    "EPSS/KEV-only": rank_epss_kev_only,
    "FIFO": rank_fifo,
}


# ------------------------------------------------------------ metrics
def recall_at_n(ranked, n):
    """Share of all exploited-after-cutoff CVEs found in the top n."""
    total = ranked["exploited_after"].sum()
    if total == 0:
        return float("nan")
    return ranked.head(n)["exploited_after"].sum() / total


def precision_at_n(ranked, n):
    """Share of the top n that were exploited after the cutoff."""
    top = ranked.head(n)
    return top["exploited_after"].sum() / max(len(top), 1)


def evaluate(ranked, name, ns=(50, 100, 250, 500)):
    row = {"strategy": name}
    for n in ns:
        row[f"Recall@{n}"] = recall_at_n(ranked, n)
        row[f"Prec@{n}"] = precision_at_n(ranked, n)
    return row


def random_row(df, ns):
    """Expected metrics for a random ranking (the luck-only reference)."""
    row = {"strategy": "Random (expected)"}
    total = df["exploited_after"].sum()
    for n in ns:
        row[f"Recall@{n}"] = min(n, len(df)) / len(df)
        row[f"Prec@{n}"] = total / len(df)
    return row


def run_pool(df, label, ns):
    pos = int(df["exploited_after"].sum())
    print(f"\n=== {label}: {len(df)} CVEs, {pos} exploited after cutoff "
          f"(base rate {pos / len(df):.3%}) ===")
    rows = [evaluate(fn(df), name, ns) for name, fn in BASELINES.items()]
    rows.append(random_row(df, ns))
    out = pd.DataFrame(rows).set_index("strategy").round(3)
    pd.set_option("display.width", 200)
    print(out.T)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cutoff", required=True, help="Cutoff date YYYY-MM-DD")
    ap.add_argument("--data", default="data/processed/vulns.csv")
    ap.add_argument("--horizon-end", default=None,
                    help="Only count KEV additions up to this date (YYYY-MM-DD)")
    ap.add_argument("--ns", default="100,500,1000,2500,5000",
                    help="Comma-separated N values")
    a = ap.parse_args()
    ns = tuple(int(x) for x in a.ns.split(","))

    df = load(a.data, a.cutoff, a.horizon_end)
    print(f"CVEs ranked          : {len(df)}")
    print(f"Missing CVSS         : {(~df['has_cvss']).sum()}")
    print(f"Missing EPSS         : {(~df['has_epss']).sum()}")
    print(f"KEV at cutoff        : {df['kev_at_cutoff'].sum()}")
    print(f"Exploited after (GT) : {df['exploited_after'].sum()}")
    if df["exploited_after"].sum() == 0:
        print("\nNo ground-truth positives in this window. Use a longer range "
              "or an earlier cutoff, then re-run.")
        return

    run_pool(df, "Pool A: all CVEs", ns)
    run_pool(df[~df["kev_at_cutoff"]].copy(),
             "Pool B: excluding CVEs already in KEV at cutoff", ns)


if __name__ == "__main__":
    main()
