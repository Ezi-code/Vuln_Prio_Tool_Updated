"""
kevyears.py - How many later-exploited CVEs would we gain by downloading
older CVEs? Uses only the KEV catalog (fast, no NVD download).

CVE year is taken from the CVE ID, so counts are approximate (a CVE with a
cutoff-year ID may have been published after the cutoff).

Usage:
    python src/kevyears.py
    python src/kevyears.py --periods 2023-06-30,2024-06-30 2024-06-30,2025-06-30
"""
import argparse

import pandas as pd
import requests

URL = ("https://www.cisa.gov/sites/default/files/feeds/"
       "known_exploited_vulnerabilities.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--periods", nargs="+",
                    default=["2023-06-30,2024-06-30", "2024-06-30,2025-06-30"],
                    help="cutoff,horizon_end pairs")
    ap.add_argument("--current-start-year", type=int, default=2021)
    a = ap.parse_args()

    k = pd.DataFrame(requests.get(URL, timeout=60).json()["vulnerabilities"])
    k["added"] = pd.to_datetime(k["dateAdded"])
    k["year"] = k["cveID"].str[4:8].astype(int)

    for p in a.periods:
        cutoff, horizon = p.split(",")
        cy = int(cutoff[:4])
        w = k[(k["added"] > cutoff) & (k["added"] <= horizon)]
        print(f"\nPeriod {cutoff} -> {horizon}: {len(w)} KEV additions")
        print(f"  CVE ID year newer than {cy} (cannot be known at cutoff): "
              f"{int((w['year'] > cy).sum())}")
        print("  Positives available if the CVE window starts in:")
        for start in (a.current_start_year, 2019, 2017, 2015, 2010, 2000):
            n = int(((w["year"] >= start) & (w["year"] <= cy)).sum())
            tag = "  <- current" if start == a.current_start_year else ""
            print(f"    {start}: {n}{tag}")


if __name__ == "__main__":
    main()
