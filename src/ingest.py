"""
ingest.py - Download NVD, EPSS and CISA KEV data and merge into one table.

Usage (from the project folder, with the venv active):
    python src/ingest.py --start 2023-01-01 --end 2024-12-31 --epss-date 2024-12-31

Optional: set an NVD API key for faster downloads (PowerShell):
    $env:NVD_API_KEY = "your-key-here"

Output: data/processed/vulns.csv plus vulns.csv.meta.json (provenance)
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_BASE = "https://epss.cyentia.com"

RAW = Path("data/raw")
PROCESSED = Path("data/processed")
WINDOW_DAYS = 119  # NVD allows at most 120 days per date-range query


# ---------------------------------------------------------------- KEV
def download_kev():
    """Return a DataFrame: cve_id, kev_date_added.

    The feed release date is attached as ``df.attrs["kev_release"]`` so the
    provenance sidecar records which KEV snapshot was used, not just today's
    download time.
    """
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    payload = r.json()
    items = payload["vulnerabilities"]
    df = pd.DataFrame(items)[["cveID", "dateAdded"]]
    df.columns = ["cve_id", "kev_date_added"]
    df["kev_date_added"] = pd.to_datetime(df["kev_date_added"])
    df.attrs["kev_release"] = payload.get("dateReleased", "")
    return df


# --------------------------------------------------------------- EPSS
def download_epss(date=None):
    """Return a DataFrame: cve_id, epss, epss_percentile, epss_model_version.
    date=None gives the latest scores; otherwise use 'YYYY-MM-DD'."""
    name = "epss_scores-current.csv.gz" if date is None \
        else f"epss_scores-{date}.csv.gz"
    r = requests.get(f"{EPSS_BASE}/{name}", timeout=120)
    r.raise_for_status()
    text = gzip.decompress(r.content).decode("utf-8")
    first_line = text.split("\n", 1)[0]  # e.g. "#model_version:v2025.03.14,..."
    version = first_line.split(",")[0].replace("#model_version:", "").strip()
    df = pd.read_csv(io.StringIO(text), skiprows=1)
    df.columns = ["cve_id", "epss", "epss_percentile"]
    df["epss_model_version"] = version
    df["epss_snapshot_date"] = date or datetime.now().strftime("%Y-%m-%d")
    return df


# ---------------------------------------------------------------- NVD
def _cvss(metrics):
    """Pick the best available CVSS base score and its version."""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                     ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        if key in metrics and metrics[key]:
            m = metrics[key][0]["cvssData"]
            return m.get("baseScore"), ver
    return None, None


def _products(configurations):
    """Return a ';'-joined set of vendor:product pairs from CPE matches."""
    found = set()
    for conf in configurations or []:
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    parts = m["criteria"].split(":")
                    if len(parts) > 4:
                        found.add(f"{parts[3]}:{parts[4]}")
    return ";".join(sorted(found))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_nvd_item(item):
    cve = item["cve"]
    score, ver = _cvss(cve.get("metrics", {}))
    desc = next((d["value"] for d in cve.get("descriptions", [])
                 if d["lang"] == "en"), "")
    return {
        "cve_id": cve["id"],
        "published": cve.get("published"),
        "cvss": score,
        "cvss_version": ver,
        "products": _products(cve.get("configurations")),
        "description": desc,
    }


def fetch_nvd_window(start, end, api_key=None):
    """Download all CVEs published between start and end (datetime)."""
    RAW.mkdir(parents=True, exist_ok=True)
    cache = RAW / f"nvd_{start:%Y%m%d}_{end:%Y%m%d}.json"
    if cache.exists():  # resume support
        return json.loads(cache.read_text(encoding="utf-8"))

    headers = {"apiKey": api_key} if api_key else {}
    pause = 0.7 if api_key else 6.5  # respect rate limits
    rows, index = [], 0
    while True:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 2000,
            "startIndex": index,
        }
        r = None
        for attempt in range(8):
            try:
                r = requests.get(NVD_URL, params=params, headers=headers,
                                 timeout=120)
            except requests.exceptions.RequestException as e:
                # dropped connection, timeout, etc: retry this page only
                print(f"  Network error ({type(e).__name__}). "
                      f"Retrying page (attempt {attempt + 1}/8) ...")
                time.sleep(10 * (attempt + 1))
                continue
            if r.status_code == 200:
                break
            print(f"  NVD returned {r.status_code}: "
                  f"{r.headers.get('message', 'no message')}")
            if r.status_code in (401, 404) and headers:
                print("  API key rejected (invalid or not activated). "
                      "Continuing WITHOUT the key (slower but works).")
                headers, pause = {}, 6.5
                continue
            time.sleep(10 * (attempt + 1))  # back off on 403/503
        else:
            code = r.status_code if r is not None else "no response"
            raise RuntimeError(f"NVD request failed after 8 attempts: {code}")
        data = r.json()
        rows += [parse_nvd_item(i) for i in data["vulnerabilities"]]
        index += data["resultsPerPage"]
        print(f"  {start:%Y-%m-%d}..{end:%Y-%m-%d}: "
              f"{len(rows)}/{data['totalResults']}")
        if index >= data["totalResults"]:
            break
        time.sleep(pause)
    cache.write_text(json.dumps(rows), encoding="utf-8")
    time.sleep(pause)
    return rows


def download_nvd(start, end, api_key=None):
    rows, cur = [], start
    while cur <= end:
        win_end = min(cur + timedelta(days=WINDOW_DAYS), end)
        rows += fetch_nvd_window(cur, win_end, api_key)
        cur = win_end + timedelta(days=1)
    return pd.DataFrame(rows).drop_duplicates("cve_id")


# -------------------------------------------------------------- merge
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="CVE publish start YYYY-MM-DD")
    ap.add_argument("--end", required=True, help="CVE publish end YYYY-MM-DD")
    ap.add_argument("--out", default="data/processed/vulns.csv",
                    help="Output CSV path")
    ap.add_argument("--epss-date", default=None,
                    help="EPSS snapshot date YYYY-MM-DD (default: latest)")
    a = ap.parse_args()

    start = datetime.strptime(a.start, "%Y-%m-%d")
    end = datetime.strptime(a.end, "%Y-%m-%d")
    api_key = os.environ.get("NVD_API_KEY")
    print("NVD API key:", "found" if api_key else "NOT set (slow mode)")

    print("Downloading KEV ...")
    kev = download_kev()
    print(f"  {len(kev)} KEV entries")

    print("Downloading EPSS ...")
    epss = download_epss(a.epss_date)
    print(f"  {len(epss)} scores, model {epss['epss_model_version'].iloc[0]}")

    print("Downloading NVD (this can take a while) ...")
    nvd = download_nvd(start, end, api_key)
    print(f"  {len(nvd)} CVEs")

    df = (nvd.merge(epss, on="cve_id", how="left")
             .merge(kev, on="cve_id", how="left"))
    df["in_kev"] = df["kev_date_added"].notna()

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    meta = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "start": a.start, "end": a.end,
        "nvd_start": a.start, "nvd_end": a.end,
        "epss_snapshot_date": str(epss["epss_snapshot_date"].iloc[0]),
        "epss_model_version": str(epss["epss_model_version"].iloc[0]),
        "kev_release": kev.attrs.get("kev_release", ""),
        "kev_snapshot_date": datetime.now().strftime("%Y-%m-%d"),
        "kev_rows": int(len(kev)), "nvd_rows": int(len(nvd)),
        "output_rows": int(len(df)),
        "output_sha256": sha256_file(out),
        "sources": ["NVD 2.0", "EPSS", "CISA KEV"],
        "notes": "KEV is downloaded as the current feed; labels are filtered "
                 "by kev_date_added at evaluation time. EPSS is snapshot-dated.",
    }
    meta_path = out.with_suffix(out.suffix + ".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Saved {len(df)} rows to {out}")
    print(f"Metadata written to {meta_path}")
    print(df[["cvss", "epss", "in_kev"]].describe(include="all"))


if __name__ == "__main__":
    main()
