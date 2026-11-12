"""
validate_data.py - Schema, leakage, and provenance checks for the processed
vulnerability data and the inventory CSVs.

This is intentionally independent of the model.  It answers the reviewer
question: "can someone else tell exactly which data and snapshot produced this
number?"

Usage:
    python src/validate_data.py
    python src/validate_data.py --cutoff 2024-06-30 --horizon-end 2025-06-30
    python src/validate_data.py --write-manifest data/manifest.json
"""
import argparse
import csv
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pandas as pd

from assets import OPTIONAL_COLUMNS, REQUIRED_COLUMNS, validate_inventory

VULN_REQUIRED = [
    "cve_id", "published", "cvss", "products", "description",
    "epss", "epss_percentile", "epss_model_version", "kev_date_added",
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_meta(path):
    p = Path(path)
    for candidate in (p.with_suffix(".meta.json"),
                      p.with_suffix(p.suffix + ".meta.json")):
        if candidate.exists():
            try:
                return json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return {}
    return {}


def validate_vulns(df, path="data", cutoff=None, horizon_end=None):
    """Return (errors, warnings).  Errors mean the data must not be used."""
    errors, warnings = [], []

    missing = [c for c in VULN_REQUIRED if c not in df.columns]
    if missing:
        errors.append(f"missing required columns: {missing}")
        return errors, warnings

    if df["cve_id"].isna().any() or df["cve_id"].duplicated().any():
        errors.append("cve_id contains nulls or duplicates")

    for date_col in ("published", "kev_date_added"):
        parsed = pd.to_datetime(df[date_col], errors="coerce")
        bad = int(parsed.isna().sum() - df[date_col].isna().sum())
        if bad:
            errors.append(f"{date_col}: {bad} values cannot be parsed as dates")

    for col, lo, hi in (("cvss", 0.0, 10.0), ("epss", 0.0, 1.0),
                        ("epss_percentile", 0.0, 1.0)):
        vals = pd.to_numeric(df[col], errors="coerce")
        bad = int(((vals < lo) | (vals > hi)).sum())
        if bad:
            errors.append(f"{col}: {bad} values outside [{lo}, {hi}]")

    versions = df["epss_model_version"].dropna().astype(str).unique()
    if len(versions) > 1:
        warnings.append(f"multiple EPSS model versions in one file: {sorted(versions)[:5]}")
    if not len(versions):
        warnings.append("no EPSS model version recorded")

    published = pd.to_datetime(df["published"], errors="coerce")
    meta = read_meta(path)
    snap = meta.get("epss_snapshot_date")
    if not snap:
        warnings.append(
            "no EPSS snapshot date in a .meta.json sidecar. "
            "Rebuild with src/ingest.py before using this file for a "
            "confirmatory result."
        )
    elif cutoff is not None:
        try:
            if pd.Timestamp(snap) > pd.Timestamp(cutoff) + pd.Timedelta(days=1):
                errors.append(
                    f"EPSS snapshot {snap} is later than cutoff {cutoff}"
                )
        except (TypeError, ValueError):
            warnings.append(f"unreadable EPSS snapshot date: {snap!r}")

    if cutoff is not None:
        cutoff = pd.Timestamp(cutoff)
        future = int((published > cutoff + pd.Timedelta(days=1)).sum())
        if future:
            errors.append(f"{future} CVEs were published after the cutoff {cutoff:%Y-%m-%d}")

        kev = pd.to_datetime(df["kev_date_added"], errors="coerce")
        if horizon_end is not None:
            horizon = pd.Timestamp(horizon_end)
            late = int((kev > horizon).sum())
            if late:
                warnings.append(
                    f"{late} KEV additions after the label horizon "
                    f"{horizon:%Y-%m-%d} are present; ensure evaluation "
                    "filters labels to the horizon."
                )

    return errors, warnings


def validate_inventories(folder):
    errors, warnings, entries = [], [], {}
    folder = Path(folder)
    if not folder.exists():
        warnings.append(f"inventory folder not found: {folder}")
        return errors, warnings, entries
    for path in sorted(folder.glob("*.csv")):
        try:
            inv = validate_inventory(path)
            entries[path.name] = {
                "rows": int(len(inv)),
                "columns": list(inv.columns),
                "sha256": sha256_file(path),
            }
        except Exception as exc:  # noqa: BLE001 - report the full reason
            errors.append(f"{path.name}: {exc}")
    return errors, warnings, entries


def manifest_entry(path):
    path = Path(path)
    p = {"path": str(path), "exists": path.exists()}
    if not path.exists():
        return p
    p.update({
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "meta": read_meta(path),
    })
    if path.suffix.lower() == ".csv":
        try:
            with path.open(newline="", encoding="utf-8") as fh:
                reader = csv.reader(fh)
                next(reader, None)
                p["rows"] = int(sum(1 for _ in reader))
        except OSError:
            pass
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed/vulns.csv")
    ap.add_argument("--inventories", default="data/inventories")
    ap.add_argument("--cutoff", default=None)
    ap.add_argument("--horizon-end", default=None)
    ap.add_argument("--write-manifest", default="data/manifest.json")
    a = ap.parse_args()

    errors, warnings = [], []
    data_path = Path(a.data)
    if not data_path.exists():
        errors.append(f"data file not found: {data_path}")
        df = None
    else:
        df = pd.read_csv(data_path)
        e, w = validate_vulns(df, data_path, a.cutoff, a.horizon_end)
        errors += e
        warnings += w

    ie, iw, inv_entries = validate_inventories(a.inventories)
    errors += ie
    warnings += iw

    print(f"Data: {data_path}")
    if df is not None:
        print(f"  rows: {len(df):,}; columns: {len(df.columns)}")
    print(f"  errors: {len(errors)}; warnings: {len(warnings)}")
    for msg in errors:
        print(f"  ERROR: {msg}")
    for msg in warnings:
        print(f"  WARNING: {msg}")

    manifest = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "data": manifest_entry(data_path),
        "inventories": inv_entries,
        "inventory_required_columns": REQUIRED_COLUMNS,
        "inventory_optional_columns": OPTIONAL_COLUMNS,
        "validation": {"errors": errors, "warnings": warnings},
    }
    out = Path(a.write_manifest)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Manifest written to {out}")
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
