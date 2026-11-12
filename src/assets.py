"""
assets.py - Asset-criticality instrument, synthetic inventories, and the
matching of CVEs to the products an organization actually runs.

Questionnaire (section 5.2.2). Each question is scored 0-3:
  exposure          0 internal only | 1 VPN/remote access | 2 partly public | 3 internet-facing
  data_sensitivity  0 public | 1 internal | 2 confidential | 3 regulated
  business_function 0 informational | 1 supporting | 2 operational | 3 production-critical
  redundancy        0 fully backed up | 1 manual fallback | 2 partial | 3 single point of failure
Total (0-12) -> tier: 0-3 Low, 4-6 Medium, 7-9 High, 10-12 Critical.

Usage:
    python src/assets.py        # writes 4 synthetic inventories to data/inventories/
"""
from pathlib import Path

import pandas as pd

CRITERIA = ["exposure", "data_sensitivity", "business_function", "redundancy"]
TIERS = ["Low", "Medium", "High", "Critical"]
TIER_RANK = {t: i for i, t in enumerate(TIERS)}

# Asset tiers are also the operational priority categories.  Keeping the
# queue labels in one place avoids a second, conflicting taxonomy in the
# report and the UI.
QUEUE_BY_TIER = {
    "Critical": "Patch now",
    "High": "Patch next",
    "Medium": "Scheduled",
    "Low": "Monitor",
}

REQUIRED_COLUMNS = ["asset_id", "asset_name", "software"] + CRITERIA
OPTIONAL_COLUMNS = ["owner", "patchable", "maintenance_window",
                    "compensating_control", "notes"]
REQUIRED_SOFTWARE_FORMAT = "semicolon-separated vendor:product tokens"


def tier_from_total(total):
    if total <= 3:
        return "Low"
    if total <= 6:
        return "Medium"
    if total <= 9:
        return "High"
    return "Critical"


def validate_inventory(path_or_df):
    """Validate an inventory and return a normalised DataFrame.

    The CSV does not require a CMDB.  Only the seven required columns are
    needed; the optional columns support operational constraints such as
    assets that cannot be patched immediately.
    """
    if isinstance(path_or_df, (str, Path)):
        path = Path(path_or_df)
        inv = pd.read_csv(path)
        label = str(path)
    else:
        inv = path_or_df.copy()
        label = "inventory"

    missing = [c for c in REQUIRED_COLUMNS if c not in inv.columns]
    if missing:
        raise ValueError(
            f"{label}: missing required columns {missing}. "
            f"Required: {REQUIRED_COLUMNS}. "
            f"Optional: {OPTIONAL_COLUMNS}."
        )

    if inv["asset_id"].isna().any() or inv["asset_id"].astype(str).str.strip().eq("").any():
        raise ValueError(f"{label}: asset_id must be present and non-empty")
    if inv["asset_id"].duplicated().any():
        dupes = sorted(inv.loc[inv["asset_id"].duplicated(), "asset_id"].astype(str).unique())
        raise ValueError(f"{label}: duplicate asset_id values: {dupes}")
    if inv["asset_name"].isna().any():
        raise ValueError(f"{label}: asset_name must be present")
    if inv["software"].isna().any() or inv["software"].astype(str).str.strip().eq("").any():
        raise ValueError(f"{label}: software must be present; use {REQUIRED_SOFTWARE_FORMAT}")

    for c in CRITERIA:
        inv[c] = pd.to_numeric(inv[c], errors="raise").astype(int)
        if not inv[c].between(0, 3).all():
            raise ValueError(f"{label}: '{c}' must be between 0 and 3")

    for c in OPTIONAL_COLUMNS:
        if c not in inv.columns:
            inv[c] = ""
    if "patchable" in inv.columns:
        allowed = {"", "yes", "no", "unknown", "y", "n"}
        vals = inv["patchable"].fillna("").astype(str).str.strip().str.lower()
        bad = sorted(set(vals) - allowed)
        if bad:
            raise ValueError(
                f"{label}: patchable must be one of yes/no/unknown (got {bad})"
            )
        inv["patchable"] = vals

    inv["criticality_score"] = inv[CRITERIA].sum(axis=1)
    inv["tier"] = inv["criticality_score"].map(tier_from_total)
    inv["tier_rank"] = inv["tier"].map(TIER_RANK)
    inv["priority_queue"] = inv["tier"].map(QUEUE_BY_TIER)
    return inv


def load_inventory(path):
    """Read an inventory CSV and compute each asset's criticality tier."""
    return validate_inventory(path)


# --------------------------------------------------- CVE <-> asset matching
def explode_products(vulns):
    """One row per (cve_id, vendor:product). Do this once and reuse."""
    s = vulns[["cve_id", "products"]].dropna()
    s = s.assign(product=s["products"].str.split(";")).explode("product")
    return s[["cve_id", "product"]]


def match_vulns(vulns, prod_df, inv):
    """Return one row per (CVE, asset) where the asset runs an affected
    product. Matching is by vendor:product PREFIX and ignores versions, so
    'microsoft:windows_10' matches windows_10_21h2 etc. (see limitations)."""
    tokens = (inv[["asset_id", "software"]]
              .assign(token=inv["software"].str.split(";"))
              .explode("token"))
    parts, unmatched = [], []
    for _, t in tokens.iterrows():
        tok = t["token"].strip()
        hit = prod_df.loc[prod_df["product"].str.startswith(tok), "cve_id"].unique()
        if len(hit) == 0:
            unmatched.append(tok)
            continue
        parts.append(pd.DataFrame({"cve_id": hit, "asset_id": t["asset_id"],
                                   "matched_product": tok}))
    if unmatched:
        print(f"  (no CVEs found for: {', '.join(sorted(set(unmatched)))})")
    if not parts:
        return pd.DataFrame()
    pairs = pd.concat(parts).drop_duplicates(["cve_id", "asset_id"])
    asset_cols = ["asset_id", "asset_name", "criticality_score", "tier",
                  "tier_rank", "priority_queue"]
    asset_cols += [c for c in OPTIONAL_COLUMNS if c in inv.columns]
    pairs = pairs.merge(inv[asset_cols], on="asset_id")
    return pairs.merge(vulns, on="cve_id")


# ------------------------------------------------- synthetic inventories
# (asset_id, asset_name, software, exposure, sensitivity, function, redundancy)
INVENTORIES = {
    "ngo_office": [
        ("N1", "Staff workstations", "microsoft:windows_10;microsoft:windows_11;microsoft:office;google:chrome;mozilla:firefox;adobe:acrobat_reader", 0, 1, 1, 0),
        ("N2", "File server", "microsoft:windows_server_2019", 0, 2, 2, 2),
        ("N3", "Public website", "wordpress:wordpress;php:php;apache:http_server;oracle:mysql", 3, 1, 1, 2),
        ("N4", "Mail server", "microsoft:exchange_server", 3, 2, 2, 3),
        ("N5", "Firewall", "fortinet:fortios", 3, 1, 3, 3),
        ("N6", "Donor database", "postgresql:postgresql;linux:linux_kernel", 0, 3, 2, 2),
        ("N7", "Office router", "mikrotik:routeros", 2, 0, 1, 3),
    ],
    "small_clinic": [
        ("C1", "Patient records server", "microsoft:windows_server_2022;microsoft:sql_server", 0, 3, 3, 3),
        ("C2", "Reception PCs", "microsoft:windows_10;microsoft:office;google:chrome", 0, 2, 2, 1),
        ("C3", "Clinic website", "wordpress:wordpress;php:php;f5:nginx", 3, 0, 0, 1),
        ("C4", "Imaging workstation", "microsoft:windows_10", 0, 3, 3, 3),
        ("C5", "VPN gateway", "paloaltonetworks:pan-os", 3, 2, 3, 3),
        ("C6", "Backup NAS", "linux:linux_kernel;samba:samba", 0, 3, 2, 1),
        ("C7", "Wi-Fi router", "mikrotik:routeros", 2, 0, 1, 3),
    ],
    "university_dept": [
        ("U1", "Learning management system", "moodle:moodle;php:php;oracle:mysql;apache:http_server", 3, 2, 2, 2),
        ("U2", "Research compute server", "linux:linux_kernel;openbsd:openssh;python:python", 1, 2, 2, 1),
        ("U3", "Lab PCs", "microsoft:windows_11;google:chrome;mozilla:firefox", 0, 0, 1, 0),
        ("U4", "Staff PCs", "microsoft:windows_10;microsoft:windows_11;microsoft:office;adobe:acrobat_reader", 0, 2, 2, 0),
        ("U5", "Student records database", "microsoft:sql_server;microsoft:windows_server_2022", 1, 3, 3, 2),
        ("U6", "Department website", "drupal:drupal;php:php;apache:http_server", 3, 0, 1, 1),
        ("U7", "Firewall", "paloaltonetworks:pan-os", 3, 1, 3, 3),
        ("U8", "Virtualization host", "vmware:esxi", 1, 2, 3, 3),
        ("U9", "Campus switch", "cisco:ios_xe", 2, 1, 2, 2),
    ],
    "sme_retail": [
        ("R1", "Point-of-sale terminals", "microsoft:windows_10", 0, 3, 3, 2),
        ("R2", "Online shop", "wordpress:wordpress;php:php;f5:nginx;oracle:mysql", 3, 3, 3, 3),
        ("R3", "Accounting PC", "microsoft:windows_11;microsoft:office", 0, 3, 2, 2),
        ("R4", "Router / firewall", "fortinet:fortios", 3, 1, 3, 3),
        ("R5", "Staff laptops", "microsoft:windows_11;google:chrome;microsoft:edge_chromium", 0, 1, 1, 0),
        ("R6", "Inventory server", "microsoft:windows_server_2019;microsoft:sql_server", 0, 2, 3, 3),
        ("R7", "CCTV recorder", "linux:linux_kernel", 1, 1, 1, 2),
    ],
}


def make_synthetic(out_dir="data/inventories"):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cols = ["asset_id", "asset_name", "software"] + CRITERIA
    for name, rows in INVENTORIES.items():
        pd.DataFrame(rows, columns=cols).to_csv(out / f"{name}.csv", index=False)
        print(f"wrote {out / (name + '.csv')} ({len(rows)} assets)")


if __name__ == "__main__":
    make_synthetic()
