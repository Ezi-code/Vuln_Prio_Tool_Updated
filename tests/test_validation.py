import pandas as pd

from validate_data import validate_vulns


def vuln_frame():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2"],
        "published": ["2024-01-01", "2024-02-01"],
        "cvss": [7.5, 9.8],
        "products": ["vendor:product", "vendor:product"],
        "description": ["ok", "ok"],
        "epss": [0.2, 0.8],
        "epss_percentile": [0.4, 0.9],
        "epss_model_version": ["v1", "v1"],
        "kev_date_added": [None, "2024-06-01"],
    })


def test_validate_vulns_accepts_clean_data():
    errors, warnings = validate_vulns(vuln_frame(), "data.csv")
    assert errors == []
    assert any("no EPSS snapshot date" in w for w in warnings)


def test_validate_vulns_catches_duplicate_and_range_errors():
    df = vuln_frame()
    df.loc[1, "cve_id"] = "CVE-1"
    df.loc[0, "epss"] = 1.5
    errors, _ = validate_vulns(df, "data.csv")
    assert any("duplicates" in e for e in errors)
    assert any("epss" in e for e in errors)


def test_validate_vulns_catches_future_publication():
    errors, _ = validate_vulns(vuln_frame(), "data.csv", cutoff="2023-12-31")
    assert any("published after the cutoff" in e for e in errors)
