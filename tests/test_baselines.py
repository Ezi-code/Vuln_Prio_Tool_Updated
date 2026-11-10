import json

import pandas as pd

from baselines import load


COLUMNS = ["cve_id", "published", "cvss", "cvss_version", "products",
           "description", "epss", "epss_percentile", "epss_model_version",
           "kev_date_added", "in_kev"]


def write_data(path):
    rows = [
        ["CVE-1", "2024-01-01", 9.8, "3.1", "a:b", "known exploited",
         0.9, 0.99, "v2023.03.01", "2024-02-01", True],
        ["CVE-2", "2024-01-02", 8.0, "3.1", "a:b", "later exploited",
         0.5, 0.90, "v2023.03.01", "2024-08-01", False],
        ["CVE-3", "2024-01-03", 7.0, "3.1", "a:b", "outside horizon",
         0.2, 0.80, "v2023.03.01", "2025-08-01", False],
        ["CVE-4", "2024-07-02", 7.0, "3.1", "a:b", "published after cutoff",
         0.1, 0.70, "v2023.03.01", "", False],
        ["CVE-5", "2024-01-04", 7.0, "3.1", "a:b", "** REJECT ** duplicate",
         0.1, 0.70, "v2023.03.01", "", False],
        ["CVE-6", "2024-01-05", 7.0, "3.1", "a:b", "missing EPSS",
         "", "", "v2023.03.01", "", False],
    ]
    pd.DataFrame(rows, columns=COLUMNS).to_csv(path, index=False)


def test_load_temporal_labels(tmp_path):
    path = tmp_path / "vulns.csv"
    write_data(path)
    df = load(path, "2024-06-30", "2025-06-30")
    assert set(df["cve_id"]) == {"CVE-1", "CVE-2", "CVE-3", "CVE-6"}
    by_id = df.set_index("cve_id")
    assert bool(by_id.loc["CVE-1", "kev_at_cutoff"]) is True
    assert bool(by_id.loc["CVE-1", "exploited_after"]) is False
    assert bool(by_id.loc["CVE-2", "kev_at_cutoff"]) is False
    assert bool(by_id.loc["CVE-2", "exploited_after"]) is True
    assert bool(by_id.loc["CVE-3", "exploited_after"]) is False
    assert bool(by_id.loc["CVE-6", "has_epss"]) is False
    assert by_id.loc["CVE-6", "epss"] == 0.0


def test_load_warns_on_stale_epss_snapshot(tmp_path, capsys):
    path = tmp_path / "vulns.csv"
    write_data(path)
    meta = path.with_suffix(path.suffix + ".meta.json")
    meta.write_text(json.dumps({"epss_snapshot_date": "2023-01-01"}),
                    encoding="utf-8")
    load(path, "2024-06-30", "2025-06-30")
    out = capsys.readouterr().out
    assert "WARNING: EPSS snapshot" in out
