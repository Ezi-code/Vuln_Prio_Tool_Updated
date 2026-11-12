import numpy as np
import pandas as pd
import pytest

from assets import tier_from_total
from model import gate_cutoff, rank_pool
from scoring import (apply_model, asset_exploit_list, exploit_report_markdown,
                     tier_exploit_summary)


def basic_pool():
    return pd.DataFrame({
        "cve_id": [f"CVE-{i}" for i in range(6)],
        "kev_at_cutoff": [False, False, False, False, True, False],
        "epss": [0.10, 0.90, 0.20, 0.80, 0.00, 0.50],
        "cvss": [5.0, 9.0, 8.0, 7.0, 1.0, 6.0],
        "tier_rank": [0, 1, 2, 1, 3, 0],
    })


def test_strict_gate_tier_cvss_order():
    out = rank_pool(basic_pool(), 0.50)
    assert list(out["cve_id"]) == ["CVE-4", "CVE-1", "CVE-3", "CVE-5",
                                   "CVE-2", "CVE-0"]
    assert out["gate"].sum() == 4


def test_kev_first_operational_order():
    pool = pd.DataFrame({
        "cve_id": ["non-kev-high", "non-kev-top", "kev-low"],
        "kev_at_cutoff": [False, False, True],
        "epss": [0.50, 0.90, 0.10],
        "cvss": [9.0, 9.0, 1.0],
        "tier_rank": [2, 3, 0],
    })
    normal = rank_pool(pool, 0.05)
    operational = rank_pool(pool, 0.05, kev_first=True)
    assert list(normal["cve_id"])[0] == "non-kev-top"
    assert list(operational["cve_id"])[0] == "kev-low"


def test_percentile_gate_is_label_free():
    pool = pd.DataFrame({
        "cve_id": [f"CVE-{i}" for i in range(100)],
        "kev_at_cutoff": [False] * 100,
        "epss": np.linspace(0.0, 0.99, 100),
        "cvss": [5.0] * 100,
        "tier_rank": [1] * 100,
    })
    cutoff = gate_cutoff(pool, gate_share=0.02)
    out = rank_pool(pool, gate_share=0.02)
    assert 0.96 < cutoff < 0.99
    assert int(out["gate"].sum()) == 2


def test_gate_share_validation():
    with pytest.raises(ValueError):
        gate_cutoff(basic_pool(), gate_share=0.0)
    with pytest.raises(ValueError):
        gate_cutoff(basic_pool())
    with pytest.raises(ValueError):
        gate_cutoff(basic_pool(), gate_share=1.0)


def test_weighted_tier_variant():
    pool = pd.DataFrame({
        "cve_id": ["high-cvss-low-tier", "low-cvss-high-tier"],
        "kev_at_cutoff": [False, False],
        "epss": [0.10, 0.10],
        "cvss": [5.0, 0.0],
        "tier_rank": [0, 3],
    })
    out = rank_pool(pool, 0.05, lam=2.0)
    assert list(out["cve_id"])[0] == "low-cvss-high-tier"


def test_apply_model_keeps_most_critical_asset():
    pairs = pd.DataFrame({
        "cve_id": ["C1", "C1", "C2"],
        "asset_name": ["workstation", "database", "web"],
        "tier": ["Medium", "Critical", "High"],
        "kev_at_cutoff": [False, False, False],
        "epss": [0.90, 0.90, 0.10],
        "cvss": [9.0, 5.0, 9.0],
        "tier_rank": [1, 3, 2],
    })
    out = apply_model(pairs, 0.50)
    assert len(out) == 2
    assert out.loc[out["cve_id"] == "C1", "asset_name"].iloc[0] == "database"


def test_apply_model_uses_asset_tier_as_priority_category():
    pairs = pd.DataFrame({
        "cve_id": ["C1", "C2", "C3"],
        "asset_id": ["A1", "A2", "A3"],
        "asset_name": ["low", "critical", "high"],
        "criticality_score": [2, 11, 8],
        "tier": ["Low", "Critical", "High"],
        "tier_rank": [0, 3, 2],
        "priority_queue": ["Monitor", "Patch now", "Patch next"],
        "kev_at_cutoff": [False, False, False],
        "epss": [0.90, 0.50, 0.70],
        "cvss": [9.0, 5.0, 7.0],
    })
    out = apply_model(pairs, 0.40)
    assert list(out["asset_tier"]) == ["Critical", "High", "Low"]
    assert list(out["priority_queue"]) == ["Patch now", "Patch next", "Monitor"]


def test_apply_model_capacity_is_separate_from_gate():
    pairs = pd.DataFrame({
        "cve_id": ["C1", "C2", "C3"],
        "asset_id": ["A1", "A2", "A3"],
        "asset_name": ["low", "critical", "high"],
        "criticality_score": [2, 11, 8],
        "tier": ["Low", "Critical", "High"],
        "tier_rank": [0, 3, 2],
        "priority_queue": ["Monitor", "Patch now", "Patch next"],
        "kev_at_cutoff": [False, False, False],
        "epss": [0.90, 0.50, 0.70],
        "cvss": [9.0, 5.0, 7.0],
    })
    out = apply_model(pairs, 0.40, capacity=2)
    assert len(out) == 2
    assert list(out["cve_id"]) == ["C2", "C3"]


def test_exploit_status_and_asset_exploit_list():
    pairs = pd.DataFrame({
        "cve_id": ["C1", "C2", "C3"],
        "asset_id": ["A1", "A2", "A3"],
        "asset_name": ["firewall", "records", "printer"],
        "criticality_score": [10, 8, 2],
        "tier": ["Critical", "High", "Low"],
        "tier_rank": [3, 2, 0],
        "priority_queue": ["Patch now", "Patch next", "Monitor"],
        "kev_at_cutoff": [True, False, False],
        "epss": [0.10, 0.90, 0.10],
        "cvss": [9.8, 7.0, 5.0],
    })
    out = apply_model(pairs, 0.50)
    assert list(out["needs_fixing"]) == [True, True, False]
    assert list(out["exploit_status"]) == [
        "Known exploited (CISA KEV at cutoff)",
        "High exploitation likelihood (EPSS gate)",
        "Below gate (monitor)",
    ]
    summary = tier_exploit_summary(out)
    assert summary.loc["Critical", "known_exploited"] == 1
    assert summary.loc["High", "epss_gated_only"] == 1
    assert summary.loc["Low", "needs_fixing"] == 0
    assets = asset_exploit_list(out)
    assert list(assets["asset_id"]) == ["A1", "A2"]
    report = exploit_report_markdown(out, "test-inventory")
    assert "# Exploit priorities: test-inventory" in report
    assert "## Critical — Patch now" in report
    assert "C1" in report
    assert "## Low — Monitor" in report


def test_tier_boundaries():
    assert tier_from_total(0) == "Low"
    assert tier_from_total(3) == "Low"
    assert tier_from_total(4) == "Medium"
    assert tier_from_total(6) == "Medium"
    assert tier_from_total(7) == "High"
    assert tier_from_total(9) == "High"
    assert tier_from_total(10) == "Critical"
    assert tier_from_total(12) == "Critical"
