import pandas as pd
import pytest

from pathlib import Path

from assets import (QUEUE_BY_TIER, TIERS, load_inventory, validate_inventory)


def inventory_df():
    return pd.DataFrame({
        "asset_id": ["A1", "A2", "A3"],
        "asset_name": ["Public site", "Records", "Workstation"],
        "software": ["wordpress:wordpress", "microsoft:sql_server",
                     "microsoft:windows_10"],
        "exposure": [3, 1, 0],
        "data_sensitivity": [1, 3, 1],
        "business_function": [1, 3, 1],
        "redundancy": [2, 3, 0],
    })


def test_asset_tiers_are_the_priority_categories():
    inv = validate_inventory(inventory_df())
    assert list(inv["tier"]) == ["High", "Critical", "Low"]
    assert list(inv["priority_queue"]) == [
        QUEUE_BY_TIER["High"], QUEUE_BY_TIER["Critical"], QUEUE_BY_TIER["Low"]
    ]
    assert TIERS == ["Low", "Medium", "High", "Critical"]
    assert set(QUEUE_BY_TIER) == set(TIERS)


def test_optional_operational_columns_are_kept():
    inv = inventory_df()
    inv["patchable"] = ["yes", "no", "unknown"]
    inv["owner"] = ["web", "clinical", "it"]
    out = validate_inventory(inv)
    assert out.loc[out["asset_id"] == "A2", "patchable"].iloc[0] == "no"
    assert out.loc[out["asset_id"] == "A2", "owner"].iloc[0] == "clinical"


def test_inventory_rejects_missing_columns():
    inv = inventory_df().drop(columns=["software"])
    with pytest.raises(ValueError, match="missing required columns"):
        validate_inventory(inv)


def test_inventory_rejects_bad_scores_and_duplicate_ids():
    inv = inventory_df()
    inv.loc[0, "exposure"] = 4
    with pytest.raises(ValueError, match="between 0 and 3"):
        validate_inventory(inv)

    inv = inventory_df()
    inv.loc[1, "asset_id"] = "A1"
    with pytest.raises(ValueError, match="duplicate asset_id"):
        validate_inventory(inv)


def test_load_inventory_template(tmp_path):
    path = tmp_path / "inventory.csv"
    inventory_df().to_csv(path, index=False)
    out = load_inventory(path)
    assert len(out) == 3
    assert out["criticality_score"].tolist() == [7, 10, 2]


def test_repository_template_is_valid():
    path = Path(__file__).resolve().parents[1] / "templates" / "asset_inventory_template.csv"
    out = load_inventory(path)
    assert len(out) == 4
    assert {"Critical", "High"} <= set(out["tier"])
