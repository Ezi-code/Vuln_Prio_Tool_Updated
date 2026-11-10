import numpy as np
import pandas as pd

from montecarlo import eval_pool


def test_top_budget_without_a_positive_does_not_crash():
    n = 100
    pool = pd.DataFrame({
        "cve_id": [f"CVE-{i}" for i in range(n)],
        "exploited_after": [False] * (n - 1) + [True],
        "tier_rank": [1] * n,
        "cvss": [5.0] * n,
        # CVE-99 is the only positive, but it has the LOWEST EPSS score and is
        # therefore outside every top budget tested here.
        "epss": np.linspace(1.0, 0.0, n),
        "published": pd.date_range("2024-01-01", periods=n, freq="D"),
    })
    out, arrays = eval_pool(pool, 0.005, {"CVE-99": 0}, 1, gate_share=0.02)
    assert out["positives"] == 1
    assert out["Model|0.02|recall"] == 0.0
    assert arrays["present"].sum() == 1.0
