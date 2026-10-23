"""
model.py - The three-stage model exactly as specified in section 5.2.1.

  Stage 1 Threat gate        : in KEV at the cutoff OR EPSS >= threshold.
                               Unflagged CVEs are deprioritized, not discarded.
  Stage 2 Criticality        : flagged CVEs are weighted by the asset tier
                               (Low, Medium, High, Critical).
  Stage 3 Severity tie-break : within a tier, higher CVSS base score first.
                               (Remaining ties: higher EPSS, an implementation
                               choice to be stated in section 5.2.1.)

lam=None  -> strict tiers, the design as specified (tier first, CVSS inside).
lam=float -> weighted variant for the sensitivity analysis of section 5.6:
             score = lam * tier/3 + CVSS/10. lam=0 ignores criticality; for
             lam >= 3 a one-tier step outweighs the whole CVSS range, which
             is the same ordering as strict tiers.
"""
import pandas as pd

TIER_MAX = 3


def rank_pool(pool, thr, lam=None):
    """Return the pool ordered best-first. Needs columns: kev_at_cutoff, epss,
    cvss, tier_rank."""
    p = pool.assign(gate=pool["kev_at_cutoff"] | (pool["epss"] >= thr))
    if lam is None:
        return p.sort_values(["gate", "tier_rank", "cvss", "epss"],
                             ascending=False, kind="stable")
    p["score"] = lam * p["tier_rank"] / TIER_MAX + p["cvss"] / 10.0
    return p.sort_values(["gate", "score", "epss"], ascending=False, kind="stable")
