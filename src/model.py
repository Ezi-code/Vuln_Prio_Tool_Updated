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

gate_share : optional, label-free alternative to a fixed EPSS threshold. The
             gate is the top `gate_share` of THIS pool's EPSS distribution
             (e.g. 0.02 for the top 2%). KEV members always pass. This adapts
             to each organization's list and to EPSS snapshot changes, so the
             same rule can be applied to a later evaluation period. It does
             not use the outcome labels.
kev_first  : operational option. Put CVEs already in KEV at the cutoff above
             all EPSS-only-gated CVEs. Evaluation pools exclude KEV at the
             cutoff, so this has no effect on the holdout metrics.
"""
import pandas as pd

TIER_MAX = 3


def gate_cutoff(pool, thr=None, gate_share=None):
    """Return the EPSS cutoff used by the Stage 1 gate.

    Pass one of:
      thr         fixed EPSS threshold (the original design)
      gate_share  top share of this pool's EPSS distribution, e.g. 0.02
    If both are supplied, gate_share wins.
    """
    if gate_share is not None:
        if not 0 < gate_share < 1:
            raise ValueError("gate_share must be between 0 and 1")
        return float(pool["epss"].quantile(1.0 - gate_share))
    if thr is None:
        raise ValueError("pass either thr or gate_share")
    return float(thr)


def rank_pool(pool, thr=None, lam=None, gate_share=None, kev_first=False,
              capacity=None):
    """Return the pool ordered best-first. Needs columns: kev_at_cutoff, epss,
    cvss, tier_rank.

    The gate is either a fixed EPSS threshold (`thr`) or the top
    `gate_share` of this pool's EPSS distribution; see `gate_cutoff`.

    `capacity` is an optional final-list size.  It is applied AFTER ranking,
    so it is deliberately separate from the Stage 1 candidate gate.  This is
    what lets Stage 2 and Stage 3 change which CVEs make the final list when
    the candidate gate is broader than the operational budget.
    """
    if capacity is not None and capacity < 0:
        raise ValueError("capacity must be non-negative")
    cutoff = gate_cutoff(pool, thr, gate_share)
    p = pool.assign(gate=pool["kev_at_cutoff"] | (pool["epss"] >= cutoff))
    keys = ["gate"] + (["kev_at_cutoff"] if kev_first else [])
    if lam is None:
        keys += ["tier_rank", "cvss", "epss"]
        out = p.sort_values(keys, ascending=False, kind="stable")
    else:
        p["score"] = lam * p["tier_rank"] / TIER_MAX + p["cvss"] / 10.0
        keys += ["score", "epss"]
        out = p.sort_values(keys, ascending=False, kind="stable")
    return out.head(capacity) if capacity is not None else out
