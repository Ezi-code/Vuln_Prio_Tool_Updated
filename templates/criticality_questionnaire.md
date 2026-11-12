# Asset Criticality Questionnaire

Use one row per asset, system, or small system group. No CMDB is required.
Score each question from 0 to 3. Total the four answers (0–12), then use the
tier boundaries below. The same four scores are loaded from the inventory CSV.

## Questions and anchors

### 1. Exposure — who can reach the asset?
| Score | Anchor |
|---:|---|
| 0 | Internal only; no remote access from outside the organization. |
| 1 | Reachable through a VPN, remote-access service, or a trusted partner link. |
| 2 | Partly public: some services or ports are exposed to the internet, or the asset shares a network with public services. |
| 3 | Internet-facing: the asset directly serves external users or is reachable from the public internet. |

### 2. Data sensitivity — what data does it hold or process?
| Score | Anchor |
|---:|---|
| 0 | Public or non-sensitive information only. |
| 1 | Internal information with limited harm if disclosed. |
| 2 | Confidential organizational, staff, customer, or operational data. |
| 3 | Regulated, clinical, financial, identity, or other high-harm data. |

### 3. Business function — what happens if the asset is unavailable?
| Score | Anchor |
|---:|---|
| 0 | Informational; no material effect. |
| 1 | Supporting function; work can continue with manual workarounds. |
| 2 | Operational function; an outage disrupts core work or service delivery. |
| 3 | Production-critical or safety-critical; the organization cannot operate without it. |

### 4. Redundancy — how quickly can the organization recover?
| Score | Anchor |
|---:|---|
| 0 | Fully backed up or replicated; restoration is routine and tested. |
| 1 | Manual fallback exists and is usable. |
| 2 | Partial redundancy; recovery is slow, untested, or incomplete. |
| 3 | Single point of failure; no practical fallback. |

## Tier boundaries

| Total score | Asset tier | Operational queue |
|---:|---|---|
| 0–3 | Low | Monitor |
| 4–6 | Medium | Scheduled |
| 7–9 | High | Patch next |
| 10–12 | Critical | Patch now |

## Scoring rules

1. Score the asset as it is used today, not as it was originally designed.
2. If two answers are plausible, choose the one with the higher impact and write
   the reason in the notes column.
3. Do not score the vulnerability here. This questionnaire describes the asset;
   the vulnerability signals are EPSS, KEV, and CVSS.
4. A second assessor should score a sample independently when possible. Report
   agreement and resolve differences by discussion.
5. Record the date and assessor in the inventory notes or a separate sheet.
6. If an asset cannot be patched, record `patchable=no` and a compensating
   control. Do not lower its criticality tier just because patching is hard.

## Worked examples

### Public website
- Exposure 3, data sensitivity 1, business function 1, redundancy 2 = **7 (High)**
- Internet-facing, but low data sensitivity and a quick rebuild path.

### Patient records server
- Exposure 0, data sensitivity 3, business function 3, redundancy 3 = **9 (High)**
- Internal but regulated data, production-critical, and a single point of failure.
  If the organization treats it as life-critical, the assessor may justify a
  Critical score; record the reason.

### Staff workstation
- Exposure 0, data sensitivity 1, business function 1, redundancy 0 = **2 (Low)**
- Individually low impact, although a group of compromised workstations may need
  a separate group-level assessment.

## Consistency check

For a research sample, have 5–8 practitioners independently score the same
8–12 asset profiles. Report:

- absolute agreement on the four scores;
- agreement on the final tier (Cohen's kappa or ICC);
- completion time per asset;
- any anchors that practitioners found ambiguous.

The goal is not perfect agreement. The goal is a transparent instrument with
documented reliability and a clear revision record.
