# Practitioner usability test

## Purpose

Test whether an IT or security practitioner can use the inventory instrument
and the ranked output without analyst help. This is an RQ2 instrument test, not
a model-accuracy test.

## Participants

Recruit 5–8 practitioners from resource-constrained organisations (NGO,
clinic, SME, university department). A participant should have day-to-day
responsibility for patching or asset ownership. Record role, organisation type,
and experience band; do not record names in the analysis file.

If the organisation requires ethics approval, obtain it before recruitment.
Keep consent forms and raw notes separate from the repository.

## Session 1: criticality scoring (about 30 minutes)

Give each participant the same 8–12 asset profiles and the questionnaire in
`templates/criticality_questionnaire.md`.

For each asset:

1. Ask the participant to read the profile and score the four questions.
2. Record the four scores, total, tier, and elapsed time.
3. Ask them to think aloud only if that does not disrupt the task.
4. At the end, ask which anchors were ambiguous and what they would change.

Do not show the expected tier before scoring. Do not correct a score during the
task; record disagreements for the debrief.

Analysis:

- absolute agreement for each of the four questions;
- exact tier agreement and agreement within one tier;
- Cohen's kappa or ICC for tier agreement;
- median completion time per asset;
- a short list of ambiguous anchors and proposed wording changes.

## Session 2: ranked-list task (about 20 minutes)

Give each participant a ranked CSV produced by `src/scoring.py` for a
representative inventory. Include the columns `asset_tier`,
`criticality_score`, `priority_queue`, and `reason`.

Tasks:

1. Identify the first three items they would patch and say why.
2. Find one item on a Critical asset.
3. Explain what "Patch now" means.
4. Say whether the reason column is enough to defend the choice to a manager.
5. Mark any column they do not understand.

Record task success, time, and any misunderstanding. Do not treat the
participant's preferred order as a model error; the purpose is to find unclear
labels and missing context.

## Success criteria

The instrument is usable if:

- at least 4 of 5 participants complete the scoring task without help;
- median time is 2–4 minutes per asset;
- tier agreement is substantial (report the statistic; do not hide a low value);
- every participant can explain the four queue labels;
- no participant believes the tier is a vulnerability severity score.

A low agreement result is a finding. Revise the anchors, record the revision,
and rerun with new participants. Do not tune the model on the usability sample.

## Materials

- `templates/asset_inventory_template.csv`
- `templates/criticality_questionnaire.md`
- one ranked CSV from `results/operational/`
- consent form and plain-language information sheet
- timer and a scoring sheet

## Reporting

Report the number of participants, recruitment context, task success, timing,
agreement statistics, and the exact anchor changes made. Keep identifiable
notes out of the repository and out of the thesis appendix.
