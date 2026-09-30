# Documentation

Every figure the project reports comes from one of these files. They are grouped
by purpose; within `evidence/`, dated files are measurement records written at the
time, and later ones supersede earlier ones where they say so.

## Start here

| Document | What it is |
|---|---|
| [`writeup.md`](writeup.md) | The project as a thesis chapter: problem, architecture, method, measured limits |
| [`principles.md`](principles.md) | The four principles the work settled on |
| [`evidence/srv22-analysis.md`](evidence/srv22-analysis.md) | The real Windows Server 2022 case: timeline, what was found, measured accuracy |
| [`demo-runbook.md`](demo-runbook.md) | How to run and demonstrate the system |

## Design and contracts

| Document | What it is |
|---|---|
| [`contract-decisions.md`](contract-decisions.md) | The binding data contract (CD-001 to CD-022): UTC only, provenance required, identity derived |
| [`details-schema.md`](details-schema.md) | Every `details` key a parser may emit, declared before use |
| [`timezone-assumptions.md`](timezone-assumptions.md) | How each parser establishes UTC |
| [`artifact-attestation-matrix.md`](artifact-attestation-matrix.md) | What each artifact can and cannot prove |
| [`../rules/schema.md`](../rules/schema.md) | The rule language (schema 2.1.0) |
| [`schema-v2-gaps.md`](schema-v2-gaps.md) | What the rule language could not express, and what was added |
| [`technique-coverage-grid.md`](technique-coverage-grid.md) | MITRE ATT&CK coverage: covered, blocked, no discriminator, not observable |
| [`feature-decisions.md`](feature-decisions.md) | Anomaly-layer features, with the leakage measurement behind every exclusion |
| [`per-family-features.md`](per-family-features.md) | Why each artifact family gets only its own features |
| [`open-decisions.md`](open-decisions.md) | Recorded decisions (e.g. OD-01, the ML scope) with their evidence |

## Laboratory and evidence handling

| Document | What it is |
|---|---|
| [`lab-setup.md`](lab-setup.md) | The virtual laboratory: machines, network, accounts, logging |
| [`scenario-design-constraints.md`](scenario-design-constraints.md) | Lessons C-01 to C-06 on designing a clean scenario |
| [`collection-manifest.md`](collection-manifest.md) | The collections and their integrity manifests |
| [`integrity-verification-day4.txt`](integrity-verification-day4.txt) | SHA-256 verification record of the collections |
| [`../groundtruth/`](../groundtruth/) | Scenario ground truth, the pre-registered verification method, collection hashes |

## AI briefing (narration)

| Document | What it is |
|---|---|
| [`narration-setup.md`](narration-setup.md) | Running the local model (Ollama) on this or another machine |
| [`handoff-narration-ui.md`](handoff-narration-ui.md) | The narration contract between the pipeline and the viewer |
| [`evidence/srv22-narration-attempts.md`](evidence/srv22-narration-attempts.md) | Four drafts on the real case, what the checks caught, and the one shown |

## Quality record

| Document | What it is |
|---|---|
| [`defect-log.md`](defect-log.md) | Every defect found (D-001 to D-077), with old and new values |
| [`open-questions.md`](open-questions.md) | Questions the evidence could not settle (cited by the ground truth) |
| [`limitations-week1.md`](limitations-week1.md) | Limitations recorded for the first build (cited by the defect log) |

## Measured evidence (`evidence/`)

**Real case**
- [`srv22-analysis.md`](evidence/srv22-analysis.md), [`srv22-narration-attempts.md`](evidence/srv22-narration-attempts.md)

**Evaluation**
- [`evaluation-2026-09-08.md`](evidence/evaluation-2026-09-08.md), [`evaluation-host2-2026-09-13.md`](evidence/evaluation-host2-2026-09-13.md)
- [`layer-ablation-2026-09-17.md`](evidence/layer-ablation-2026-09-17.md), [`layer-ablation-2026-09-18.md`](evidence/layer-ablation-2026-09-18.md)
- [`rule-coverage-public-corpus-2026-09-14.md`](evidence/rule-coverage-public-corpus-2026-09-14.md), [`atomic-evtx-assessment-2026-09-15.md`](evidence/atomic-evtx-assessment-2026-09-15.md), [`worst-case-guards-2026-09-14.md`](evidence/worst-case-guards-2026-09-14.md)

**Anomaly ranking (ML)**
- [`ml-stage-record-2026-09-13.md`](evidence/ml-stage-record-2026-09-13.md) — the complete record of the ML stage
- [`ml-scope-evidence-2026-09-20.md`](evidence/ml-scope-evidence-2026-09-20.md), [`family-signal-survey-2026-09-18.md`](evidence/family-signal-survey-2026-09-18.md), [`ranking-signals-2026-09-20.md`](evidence/ranking-signals-2026-09-20.md), [`phase-span-2026-09-20.md`](evidence/phase-span-2026-09-20.md)
- OD-01 phases: [1 coverage audit](evidence/od-01-phase1-coverage-audit.md), [2 acceptance](evidence/od-01-phase2-acceptance.md), [3 feature ceiling](evidence/od-01-phase3-feature-ceiling.md), [4 38-family model](evidence/od-01-phase4-flagged-ablation.md), [5 scorer comparison (MODA\*-G vs Isolation Forest)](evidence/od-01-phase5-scorer-comparison.md), [6 relational features](evidence/od-01-phase6-relational-features.md)

**Rules and scoring**
- [`rule-base-rates-2026-09-13.md`](evidence/rule-base-rates-2026-09-13.md), [`rule-base-rates-2026-09-18.md`](evidence/rule-base-rates-2026-09-18.md), [`entity-scoring-d058-2026-09-18.md`](evidence/entity-scoring-d058-2026-09-18.md)
- [`recyclebin-predicate-2026-09-18.md`](evidence/recyclebin-predicate-2026-09-18.md), [`t1059-predicate-2026-09-19.md`](evidence/t1059-predicate-2026-09-19.md)

**Parsers**
- [LNK](evidence/lnk-parser-2026-09-17.md), [NTUSER Explorer keys](evidence/ntuser-explorer-2026-09-17.md), [SAM](evidence/sam-parser-2026-09-17.md), [scheduled tasks](evidence/scheduled-tasks-parser-2026-09-17.md), [SRUM](evidence/srum-parser-2026-09-17.md)
- Prefetch library checks: [`prefetch-spike-cleanb.txt`](evidence/prefetch-spike-cleanb.txt), [`prefetch-spike-s1v2.txt`](evidence/prefetch-spike-s1v2.txt)

**Early run records**
- [`day5-run-2026-08-30.md`](evidence/day5-run-2026-08-30.md), [`gate-run-2026-08-30.txt`](evidence/gate-run-2026-08-30.txt), `run-clean_a.txt`, `run-clean_b.txt`, `run-s1_v2.txt`, [`lab-verification.txt`](evidence/lab-verification.txt), [`accounts-and-volumes.txt`](evidence/accounts-and-volumes.txt)
- Narration samples: `narration-s1v3-promptv2.json`, `narration-s1v3-promptv7.json`
