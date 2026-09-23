# dfir-triage-pipeline

## Gate

    python -m ruff check .            ->  All checks passed!
    python -m pytest -q               ->  991 passed, 21 skipped
    python rules\validate_rules.py    ->  schema 2.1.0  rules 24  errors 0  warnings 0

The 16 skips are collection-backed integration tests, active only when
`DFIR_TEST_COLLECTION` points at a collection:

    $env:DFIR_TEST_COLLECTION = "%USERPROFILE%\dfir-evidence\collection_clean_b"
    python -m pytest -q

Counts differ per collection, because some assertions are about one collection
only. All three must be green. The per-collection figures were last measured
before the Week 3 rule and engine tests landed and are therefore NOT quoted
here: 181/10, 181/10 and 186/5 were correct at 78c9426 and are now certainly
low by the number of tests added since. They are left blank rather than
carried forward wrong -- an unmeasured figure is honest, a stale one is not.

The three-line gate above was measured 2026-09-01 on Python 3.11, after
merging the Week 3 correlation engine with the parser and feature work.

**The pytest figure is no longer maintained by hand.** The suite asserts that
`passed + skipped` equals what it collected, so adding a test without touching
this line fails the gate and names the correct number. That check exists because
this line went stale three times in two days, each time in a commit that added
tests and set the figure from the previous measurement. An instruction someone
has to remember is a defect waiting for a busy afternoon.

## Layout

Evidence lives **outside this repository** at `%USERPROFILE%\dfir-evidence`
(CD-016). Nothing under it is tracked, ignored, or reachable by any git
operation -- `git clean -xdf` removes ignored files, so an ignore rule would
protect the repo from the evidence, not the evidence from the repo.

    HOST 1 -- a collaborator's machine, collected August 2026
    collection_clean_a   892 files   ambient-noise control
    collection_clean_b   916 files   reference baseline (CD-014)
    collection_s1_v2     817 files   scenario: HTTP delivery, exec, persist, log clear

    HOST 2 -- collected September 2026 because host 1's browser family held 11
    rows and could not be modelled, so the download was never scored
    collection_clean_c   736 files   training baseline; 62 downloads, 470 4104 rows
    collection_s1_v3     799 files   scenario, same four steps

**Train and score within one host.** A model fitted on host 1 and scored against
host 2 flags nearly every row, because two machines differ in software, users
and hostname -- the same failure as the 27.4% artifact-mix result below.

## Anomaly layer

`docs/feature-decisions.md` records every excluded field with the measurement
that disqualified it. Two things there are easy to undo by accident:

- **`hour_of_day` and `is_weekend` are excluded**, though the plan proposed
  them as features. Hours 21-23 hold 33% of `s1_v2` and about 1% of the
  baselines, because the operator ran the scenario in the evening.
- **One model per `source_artifact`.** A single model over mixed families
  scores on artifact identity: `run_count` is non-zero only for Prefetch, so a
  mixed forest splits on record type. Measured, that put `s1_v2` at 27.4%
  outliers against `clean_a`'s 5.5%, almost entirely from artifact mix.

The B-12 acceptance test is asserted in `tests/test_features.py`: a model fitted
on `clean_b` must not flag `clean_a` as broadly anomalous. If that fails, no
`s1_v2` result means anything.

- **`features.FAMILY_FEATURES` restricts each family to the columns its records
  can populate.** A download has never run; a Prefetch record has no MIME type.
  A constant column is not ignored -- the forest picks features at random, so it
  spends splits partitioning nothing. Argued in `docs/per-family-features.md`,
  committed before the implementation.

**The anomaly layer ranks; it does not detect.** Nothing is flagged as an
outlier in either host's scenario.

**ML scope is DECIDED (OD-01, 2026-09-20): report the measured answer.**
`FAMILY_FEATURES` stays at 7 and is not extended to the 31 further families.
The reasoning is in `docs/open-decisions.md`; the evidence is in
`docs/evidence/ml-scope-evidence-2026-09-20.md` and
`ml-stage-record-2026-09-13.md`.

The short form: the anomaly layer ranks rather than detects, at a ~5%
false-positive floor, and no family places the attack entity in its own top
decile. Extending to families the attack does not touch cannot improve its
rank — it enlarges the denominator, which the ablation already showed makes
the percentile worse. The deliverable is that measured negative about
method-corpus fit, not a larger feature layer. What would reopen it is a
corpus with enough labelled intrusion entities to compute lift instead of a
single rank, which is a collection problem rather than a feature one.

**The anomaly layer is scoped to the original 7 families.** `FAMILY_FEATURES`
declares feature sets for `amcache`, `browser`, `evtx.powershell`,
`evtx.security`, `evtx.system`, `prefetch` and `registry` and for nothing
else. An undeclared family is skipped with that reason recorded, never
defaulted to the full feature vocabulary (D-063).

**The 38-family extension was built, measured, and left OFF by default**
(OD-01 Phase 4, `docs/evidence/od-01-phase4-flagged-ablation.md`). Setting
`DFIR_EXTENDED_FAMILIES=1` opts into `features._EXTENDED_FAMILY_FEATURES`, which
declares the only four undeclared families that carry any behavioural key at
all. **Of the 31 undeclared families above the row floor, 27 carry no key a
forest column could be computed from** — a column over them would be constant.
Of the four that do, the leakage test drops the temporal columns (they encode
collection identity), and the distinct-vector guard then rejects three of the
four; the one that fits (`evtx.bits`) carries no attack row. Measured, flag ON
moved the attack rank from 79/443 to 81/443 — worse, no gain (**both figures are
pre-D-074**, on the leaking `_SHARED`; the ON side was not re-run after the
D-074 fix). The flag stays off; it exists so the negative is measured rather
than asserted. Do not enable it in the shipped pipeline.

**The ablation at the current state is a BASELINE, not a ranking result**
(D-062). It measures where the layer stands before any ML work, which is the
only honest starting point for deciding whether that work is worth doing:

    2026-09-13,  7 declared, 7 parsed     host 2:  40 of 525  (top 7.6%)
    2026-09-18,  7 declared, 38 parsed    host 2:  81 of 443  (top 18.3%)
                                          host 1: 298 of 1189 (top 25.1%)

The percentile fell because the entity denominator grew with the event pool
while the model stayed fitted on seven families -- dilution, not damage. A
rank figure quoted without its pipeline version is the defect; see D-062
before using any of these. **All of them are superseded when D-058 lands**,
because the rules-side scoring they sit beside is what D-058 changes.

**Post-D-074 (2026-09-21), the current honest ML-only rank is 40/443 (top 9.0%)
on s1_v3**, up from 79/443 before the fix. Removing the two per-hour density
columns from `_SHARED` (they ranked on collection-identity timing) did not cost
rank — it recovered it, because those columns were demoting the quiet attack
entity below a crowd of collection-timing outliers. Fitted set unchanged
(`amcache`, `evtx.powershell`, `prefetch`). This is the figure to quote; the
79/443 above it is pre-D-074.

**Pluggable scorers (OD-01 Phase 5, `DFIR_ANOMALY_SCORER`).** The anomaly
algorithm is selectable behind a flag. **The default is `moda_g` (MODA*-G) as of
2026-09-22 — the user's decision** (this reverses the earlier "Isolation Forest
stays the default" instruction; the reversal is deliberate, not drift). MODA*-G
ranked the attack **14/443** vs Isolation Forest's 40/443 on s1_v3, with the
clean-host rate in band (0.048) and entity count unchanged (443) — the first and
only lever in OD-01 to move the rank, and it is understood (§9: amcache's
MCD+Peña engines saturate on the payload). It is vendored under `_vendor/`
(MIT). **Isolation Forest stays fully available and byte-exact** — one env var:
`DFIR_ANOMALY_SCORER=isolation_forest` reproduces the old committed pipeline
(40/443, same top-10), proven by the inertness test. `dif` is wired but not
runnable here (deepod's DIF version pins torch<1.13.1, unavailable for py3.11).
`ensemble_if_moda` and MODA's categorical engine (`DFIR_MODA_CATEGORICAL`) were
measured and both do WORSE than MODA numeric-only (ensemble 17/443; SDC 60/443).
Merging clean_a+b+c as one baseline is host-mixing and NOT valid (§11: MODA's
clean ceiling blows to 0.129) — train within one host. Evidence:
`docs/evidence/od-01-phase5-scorer-comparison.md` (§6–11).

**COST OF THE MODA DEFAULT: it is markedly slower than IF.** MODA*-G is
transductive (fit stores train; score stacks train+query and runs MCD/Gower kNN
per family), so every model fit is minutes on the full corpus, not seconds. The
test suite is correspondingly slower now that the unset default is MODA — set
`DFIR_ANOMALY_SCORER=isolation_forest` when running the gate for speed, or when a
caller (e.g. an interactive UI) needs low latency. Revert the default if a
clean-host ceiling ever leaves the ~0.05 band or the entity count moves off 443.

**Removal procedure** (the user asked to keep the rollback option): set
`DFIR_ANOMALY_SCORER=isolation_forest` to fall back instantly, or to remove the
alternatives entirely, first change `anomaly.DEFAULT_SCORER` back to
`"isolation_forest"`, then delete `dfir_triage_pipeline/_scorers_dif.py`,
`_scorers_moda.py`, `_scorers_ensemble.py`, `_vendor/`, and the `"dif"`/
`"moda_g"`/`"ensemble_if_moda"` lines in `anomaly._SCORER_REGISTRY`. `run.json`
records which scorer produced its percentiles (`anomalies.scorer`, run_json
v1.4.0) — UI consumers should render it as ranking provenance.

**LLM narration (OD-01 Phase 7, `DFIR_NARRATION`, OFF by default).** An optional,
detachable prose summary of a run, in `core/narration.py`. **Unset the flag and
nothing changes** — no `narration` key in run.json, no Ollama dependency, the
gate stays fast and model-free. Enable with a spec string
`DFIR_NARRATION=backend:model`; only `ollama` is registered (`null` is the
default no-op), and an unknown backend raises. Ollama runs on ANOTHER machine —
point `DFIR_NARRATION_ENDPOINT` at it (default `http://localhost:11434`); the
code only makes an HTTP call, it never installs or runs Ollama here. Example:
`DFIR_NARRATION=ollama:qwen2.5:7b DFIR_NARRATION_ENDPOINT=http://192.168.1.50:11434`.
The narration is **non-authoritative** (`is_verdict` false), written into
run.json BEFORE the manifest hash (so it is covered), and rendered in report.html
only when accepted, labelled AI-generated and set apart from the verdict. It is
**validated, not trusted**: `core/citations.py` (decoupled from any model) checks
every rule id, executable and salient number the prose cites against the fact
slice the model was shown; any miss → `status: "rejected"` and the prose is kept
under `narration.rejected` (audit only, never rendered). Validator scope is
honest — it catches fabricated ids/exes/numbers, not arbitrary free text; the
prompt constrains the model to name entities only by executable.
**The fact slice is VERDICT-FIRST, and that is load-bearing.** The first live run
(qwen2.5:7b, prompt v1) fabricated nothing and still narrated the wrong panel: it
described the anomaly ranking — which measurably leads with benign OS binaries —
and omitted the 99/critical `invoice_scan.exe` the rules detected. Two fixes, both
kept: `_facts()` now builds `verdict_entities` from `doc["entities"]` (severity,
score, rule_ids, worst first) and renames the ranking key to
`prioritisation_ranking_not_detections`; and the validator gained a
**completeness** check — every `critical` verdict entity (or the top-scoring one
if none is critical) must appear in the prose or it is rejected with
`missing:<entity>`. `describes_ranking_as_detection` is an advisory flag for
prose that credits the anomaly layer with detecting. Prompt v2. The lesson is
general: a citation validator measures faithfulness to the facts it was given,
never whether those were the right facts — precision and emphasis are separate
axes and each needs its own check.
**Measured limit, left in deliberately.** Prompt v2 passes every check and still
contains a false claim: it says `invoice_scan.exe` is "ranked first in the
moda_g prioritisation ranking" — it is not, and it does not appear in the
ranking slice at all (`dllhost.exe` leads it). The model inferred that the
critical verdict must also top the ranking, which is exactly the conflation the
two-panel split exists to prevent and which OD-01 measured to be false. Nothing
is fabricated, nothing required is omitted, attribution is correct — it is a
false RELATIONAL claim between facts each supplied correctly, a third failure
mode a closed-vocabulary validator cannot structurally reach. Pinned by
`test_a_false_relational_claim_still_validates`; **do not "fix" it** — it is the
honest boundary and the reason narration stays `is_verdict: false`, labelled,
and separated from the verdict panel. Reference output:
`docs/evidence/narration-s1v3-promptv2.json`. Determinism:
temperature 0 + fixed seed + recorded model digest reproduce on the same
host/model (not bit-identical across machines). A backend failure records
`status: "error"`, never aborts the run. run_json → v1.5.0. **The module IS the
model-comparison harness**: run the pipeline with each candidate tag and read
`narration.validation.unresolvable` / `missing_mentions` / `mentions_scorer` from
each run.json — zero unresolvable AND the verdict named wins; no separate
benchmark script. **Removal**: delete
`core/narration.py`, `core/citations.py`, the `__main__` hook, `_narration_panel`
in report_html, and revert RUN_JSON_VERSION; the default path never imports any
of it.

**Relational / cross-family features were measured and NOT shipped (OD-01
Phase 6, 2026-09-22, `docs/evidence/od-01-phase6-relational-features.md`).** The
last untried feature family -- `family_count`, `activity_span_hours`,
`download_precedes_exec` per entity over all 38 families -- ranks the payload
1-2/443, above any single artifact family. But the rank is carried entirely by
`download_precedes_exec`, which selects exactly the 3-entity R-CORR download->exec
set, and the payload lands in a 3-way tie with two benign installers (npp, vlc).
The ML re-derives the rule rather than seeing the chain independently, so it is
not wired in and gets no flag -- adding it would feed the verdict panel's own
output back into triage ranking. `phase_span` was excluded up front as rule
output, not a raw-event feature. This is why the lever was deferred three times,
now measured. No code change; the finding is the negative.

**No family places the attack entity in its own top decile** -- `bam` 33%,
`prefetch` 41%, `amcache` 89%. The combined figure of 1/894 is the RULES layer
placing it first with the anomaly ranking appended behind it. Detection comes
from the deterministic rules; the anomaly layer contributes triage ranking and
a measured ~5% false-positive floor on clean hosts.

**There is no accuracy figure and none can be computed** -- 4 attack events in
2,304 is not a labelled test set, and labelling by collection would measure
collection identity (`hour_of_day` scores 86.0% that way). With one ground-truth
entity every ranking metric reduces to its position, so the rank is reported
rather than lift. Full progression in
`docs/evidence/ml-stage-record-2026-09-13.md`.

## Contracts

`docs/contract-decisions.md` is binding. Read it before changing `model.py`,
`timeline.py` or `parsers/base.py`. `docs/details-schema.md` governs `details`
keys: **a key must be declared there before any parser emits it.**

`docs/defect-log.md` carries the D-numbers. Record both the old and new value
whenever a change alters the `event_id` hash.

## Toolchain rules that reject otherwise-correct code

- `UP017` rejects `UTC = timezone.utc`. Use `from datetime import UTC`.
- `B017` rejects `pytest.raises(Exception)`. Name the type.
- `I001` rejects the parser registration imports as separate lines with only
  `# noqa: E402,F401`. Add `,I001` to the first (D-014).

## Prefetch specifics, established by execution

- `windowsprefetch==4.0.3` returns run times as **naive strings** that mean
  **UTC** (D-013, confirmed against ground truth and against the raw FILETIME
  bytes). Attach UTC; never `astimezone()` a naive value.
- The volume serial attribute is `volSerialNumber`, **not** `volumeSerialNumber`.
- The library misreads `runCount` at offset `0xD0`; the parser reads `0xC8`
  (D-023). Verified on all 835 collected `.pf` files.
- `Op-*.pf` are SysMain files that parse without raising and fabricate a binary
  name. Excluded by basename (D-025).
- Five `.pf` files are zero-filled and yield no records rather than raising
  (D-024).
