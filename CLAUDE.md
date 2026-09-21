# dfir-triage-pipeline

## Gate

    python -m ruff check .            ->  All checks passed!
    python -m pytest -q               ->  958 passed, 21 skipped
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
algorithm is selectable behind a flag; **Isolation Forest is the default and
must stay the default** (the user said so twice). Unset or `isolation_forest`
is byte-identical to the committed pipeline — proven: the flag-unset ablation
reproduces 40/443 with the same top-10 order. `moda_g` (MODA*-G, vendored under
`_vendor/`) was measured and **improved the attack rank to 14/443** with the
clean-host rate in band (0.048) and entity count unchanged (443) — the first
lever in OD-01 to move the rank. `dif` is wired but not runnable here (deepod's
DIF version pins torch<1.13.1, unavailable for py3.11). Evidence:
`docs/evidence/od-01-phase5-scorer-comparison.md`. **Do not switch the default
to an alternative** without the user's decision; the flag makes adoption one env
var. **Removal procedure** (the user asked to keep it): delete
`dfir_triage_pipeline/_scorers_dif.py`, `_scorers_moda.py`, `_vendor/`, and the
`"dif"`/`"moda_g"` lines in `anomaly._SCORER_REGISTRY` — the default path never
imports them, so removal cannot affect Isolation Forest. `run.json` records
which scorer produced its percentiles (`anomalies.scorer`, run_json v1.4.0).

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
