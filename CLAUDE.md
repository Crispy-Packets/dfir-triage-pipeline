# dfir-triage-pipeline

## Gate

    python -m ruff check .            ->  All checks passed!
    python -m pytest -q               ->  246 passed, 16 skipped
    python rules\validate_rules.py    ->  schema 1.4.0  rules 10  errors 0  warnings 0

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

The three-line gate above was measured 2026-08-30 on Python 3.11, at 56b21d6
plus the schema 1.4.0 rule changes. When these numbers change, change them here
in the same commit -- a gate line that no longer matches the run it describes is
worse than no gate line.

## Layout

Evidence lives **outside this repository** at `%USERPROFILE%\dfir-evidence`
(CD-016). Nothing under it is tracked, ignored, or reachable by any git
operation -- `git clean -xdf` removes ignored files, so an ignore rule would
protect the repo from the evidence, not the evidence from the repo.

    collection_clean_a   892 files   ambient-noise control
    collection_clean_b   916 files   reference baseline (CD-014)
    collection_s1_v2     817 files   scenario: HTTP delivery, exec, persist, log clear

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

**The anomaly layer does not detect Scenario 1**, and that is the recorded
result, not a defect. The execution ranks 52nd percentile among Prefetch rows
and the log clear 24th among Security rows. Detection comes from the
deterministic rules; the anomaly layer contributes triage ranking and a measured
~5% false-positive floor on clean hosts.

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
