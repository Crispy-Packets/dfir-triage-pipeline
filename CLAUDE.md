# dfir-triage-pipeline

## Gate

    python -m ruff check .            ->  All checks passed!
    python -m pytest -q               ->  916 passed, 21 skipped
    python rules\validate_rules.py    ->  schema 2.0.0  rules 15  errors 0  warnings 0

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

**The anomaly layer is scoped to the original 7 families.** `FAMILY_FEATURES`
declares feature sets for `amcache`, `browser`, `evtx.powershell`,
`evtx.security`, `evtx.system`, `prefetch` and `registry` and for nothing
else. **Extending it to the 31 families added by the parser work is a separate
workstream and has not been started.** An undeclared family is skipped with
that reason recorded, never defaulted to the full feature vocabulary (D-063).

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
