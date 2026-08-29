# dfir-triage-pipeline

## Gate

    python -m ruff check .            ->  All checks passed!
    python -m pytest -q               ->  124 passed, 15 skipped
    python rules\validate_rules.py    ->  schema 1.2.0  rules 6  errors 0  warnings 0

The 15 skips are collection-backed integration tests, active only when
`DFIR_TEST_COLLECTION` points at a collection:

    $env:DFIR_TEST_COLLECTION = "%USERPROFILE%\dfir-evidence\collection_clean_b"
    python -m pytest -q   ->  130 passed, 9 skipped

Counts differ per collection, because some assertions are about one collection
only. All three must be green:

    collection_clean_a  ->  130 passed,  9 skipped
    collection_clean_b  ->  130 passed,  9 skipped
    collection_s1_v2    ->  134 passed,  5 skipped

Last measured 2026-08-30 on Python 3.11. When these numbers change, change them
here in the same commit -- a gate line that no longer matches the run it
describes is worse than no gate line.

## Layout

Evidence lives **outside this repository** at `%USERPROFILE%\dfir-evidence`
(CD-016). Nothing under it is tracked, ignored, or reachable by any git
operation -- `git clean -xdf` removes ignored files, so an ignore rule would
protect the repo from the evidence, not the evidence from the repo.

    collection_clean_a   892 files   ambient-noise control
    collection_clean_b   916 files   reference baseline (CD-014)
    collection_s1_v2     817 files   scenario: HTTP delivery, exec, persist, log clear

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
