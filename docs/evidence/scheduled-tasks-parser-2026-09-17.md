# Scheduled tasks parser — measured record, 2026-09-17

Fifteenth artifact family. Measured across all five collections through
`ingest.collect_events`.

## Why this family matters more than services did

4698 (task created) belongs to the **Object Access** audit subcategory, which is
**off by default**. Measured across all five collections: **zero 4698 events**.

That makes tasks a stronger case than services. A service has System 7045 *and*
the registry key — two records, one corroborating the other. A task has only the
definition on disk. There is no enabled-by-default event to fall back on, so
without this parser a scheduled-task persistence mechanism is invisible to the
pipeline entirely.

## Measured counts

| collection | files | events | exec | com_handler | hidden | disabled |
|---|---|---|---|---|---|---|
| clean_a | 210 | 210 | 96 | 113 | 56 | 36 |
| clean_b | 210 | 210 | 96 | 113 | 56 | 35 |
| s1_v2 | 210 | 210 | 97 | 112 | 56 | 37 |
| clean_c | 205 | 205 | 93 | 111 | 56 | 33 |
| s1_v3 | 220 | **222** | 106 | 115 | 57 | 35 |

Families per collection: **15**. Zero parse failures.

`s1_v3` yields 222 events from 220 files because `MareBackup` declares **three
`Exec` actions**, each emitted separately — two actions are two things that
would run, and collapsing them would hide one.

## `ComHandler` outnumbers `Exec` on every collection

**115 to 106 on `s1_v3`**, and the same ordering on all five. A task action is
either a command line or a **COM class id** with no command line anywhere in the
file. A parser reading only `<Exec><Command>` drops more than half the tasks,
silently — and drops precisely the fileless shape, where persistence is a CLSID
pointing at a registered object rather than a path on disk.

Both are emitted, distinguished by `action_type`. The CLSID is reported as
recorded; resolving it to a DLL needs the SOFTWARE hive, which this parser does
not read.

## Two bugs, one caught by the contract and one by counting first

**D-045 — four tasks raised on a UTC offset.** `SystemSoundsService` carries
`2005-06-23T13:48:00-08:00`. Measured across four collections: **86 naive, 4
offset-bearing, none with `Z`**.

The two shapes need *opposite* handling. A naive value is the subject's wall
clock with no zone stated → attach UTC (D-013), because converting applies the
analyst's zone to the subject's. An offset-bearing value *does* state its zone →
convert, which preserves the instant; attaching UTC would move the event eight
hours with nothing raising.

CD-019's validation rejected the non-zero offset outright, so the parser failed
loudly on one file per collection instead of emitting events an hour off. **The
contract caught what the parser did not.** 221 events / 1 failure → 222 / 0.

**D-046 — `can_handle` dropped five real tasks.** The first version rejected any
name containing a dot, since task definitions have no extension. Five of 220
names contain one, four of them *beginning* with a dot (`.NET Framework NGEN
v4.0.30319`).

This one would never have surfaced as an error: a rejected file counts as
**skipped**, not failed. The run would have reported 215 handled with no
warning, and 215 is a plausible number against a directory nobody counted.
Caught by counting the corpus before trusting the filter.

## The URI needed normalising

`<RegistrationInfo><URI>` is inconsistent about its leading backslash **within
one collection** — three of the first four files carry it, one does not. Left
raw, one task reached by two spellings becomes two entities and a rule joining
on identity matches neither. Normalised to a single leading separator, with a
fallback to the path under `Tasks\` when the element is missing.

## What this family does not claim

`timestamp_type=presence`. The definition says a task **exists** and what it
**would** run. It does not say the task ever ran — `LastRunTime` lives in the
Task Scheduler's own log and in `SOFTWARE\...\Schedule\TaskCache`, neither of
which is read here. Same limit as the registry Run keys (D-027).

Only **26 of 222** tasks on `s1_v3` carry a registration date at all, which is
why the date is a detail rather than the event timestamp; the rest carry the
1601 sentinel the other presence-typed families use.

`task_enabled` and `task_hidden` are written **only when the XML states them**.
Both default to true when the element is absent, and writing the default would
assert a value the file does not carry.

## No finding on this corpus, and that is the expected result

No rule selects `scheduled_task` yet. The seven `exec` actions in user-writable
locations on `s1_v3` are all Windows Defender platform binaries under
`ProgramData` and OneDrive updaters under `AppData` — legitimate, and structurally
identical to what a malicious task would look like. That is the discriminator
problem this pipeline has hit before (D-040), and a rule for this family needs
the same treatment: a shape predicate, not a name list.

Scenario 1 establishes persistence via a **Run key**, not a task, so there is no
attacker-created task in any collection to detect. The parser exists for
coverage of a mechanism the corpus does not exercise — which is the point of the
attestation-derived approach rather than the corpus-derived one.

## Gate at this commit

    ruff              All checks passed!
    pytest            551 passed, 20 skipped
    validate_rules    schema 2.0.0   rules 14   errors 0   warnings 0

    families          15 (was 14)
