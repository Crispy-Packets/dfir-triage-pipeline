# NTUSER Explorer keys — measured record, 2026-09-17

Four families added: `userassist`, `recentdocs`, `typedpaths`, `runmru`.
Measured across all five collections through `ingest.collect_events`.

## The result that matters

**On `s1_v2` — the collection whose Security log was cleared — three
independent artefacts converge on one account.**

```
22:57:15  userassist  process_exec  user=janed              runs=28  focus=24s
22:57:15  prefetch    process_exec  user=-
22:57:36  bam         process_exec  user=S-1-5-...-1002
          sam                       RID 1002 = janed
```

The 4688 that would have named the principal is gone. Prefetch records the
execution and no user at all. **UserAssist names the account directly**, BAM
gives a SID whose RID is 1002, and SAM resolves 1002 to `janed` — three
different derivations, one answer, none of them a log.

The UserAssist and Prefetch timestamps agree **to the second**. Two artefacts
written by different subsystems, one clock, asserted in
`test_the_userassist_time_agrees_with_prefetch`.

UserAssist also shows `runs=28` and an earlier entry at 15:15:50 with `runs=3` —
the binary ran repeatedly before the scenario execution, which no other family
in the pipeline reveals.

## Why these keys are structurally different from everything else

**Per-user by construction.** Prefetch and Shimcache are machine-wide and name
no principal. BAM supplies a SID, but only for what its service observed. These
keys sit *inside one user's hive*, so the principal is the hive's owner and
needs no inference at all.

Host 1 has three accounts, and each hive yields only its own owner — a
separation the machine-wide families cannot make. Measured on `clean_b`:

| user | userassist | recentdocs | runmru |
|---|---|---|---|
| Youssef | 55 | 42 | 1 |
| janed | 26 | 6 | 0 |
| admin_local | 19 | 1 | 0 |

## Measured counts

| collection | userassist | recentdocs | typedpaths | runmru | families |
|---|---|---|---|---|---|
| clean_a | 94 | 48 | 0 | 1 | 18 |
| clean_b | 100 | 49 | 0 | 1 | 18 |
| s1_v2 | 124 | 89 | 0 | 2 | 18 |
| clean_c | 45 | 38 | 0 | 1 | 18 |
| s1_v3 | 55 | 46 | 0 | 1 | 18 |

`typedpaths` is **zero everywhere** — the key exists and is empty on both hosts.
That is recorded rather than hidden: nobody typed a path into the Explorer
address bar on these machines. The family is parsed so that a collection where
someone did will produce rows.

## Three encodings, each read from the bytes

**1. Value names are ROT13.** `HRZR_PGYFRFFVBA` is `UEME_CTLSESSION`. Not
obfuscation worth respecting — but a parser that skips the decode emits dense
consonant runs that look like real paths.

**2. The UserAssist record is 72 bytes with the FILETIME at offset 60** — the
*last* field, not the first. Run count is at 4, focus count at 8, focus
milliseconds at 12. A truncated record is rejected rather than partially
decoded: the time is at the end, so a short blob yields a plausible run count
with a timestamp read from whatever bytes happen to be there.

Measured on `clean_b`: **57 records of 72 bytes and 2 of 1612**. The 1612-byte
values are `UEME_CTLSESSION` session aggregates, not programs, and are skipped —
emitting one would invent a binary of that name with a run count in the
hundreds.

**3. RecentDocs values terminate on a null CODE UNIT.** Splitting on a single
null *byte* consumes the low byte of the following UTF-16 unit: `test_doc` came
back as `test_doc�`.

## One file, five families

`registry.py` already reads Run/RunOnce out of NTUSER.DAT, and `find_parser`
returns the **first** parser whose `can_handle` matches. A second parser
registered against the same file would never run.

So `registry.RegistryParser.parse` **delegates** to
`ntuser_explorer.explorer_events` rather than the module registering itself. The
two stay separate files because they answer different questions — what persists
versus what this person did — and neither set of decisions should have to be
read to understand the other. Asserted by `test_the_registry_parser_owns_the_file`.

## A validator change this forced

`userassist` joins `sam` in `MIXED_TIMESTAMP_TYPE`: a record with a real
FILETIME is `last_run` (measured 85 of 124 on `s1_v2`), one without falls back
to the key write and is `presence`.

But the existing guard only knew the `sam` spelling — `details.last_logon
not_equals never`. UserAssist's presence records carry **no such field**, so
that guard would have blocked every windowed `userassist` rule unconditionally,
with no way to satisfy it.

`_excludes_never_used` now accepts the general form, `timestamp_type equals
last_run`, alongside the two `sam`-specific spellings. A guard nothing can
satisfy is not a safety property; it is a family that silently cannot be used.

## What these keys do not attest

**UserAssist counts GUI launches only.** A program started from a command line,
a script, or a service leaves no entry — so a zero count is *not* evidence that
something did not run. This matters directly here: `invoice_scan.exe` appears
because it was double-clicked, and a scenario that ran it from `cmd.exe` would
show nothing.

**RecentDocs records that a name was opened through the shell**, not that the
file exists or ever did. Entry 15 on `clean_b` decodes to a URL query string
rather than a filename, which is why the recorded string is reported without
asserting it is a path.

**All three MRU families are `presence`.** The timestamp is the containing key's
last write, shared by every sibling value — D-027 exactly — which is why
`value_count_in_key` is emitted alongside.

## Gate at this commit

    ruff              All checks passed!
    pytest            589 passed, 20 skipped
    validate_rules    schema 2.0.0   rules 14   errors 0   warnings 0

    families          18 present in any collection (was 15)

`typedpaths` is parsed and registered but appears in NO collection, because the
key is empty on both hosts. Four families were added; 18 rather than 19 are
observed. The distinction is deliberate -- a family that parses and finds
nothing is not the same as one that does not exist.
