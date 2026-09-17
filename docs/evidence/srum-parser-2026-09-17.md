# SRUM parser — measured record, 2026-09-17

Fourteenth artifact family. Measured across all five collections through
`ingest.collect_events`.

## What SRUM adds that nothing else in the pipeline has

**Transfer volume.** Prefetch says a binary ran; BAM says which SID ran it;
neither says a program sent 90 MB somewhere. For an exfiltration question SRUM
is the record, and it is the only family here that carries one.

## Measured row counts

| collection | network_usage | resource_usage | total | unattributed |
|---|---|---|---|---|
| clean_a | 800 | 5,379 | 6,179 | 41 |
| clean_b | 800 | 5,379 | 6,179 | 41 |
| s1_v2 | 1,065 | 7,288 | 8,353 | 54 |
| clean_c | 279 | 785 | 1,064 | 26 |
| s1_v3 | 334 | 1,398 | 1,732 | 31 |

98%+ of rows carry a resolved SID (1,701/1,732 on `s1_v3`). Families per
collection: **14**.

## Three decode facts, each established from the bytes

Every one would have produced well-formed, plausible, wrong output, and none
would have raised.

**1. `IdType=3` is the SID; 0, 1 and 2 are all application identities.** This
is the opposite of the numbering in most format write-ups. `IdType=3` holds
`\x01\x01\x00\x00\x00\x00\x00\x05\x14\x00\x00\x00` (`S-1-5-20`); `IdType=0`
holds `!!WmiPrvSE.exe!2019/10/16:23:45:21!860a3!`. Taking the conventional
numbering on faith attributes **every row to the wrong party**.

The application identity arrives in three shapes — a device path
(`\Device\HarddiskVolume1\Windows\System32\dwm.exe`), a bare service name
(`Dnscache`), and an AppX package identity
(`Microsoft.Windows.Search_1.14.9.19041_…`). All three are kept **as recorded**
(CD-010): which shape SRUM used is itself information about how the program was
launched.

**2. `TimeStamp` is an OLE automation date whose float64 bits arrive as an
int.** `dissect` declares the column `JET_coltyp.DateTime` and returns
`4676592689485971456`. That is not a scale factor from a real time — the *bits*
must be reinterpreted as a float64: 46274.1875 days from 1899-12-30 =
`2026-09-09T04:30Z`. Treating it as ticks places the event roughly **148 million
years** out, and nothing raises. Values outside 1995–2100 are rejected rather
than clamped.

**3. `AppId=1` resolves under no IdType at all.** It is SRUM's own sentinel for
traffic it could not attribute — 31 of 334 network rows on `s1_v3`. Those rows
are emitted as `<unattributed>` rather than dropped (the bytes were still moved)
and rather than given a fabricated `<id 1>` name, which would put an invented
identifier into a field a rule may join on. **An unresolvable id other than 1
yields no event.**

## The scenario binary is absent from SRUM on BOTH hosts, for two different reasons

This is the most important measured result here, and the first explanation I
reached for was wrong.

**`s1_v3` — collection timing.** SRUM's last flush is **11:48:00**; the payload
ran at **11:50:09**. Zero rows exist at or after the execution *for any
program*. The horizon is 2.2 minutes short, and absence is a timing fact with a
measurable boundary.

**`s1_v2` — refutes that as a general claim.** SRUM flushed **325 rows after**
the 22:57:15 execution there, and `invoice_scan.exe` is still absent. So flush
timing explains one host only.

What SRUM *did* record in that 30-minute window: 97 distinct applications, and
it does name short-lived user binaries elsewhere on that host — 49 rows under
`\Users\`, including installer processes in `AppData\Local\Temp`. So the barrier
is not "SRUM ignores user programs".

**The distinguishing property is duration.** Every program SRUM names ran long
enough to cross a sampling interval. `invoice_scan.exe` is a small binary that
exits immediately. That is a **structural limit of the artifact** — SRUM samples
running processes rather than recording process starts — and it belongs in the
attestation matrix as a "cannot attest" clause, not in a collection note.

This is the D-028 shape: an artefact that could have corroborated, and on this
evidence did not. Both reasons are recorded because they are different, and a
future collection would hit one or the other.

## Effect on the layer ablation, measured

| layer | entities | attack rank | in top 10 |
|---|---|---|---|
| rules only | 5 | **1/5** | yes |
| ML only | 974 | 58/974 | no |
| both | 976 | **1/976** | yes |

Against the pre-SRUM figures (525 / 37 / 527): the ML-only rank moved from 37 to
58 in absolute position while **improving as a percentile, 7.0% → 6.0%**,
because SRUM added 449 entities to the corpus. The headline claim is unchanged:
rules rank the attack first, and the combined layer ranks it first of 976.

**Rule firings are bit-identical with and without SRUM** on all five
collections (64/72/19/6/6). No rule selects `srum` and none joined across into
it — verified by running the engine twice per collection, once with the family
filtered out.

## A known dilution, stated rather than fixed

`srum` has no `FAMILY_FEATURES` entry, so it falls back to all 21 features.
`docs/per-family-features.md` establishes that a constant column is
*measurably worse* than an absent one — the forest picks features at random and
spends splits partitioning nothing. SRUM rows populate neither the download
columns, nor the script columns, nor `run_count`.

This is not corrected here because the correction must be **measured, not
assumed** — the same rule that caught the base-rate error. SRUM is now the
largest family in the corpus, so a per-family restriction is worth doing
properly against the ablation harness rather than by inspection.

## Dependency

`dissect.esedb==3.18`, now pinned in `pyproject.toml` and imported lazily inside
the parser. Pure Python matters here: the alternatives bind to `libesedb`, which
does not build on Windows without a toolchain the examiner may not have.

## Gate at this commit

    ruff              All checks passed!
    pytest            514 passed, 20 skipped
    validate_rules    schema 2.0.0   rules 14   errors 0   warnings 0

    families          14 (was 13)
