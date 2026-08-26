# Scenario 1 — verification sheet

Verdicts follow the closed vocabulary fixed in `groundtruth/verification-method.md`
before any comparison was run: `MATCHED`, `DESTROYED`, `NOT-EVALUABLE`,
`NOT-PARSED`, `MISSED`. `MISSED` is the only category that denotes a pipeline
failure.

**Status: partial.** The pipeline has not yet been run over the three
collections, so no row can carry `MATCHED` — that verdict requires a produced
timeline row within tolerance. Rows whose verdict does not depend on the
pipeline are settled below and marked with the evidence that settles them.
Rows awaiting the run are marked `PENDING RUN` in the Evidence column.

---

## 1. Ground-truth rows

| # | GT step | Expected artefact | Verdict | Evidence |
|---|---|---|---|---|
| 1 | download | Edge `History` | `NOT-PARSED` | Present, 229,376 bytes, and **read by hand 2026-08-26**: 24 tables, 11 `downloads` rows, 30 `urls`, 35 `visits`. The scenario download is `downloads` id 13, 4,608 bytes, 2026-08-23T22:20:06.710763Z. Browser family is Week 2 |
| 2 | download | `Zone.Identifier` | `NOT-EVALUABLE` | Verified live at `ZoneId=3`; `C\Users\janed\Downloads` is outside the KapeTriage collection scope. OQ-005 |
| 3 | download | `$MFT` | `NOT-PARSED` | Present in all three collections. MFT parser is Week 2. No longer needed to settle OQ-001, which closed from Edge and Prefetch; still useful as a third measurement, and see the OQ-005 note about three same-named files in `Downloads` |
| 4 | execute | Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf` | `NOT-PARSED` | **Present and read by hand, 2026-08-24 collection.** 7,145 bytes, format version 30, run count **1**, last run **2026-08-23T22:57:15.832787Z**. Referenced path resolves to `C:\Users\janed\Downloads\invoice_scan.exe`. Prefetch parser does not exist in the merged tree |
| 5 | execute | EID 4688 for `invoice_scan.exe` | `DESTROYED` | **Confirmed by direct read 2026-08-26.** `collection_s1_v2`'s Security log holds 584 records, EventRecordID 28,201–28,784, contiguous, no gaps. Its **first** record is the EID 1102 itself at 23:05:06.682356Z. No record predates the clear, so no 4688 for the 22:57:15 execution survives |
| 6 | execute | Marker file `invoice_scan_marker.txt` | `NOT-PARSED` | **Confirmed present in evidence indirectly**: listed among the referenced files of the Prefetch record in row 4, as `...\USERS\JANED\APPDATA\LOCAL\INVOICE_SCAN_MARKER.TXT`. The file itself is in `NTUSER`-adjacent user space; registry/user-artefact parsing is Week 2 |
| 7 | execute | Amcache, UserAssist | `NOT-PARSED` | Amcache present; UserAssist inside `NTUSER.DAT`. Registry parser is Week 2 (OQ-002) |
| 8 | persist | `NTUSER.DAT` Run key | `NOT-PARSED` | Hive present in `collection_s1_v2`. Registry parser is Week 2 (OQ-002) |
| 9 | logclear | EID 1102 | `PENDING RUN` | Artefact present and previously counted 1 of 1 at EventRecordID 28,201. Becomes `MATCHED` when the pipeline produces the row within tolerance |

**`MISSED` count: 0.** No row is present-parsed-and-absent-from-the-timeline.
Row 9 is the only row whose verdict can change when the pipeline runs, and it
can only change from `PENDING RUN` to `MATCHED` or to `MISSED`.

## 2. Execution timeline, from collected evidence

Reconstructed for the incident window without a parser. Every value is cited.

| Time (UTC) | Event | Source |
|---|---|---|
| 22:38:27.274684 | `Get-Contetn ... -Stream Zone.Identifier` (typo) | 4104, EventRecordID 1597 |
| 22:38:44.710217 | `Get-Content C:\Users\janed\Downloads\invoice_scan.exe -Stream Zone.Identifier` | 4104, EventRecordID 1602 |
| **22:20:06.710763** | **download starts** | **Edge `History`, `downloads` id 13, `start_time`** |
| 22:20:07.324360 | download completes, 4,608 bytes, `state` 1 | Edge `History`, `downloads` id 13 |
| ~~22:45:32.274977~~ | download, as claimed by the operator log — **superseded, late by 25m 25.6s** | `groundtruth/Scenario1.md`, annotated |
| 22:46:06 – 22:47:59 | Defender scheduled Quick Scan, no detections | Defender/Operational 1000, 1001 |
| **22:57:15.832787** | **`invoice_scan.exe` executed, run count 1** | **Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf`, slot 0** |
| 23:05:06.682356 | Security log cleared | EID 1102, EventRecordID 28,201 |
| 23:30 – 23:31 | KAPE collection of `collection_s1_v2` | EID 4688, EventRecordID 28777 / 28784 |

The execution time is new. It was not previously recorded anywhere in this
repository, and it does not depend on the EVTX evidence that the log clear
destroyed.

The ordering problem that motivated OQ-003 is resolved by the first row. The
`Zone.Identifier` reads at 22:38 fall eighteen minutes **after** the download,
not seven minutes before it. The contradiction was in the operator log.

Rows 2 and 4 of the operator log survive the check: its execute entry is 6.70 s
late against Prefetch, and its log-clear entry 6.11 s late against EID 1102.
Both sit inside the +/-60 s tolerance. Only the download entry fails, by a
factor of roughly 250, which is why it is treated as a transcription error
rather than as evidence of clock drift.

The scenario therefore spans **44m 59.97s**, not the 19m 40s originally
recorded. See the amendment in `groundtruth/verification-method.md`.

## 3. Action 99 — clean collection contamination check

Run under the dated rule fixed in `groundtruth/verification-method.md`, not
under the runbook's withdrawn "discard and recollect" rule.

**The sharpest instrument, complete and negative.** The Prefetch directory of
each clean collection was listed in full and filtered for entries beginning
`INVOICE`:

| Collection | `INVOICE_SCAN.EXE-*.pf` present? |
|---|---|
| `collection_clean_a` | **No** |
| `collection_clean_b` | **No** |
| `collection_s1_v2` | Yes — `INVOICE_SCAN.EXE-A345C2FE.pf`, 7,145 bytes |

A Prefetch file for that executable is direct evidence that the binary executed
on the machine the snapshot was taken from. Its absence from both clean
baselines, and its presence in the scenario collection, is the expected result:
**the snapshot revert took.** This is stated as a positive result, naming the
instrument and the three trees searched, rather than as an absence of finding.

Filename and timeline searches across the three collection trees and the three
timeline CSVs remain `PENDING RUN` for the CSV half.

**Browser-side check, added 2026-08-26.** Edge `History` in `collection_s1_v2`
records eleven `invoice_scan.exe` downloads. Dated under the same rule:

| Window | Count | Detail |
|---|---|---|
| LAB-BUILD (2026-08-20 / 21) | 10 | Nine from `192.168.50.5`, sizes 201,216 (five) and 360,448 (three, plus id 12); target paths include `invoice_scan (1).exe` and `invoice_scan (2).exe` |
| INCIDENT (2026-08-23 22:45Z–23:31Z) | 0 | The scenario download at 22:20:06Z falls 25 minutes **before** the declared incident window, because that window was drawn from the erroneous operator-log time |
| OTHER | 1 | The scenario download itself, 2026-08-23T22:20:06.710763Z, `192.168.50.2`, 4,608 bytes |

**The incident window in `groundtruth/verification-method.md` section 3 needs
its lower bound moved from 22:45 to 22:20 now that OQ-003 is closed.** Recorded
here rather than edited there: that section was pre-registered, and the window
was drawn in good faith from the best time then available. The correction is an
amendment, not a rewrite.

**Journal check.** `History-journal`, 8,720 bytes, SHA-256
`7ae0bb4e...85d4438`. Its first eight bytes are zero, not the SQLite
rollback-journal magic `d9d505f920a163d7`: the journal header has been
invalidated, which is what SQLite does on a successful commit when the file is
persisted rather than deleted. It carries no pending transaction. Only six
printable strings survive in it, all fragments of the `meta` table, none
matching `invoice`, `192.168.50`, `Downloads` or `.exe`. **The committed state
read above is therefore the complete state**, which is the opposite of the
concern its presence raised, and is recorded as a resolved negative.

## 4. Baseline composition — recorded here because it bears on Week 4

Both clean collections' Prefetch directories contain execution artefacts for
Visual Studio, SQL Server, SSMS, VS Code, Cursor, Notepad++, Skype, OneDrive and
M365 Copilot. Because the set appears in both, it predates both and belongs to
the BASELINE-CLEAN snapshot itself.

`docs/lab-setup.md` described that snapshot as carrying "one small application
install". The description is corrected there. The consequence recorded here: the
Week 4 anomaly model trained on these baselines learns a developer workstation
as normal, not the end-user profile `janed` is described as.

Edge `History` corroborates this from a second artefact family. Of 30 `urls`
rows, the browsed hosts are `bing.com` (12 visits), `notepad-plus-plus.org` (5),
`google.com` (4+2), `192.168.50.5:8000` (3), `github.com` (2), `news.com` (2),
`wikipedia.org`, `cnet.com` and `filebin.net`. The `downloads` table also holds
a Notepad++ installer fetched from GitHub on 2026-08-17 and a `Files.zip` fetched
from a university Moodle instance on 2026-08-20. `janed`'s browsing is a mixture
of lab-construction searches and unrelated real-world activity, not a simulated
end-user profile.

## 4b. What the scenario collection's Security log actually contains

Read directly 2026-08-26 with `evtx` 0.12.1, the pinned version.

| Measure | Value |
|---|---|
| Records | 584, EventRecordID 28,201–28,784, contiguous, zero duplicates |
| Span | 2026-08-23T23:05:06.682356Z to 23:31:48.536586Z — 26m 42s |
| First record | the EID 1102 log clear |
| EID 4688 | 299 |
| Other frequent EIDs | 5379 (108), 4624 (58), 4672 (54), 4798 (17) |
| 4688 by `SubjectUserName` | `WINDOWS10$` 247, `admin_local` 39, `-` 11, `LOCAL SERVICE` 2 |
| 4688 in the Guest Additions install chain | 20 |
| 4688 for `kape.exe` | 3 |
| 4688 attributable to the attack | **0** |

The contiguity check independently re-confirms CD-004 for this file: 584
records, 584 distinct EventRecordIDs, no gaps.

**Every record in this log is post-incident.** The log begins at the moment the
actor destroyed it and ends at acquisition. Its largest burst is 102 process
creations in the 30 seconds from 23:15:30, which is the VirtualBox Guest
Additions install settling — an investigator action taken on the live machine
eight minutes after the log clear and sixteen minutes before collection. See the
correction under "Virtualisation tooling" in `docs/lab-setup.md`.

This is the strongest single demonstration in the Week 1 evidence of why
multi-artefact triage is necessary: the canonical execution record is gone, and
what replaced it in the same log is the investigator's own tooling.

## 5. Provenance sample — action 96

`PENDING RUN`. Three rows are to be drawn at random from
`outputs/s1_v2/timeline.csv` and resolved by hand to `EventRecordID=<n>` in the
named `source_file`. The rows drawn will be named here with their resolution, in
accordance with `groundtruth/verification-method.md` section 4.

Two hand resolutions have already been performed, against artefact families
other than EVTX, and are recorded as method evidence rather than as the sample:

1. The execution artefact in row 4 was located, opened and read directly, and
   its volume device path resolved to a drive letter through the serial recorded
   in `docs/evidence/accounts-and-volumes.txt`.
2. The Edge `History` database was copied out of the collection, opened
   read-only and non-replaying with `immutable=1`, and the `downloads` row for
   the scenario located by hand. SHA-256 of the copy read:
   `cb6879c3f8f5296886f945982452a028d39d88582eb37273012d04b7c503ecfe`.
   The copy was taken because the file's depth in the collection tree exceeded
   what the reading toolchain could open in place; the source was not modified.
   Both facts are recorded so the provenance of this reading is auditable.

## 6. Prefetch parser review

**Blocked, not waived.** `dfir_triage_pipeline/parsers/prefetch.py` does not
exist in the merged tree as of 2026-08-26, and `parsers/__init__.py` still has
the import commented out. Review criteria are fixed in
`Person A/Day 5 - remaining.md` and execute when the module exists.

The manual read of `INVOICE_SCAN.EXE-A345C2FE.pf` gives that review a reference
result to check against, which it did not have before:

| Field | Expected value |
|---|---|
| executable | `INVOICE_SCAN.EXE` |
| prefetch hash | `0xA345C2FE` |
| format version | 30 |
| run count | 1 |
| last run, slot 0 | `2026-08-23T22:57:15.832787Z` |
| slots 1–7 | unset |
| volumes | 1, `\VOLUME{01dd01162add2da6-a62af538}`, serial `0xA62AF538` |
| referenced files | 43 |

A parser that reports a different run count, a different slot 0, or a path
normalised in a way that loses the volume identity, is wrong against this
record.

Integration (action 90) is outstanding and moves to Week 2. Week 1 verification
therefore covers one of two declared Week 1 parsers, and every Prefetch-dependent
ground-truth row above carries `NOT-PARSED` rather than `MISSED`.
