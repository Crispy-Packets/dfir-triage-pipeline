# Scenario 1 — verification sheet

Verdicts follow the closed vocabulary fixed in `groundtruth/verification-method.md`
before any comparison was run: `MATCHED`, `DESTROYED`, `NOT-EVALUABLE`,
`NOT-PARSED`, `MISSED`. `MISSED` is the only category that denotes a pipeline
failure.

> **Superseded for verdicts by `groundtruth/scenario1-verification-week3.md`
> (2026-08-30).** This sheet remains the Week 1 record and is not edited. Two
> things in it are stale and are corrected there rather than here:
>
> * Row 9 quotes `event_id` `8a5def6de6c37254`. That record is now
>   `5573ac8d6a6363d2` — `timestamp_type` entered the `event_id` content hash
>   when `CD-019` landed. The evidence did not change; the identifier did.
> * Six rows carry `NOT-PARSED` because the parsers did not exist. Three now
>   resolve to `MATCHED`.
>
> Read this sheet for what Week 1 could establish. Read the Week 3 sheet for
> what the pipeline now produces.

**Status: complete for Week 1.** The pipeline was run over all three
collections on 2026-08-26 and every row below carries a final verdict. The
`MISSED` count is **0**.

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
| 9 | logclear | EID 1102 | **`MATCHED`** | Timeline row `event_id` `8a5def6de6c37254`, `source_file` `C/Windows/System32/winevt/logs/Security.evtx`, `source_locator` `EventRecordID=28201`, `timestamp_utc` 2026-08-23T23:05:06.682356Z. Ground truth 23:05:12.794670Z. **Δ = 6.112 s**, inside the ±60 s tolerance |

**`MISSED` count: 0.** Of nine ground-truth rows: one `MATCHED`, one
`DESTROYED`, one `NOT-EVALUABLE`, six `NOT-PARSED`, zero `MISSED`.

Stated as the method requires: **every declared artefact that the Week 1
pipeline could have produced, it produced.** The single row for which the
pipeline was both responsible and capable is `MATCHED` to within 6.112 s of
ground truth. The recall figure `MATCHED / (MATCHED + MISSED)` is 1/1. The six
`NOT-PARSED` rows are the declared Week 2 roadmap and the one `NOT-EVALUABLE`
row is collection scope; neither is charged to the pipeline.

## 1b. Pipeline run, 2026-08-26

Run over all three collections. `run.txt` captured for each under `outputs/`.

| Collection | `files_seen` | manifest expects | `files_handled` | `files_failed` | Events | `evtx.security` | `evtx.system` |
|---|---|---|---|---|---|---|---|
| `collection_s1_v2` | 817 | 817 | 2 | **0** | 382 | 359 | 23 |
| `collection_clean_a` | 892 | 892 | 2 | **0** | 10,158 | 10,142 | 16 |
| `collection_clean_b` | 916 | 916 | 2 | **0** | 10,455 | 10,439 | 16 |

`files_seen` reconciles exactly against `docs/collection-manifest.md` in all
three. `files_failed` is zero in all three. The traversal did not stop early.

### Event counts reconcile against independently documented figures

The event totals were not taken on trust. Each was checked against a count
established separately, before the pipeline existed in this form.

| Check | Independent figure | Pipeline | Agree |
|---|---|---|---|
| s1_v2 Security: sum of the six declared EIDs | 4688 (299) + 4624 (58) + 1102 (1) + 4625 (1) = **359** | 359 | yes |
| clean_b Security: sum of declared EIDs | 4624 (919) + 4625 (13) + 4688 (9,502) + 4720 (5) = **10,439** | 10,439 | yes |
| clean_b System: EID 7045 | **16** | 16 | yes |
| clean_b `process_exec` by `SubjectUserName` | `WINDOWS10$` 7,881 · `Youssef` 1,176 · `admin_local` 179 · `janed` 103 | identical | yes |

The s1_v2 figure is the stronger of the two: those EID counts were obtained by
reading `Security.evtx` directly with `evtx` 0.12.1 outside the pipeline, and
they sum to the pipeline's own total exactly. **The parser emits every declared
EID and nothing undeclared.**

### Contract checks

| Check | Result |
|---|---|
| `source_locator` matches `^EventRecordID=\d+$` | 382 / 382 and 10,455 / 10,455 conform. Zero exceptions |
| Sorted ascending by `timestamp_utc` | true in both files checked |
| `confidence` | `high` on every row of both files |
| Distinct `source_file` values | two per collection: `Security.evtx`, `System.evtx` |

CD-004 is satisfied in output, not only in the source records.

## 1c. Path-shape analysis — the Week 3 contract question

Measured across `outputs/s1_v2/timeline.csv` (382 rows) and
`outputs/clean_b/timeline.csv` (10,455 rows).

### The device-path risk is real but small, and it is confined to the collection tool

| `process_exec` path form | s1_v2 | clean_b | total |
|---|---|---|---|
| drive letter `C:\...` | 296 | 9,475 | 9,771 |
| `\Device\HarddiskVolumeN\...` | 0 | **10** | **10** |
| `\Device\CdRom0\...` | 1 | 0 | 1 |
| other (`Registry`, `MemCompression`, kernel pseudo-processes) | 2 | 17 | 19 |

All ten device-path rows are the same two binaries:
`\Device\HarddiskVolume2\kape\KAPE\kape.exe` (6) and
`...\gkape.exe` (4). `\Device\HarddiskVolume2` is Z:, so these are the
collection tooling running from the collection volume - lab-operation artefacts
already declared as such under "Investigator activity in the evidence".

**This narrows an assumption carried in the Day 5 plan and in earlier revisions
of `docs/lab-setup.md`.** Both treated NT device paths in 4688 as a threat to
the Week 3 download-to-execution join. Measured, they are 10 rows in 9,801
`process_exec` rows - 0.10 per cent - and not one of them is attack-relevant. No
`process_exec` row for a user-space binary uses a device path. The join is not
at risk from this.

### The real path problem is `service_install`, and it is worse

`Event.path` is documented in `model.py` as *"full path as recorded; never a
basename"*. For `service_install` that is not what the field contains.

| Form | s1_v2 | clean_b | Example |
|---|---|---|---|
| quoted, sometimes with arguments | 18 | 9 | `"C:\Program Files\...\sqlservr.exe" -sMSSQLSERVER` |
| relative, no root | (in 18) | 3 | `system32\DRIVERS\RsFx0800.sys` |
| NT `\SystemRoot\` form | (in 18) | 1 | `\SystemRoot\System32\drivers\VBoxWddm.sys` |
| unexpanded environment variable | 2 | 1 | `%SystemRoot%\system32\svchost.exe -k print` |
| plain drive letter | 3 | 2 | `C:\Windows\System32\svchost.exe` |

**Of 39 `service_install` rows across the two collections, 34 carry a value that
is not a plain absolute filesystem path.** The field is holding a service
`ImagePath`, which is a command line, not a path. A Week 3 rule joining
`process_exec` to `service_install` on `path` equality will match
`C:\Windows\System32\svchost.exe` against
`%SystemRoot%\system32\svchost.exe -k print` and return nothing.

This is a contract question and it belongs to Person B: the parser is passing
through what the record says, which is correct. What is needed is a decision -
either `path` is normalised at parse time and the raw value preserved in
`details`, or `Event` gains a separate field for a service image path. It cannot
be settled by the EVTX parser alone.

### `user` has the same problem on a second axis

Fourteen distinct values in `clean_b`, of which **two mean "absent"** - the empty
string (11 rows in s1_v2) and `-` (134 rows in clean_b) - and at least four
denote system contexts: `SYSTEM`, `LocalSystem`, `LOCAL SERVICE`,
`NT AUTHORITY\LOCALSERVICE`. Any Week 4 grouping by `user` will treat these as
distinct principals unless a normalisation rule exists. It does not yet.

### Rows that cannot participate in a path join at all

`path` is empty on every `logon` (919 + 58), `logon_failed` (13 + 1),
`account_created` (5) and `log_cleared` (1) row - **997 of 10,837 rows across the
two collections**. This is semantically correct; it is recorded so that a
future join reporting "no correlation" against those event types is read as
by-design rather than as a defect.

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

**Timeline search, completed 2026-08-26.** Every row of
`outputs/s1_v2/timeline.csv` and `outputs/clean_b/timeline.csv` was searched
case-insensitively for `invoice` in the `path` and `action` columns.

| Timeline | Rows searched | `invoice` hits |
|---|---|---|
| `outputs/s1_v2/timeline.csv` | 382 | **0** |
| `outputs/clean_b/timeline.csv` | 10,455 | **0** |

Zero in the scenario collection is the expected result and is itself a finding:
the EID 4688 for the execution at 22:57:15.832787Z was destroyed by the log
clear, so the pipeline cannot see the execution in EVTX at all. It is visible
only in Prefetch, which Week 1 does not parse. Zero in `clean_b` is consistent
with the Prefetch result above.

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

**The `VBoxService` EID 7045 exists, confirmed 2026-08-26 from the pipeline
output.** `outputs/s1_v2/timeline.csv` carries a `service_install` row at
2026-08-23T23:14:04 with `path` `%SystemRoot%\System32\VBoxService.exe`,
alongside four VirtualBox driver installs the same minute: `VBoxGuest.sys`,
`VBoxWddm.sys`, `VBoxMouse.sys` and `VBoxSF.sys`. `docs/lab-setup.md` previously
asserted that no such record existed in any collection. The claim was withdrawn
on the strength of the 4688 install chain; it is now disproved outright by the
7045 itself, and no further reading of `System.evtx` is required.

## 5. Provenance sample — action 96

**Rows drawn 2026-08-26. Resolved 2026-08-28. All three resolve as documented.**

Three rows were drawn at random from `outputs/s1_v2/timeline.csv` (382 rows) by
uniform sample of the row index, not by selection. They are named here before
resolution so that the sample cannot be quietly changed if one proves awkward.

| Drawn index | `timestamp_utc` | `event_type` | `user` | `path` | `source_file` | `source_locator` | Resolved by hand? |
|---|---|---|---|---|---|---|---|
| 131 | 2026-08-23T23:15:31.058684Z | `process_exec` | `WINDOWS10$` | `C:\Windows\System32\svchost.exe` | `C/Windows/System32/winevt/logs/Security.evtx` | `EventRecordID=28364` | **yes — 4/4 fields** |
| 303 | 2026-08-23T23:17:45.468579Z | `logon` | `SYSTEM` | *(empty)* | `C/Windows/System32/winevt/logs/Security.evtx` | `EventRecordID=28640` | **yes — 4/4 fields** |
| 330 | 2026-08-23T23:19:36.095131Z | `process_exec` | `admin_local` | `Z:\kape\KAPE\kape.exe` | `C/Windows/System32/winevt/logs/Security.evtx` | `EventRecordID=28674` | **yes — 4/4 fields** |

Row 330 is worth resolving first: `docs/lab-setup.md` records EventRecordID
28674 independently, as the 2026-08-23T23:19 KAPE run that used `--tsource Z:`
and is *not* the C: collection. If the hand resolution finds that record and it
matches that description, the provenance claim is demonstrated against a record
whose identity was documented before the timeline existed.

Resolution procedure, per `groundtruth/verification-method.md` section 4: open
the named `source_file` inside `collections/collection_s1_v2/`, locate
`EventRecordID=<n>`, and confirm the timestamp, event type and path against the
row above. Record the outcome here. If any row cannot be resolved by hand, that
is a finding and is recorded as one rather than resolved by drawing a different
row.

### Outcome, 2026-08-28

All three records were located in
`collection_s1_v2\C\Windows\System32\winevt\logs\Security.evtx` and every
field matched: 12 of 12 across timestamp, event type, user and path. No row
failed to resolve and no row was redrawn.

| Index | EventRecordID | EID | Timestamp | Event type | User | Path |
|---|---|---|---|---|---|---|
| 330 | 28674 | 4688 | match | match | match | match |
| 131 | 28364 | 4688 | match | match | match | match |
| 303 | 28640 | 4624 | match | match | match | match |

Row 330 carries the strong form of the claim. `docs/lab-setup.md:316` records
EventRecordID 28674 as the 2026-08-23T23:19 KAPE run that used `--tsource Z:`
and is *not* the C: collection. That identification was written before the
timeline existed. The record resolves to exactly that: EID 4688 at
23:19:36.095131Z, `SubjectUserName` `admin_local`, `NewProcessName`
`Z:\kape\KAPE\kape.exe`. The timeline row is therefore traceable to a record
whose identity was documented independently of it.

Row 303 confirms the empty-path convention is deliberate rather than a dropped
field. EID 4624 carries no process image, so `path` is empty and `user` is read
from `TargetUserName`, not `SubjectUserName` — the parser's own field selection
for logon events, exercised here against a real record.

**Method, and how it differs from the procedure above.** The three records were
read programmatically from the `.evtx` with `PyEvtxParser` and the raw event XML
parsed directly, rather than opened in Event Viewer. Field selection replicates
the parser's rules independently rather than importing them. The reading does
**not** go through `outputs/s1_v2/timeline.csv`: the purpose of the check is to
confirm the timeline against its source, so reading the timeline would make the
check circular.

This is a weaker demonstration than an Event Viewer resolution in one specific
respect, and the difference is recorded rather than glossed. Both this reading
and the pipeline use the same `evtx==0.12.1` library to decode the binary
format, so a defect inside that library's record decoding would be invisible to
both. What the check does establish independently is everything above the
decoder: record location by EventRecordID, XML field selection, timestamp
normalisation, event-type mapping, and the timeline's row content. A subsequent
Event Viewer spot-check of row 330 would close the remaining gap; it is not
required for the provenance claim, which concerns the pipeline's handling of the
record rather than the correctness of the EVTX binary parser.

Script: `tools/resolve_provenance.py`.

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
