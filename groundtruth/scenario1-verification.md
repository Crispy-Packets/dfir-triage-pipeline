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
| 1 | download | Edge `History` | `NOT-PARSED` | Present: `.../Default/History`, 229,376 bytes, plus a `History-journal` of 8,720 bytes. Browser family is Week 2 |
| 2 | download | `Zone.Identifier` | `NOT-EVALUABLE` | Verified live at `ZoneId=3`; `C\Users\janed\Downloads` is outside the KapeTriage collection scope. OQ-005 |
| 3 | download | `$MFT` | `NOT-PARSED` | Present in all three collections. MFT parser is Week 2. Carries the size that settles OQ-001 |
| 4 | execute | Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf` | `NOT-PARSED` | **Present and read by hand, 2026-08-24 collection.** 7,145 bytes, format version 30, run count **1**, last run **2026-08-23T22:57:15.832787Z**. Referenced path resolves to `C:\Users\janed\Downloads\invoice_scan.exe`. Prefetch parser does not exist in the merged tree |
| 5 | execute | EID 4688 for `invoice_scan.exe` | `DESTROYED` | Predates the EID 1102; the surviving Security log's first record post-dates the clear |
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
| 22:45:32.274977 | download, **as claimed by the operator log** | `groundtruth/Scenario1.md` |
| 22:46:06 – 22:47:59 | Defender scheduled Quick Scan, no detections | Defender/Operational 1000, 1001 |
| **22:57:15.832787** | **`invoice_scan.exe` executed, run count 1** | **Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf`, slot 0** |
| 23:05:06.682356 | Security log cleared | EID 1102, EventRecordID 28,201 |
| 23:30 – 23:31 | KAPE collection of `collection_s1_v2` | EID 4688, EventRecordID 28777 / 28784 |

The execution time is new. It was not previously recorded anywhere in this
repository, and it does not depend on the EVTX evidence that the log clear
destroyed.

Note the ordering problem this does not resolve: the `Zone.Identifier` of the
downloaded file is read at 22:38:44, seven minutes before the operator log's
download time of 22:45:32. That contradiction is OQ-003 and is settled from Edge
`History`, not from this table.

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

## 4. Baseline composition — recorded here because it bears on Week 4

Both clean collections' Prefetch directories contain execution artefacts for
Visual Studio, SQL Server, SSMS, VS Code, Cursor, Notepad++, Skype, OneDrive and
M365 Copilot. Because the set appears in both, it predates both and belongs to
the BASELINE-CLEAN snapshot itself.

`docs/lab-setup.md` described that snapshot as carrying "one small application
install". The description is corrected there. The consequence recorded here: the
Week 4 anomaly model trained on these baselines learns a developer workstation
as normal, not the end-user profile `janed` is described as.

## 5. Provenance sample — action 96

`PENDING RUN`. Three rows are to be drawn at random from
`outputs/s1_v2/timeline.csv` and resolved by hand to `EventRecordID=<n>` in the
named `source_file`. The rows drawn will be named here with their resolution, in
accordance with `groundtruth/verification-method.md` section 4.

One hand resolution has already been performed, against Prefetch rather than
EVTX, and is recorded as method evidence rather than as the sample: the
execution artefact in row 4 was located, opened and read directly, and its
volume device path resolved to a drive letter through the serial recorded in
`docs/evidence/accounts-and-volumes.txt`.

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
