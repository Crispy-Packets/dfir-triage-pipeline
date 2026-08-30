# Scenario 1 — verification sheet, Week 3

Supersedes the verdict column of `groundtruth/scenario1-verification.md`, which
remains the Week 1 record and is not edited. Verdicts follow the closed
vocabulary fixed in `groundtruth/verification-method.md` **before** any
comparison was run: `MATCHED`, `DESTROYED`, `NOT-EVALUABLE`, `NOT-PARSED`,
`MISSED`. `MISSED` is the only category that denotes a pipeline failure.

**Produced 2026-08-30** from the run recorded in `FYP\day34-gate-log.txt`, at
commit `56b21d6`, over `outputs/s1_v2/timeline.csv` (3,429 rows) and
`outputs/s1_v2/findings.csv` (22 findings). Every value below was read out of
those two files, not carried forward from a planning document.

---

## 1. Ground-truth rows, re-verdicted

| # | GT step | Expected artefact | Week 1 | **Week 3** | Evidence |
|---|---|---|---|---|---|
| 1 | download | Edge `History` | `NOT-PARSED` | **`MATCHED`** | `event_id` `4c58a24247dc3d22`, `downloads.id=13`, `2026-08-23T22:20:06.710763Z`, path `C:\Users\janed\Downloads\invoice_scan.exe`. Exact to ground truth, Δ = 0 |
| 2 | download | `Zone.Identifier` | `NOT-EVALUABLE` | `NOT-EVALUABLE` | Unchanged. `C\Users\janed\Downloads` is outside KapeTriage collection scope (OQ-005). Not a parser question |
| 3 | download | `$MFT` | `NOT-PARSED` | `NOT-PARSED` | Unchanged. No MFT parser exists; the seven families in the timeline are `amcache`, `browser`, `evtx.powershell`, `evtx.security`, `evtx.system`, `prefetch`, `registry` |
| 4 | execute | Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf` | `NOT-PARSED` | **`MATCHED`** | `event_id` `58c5d22e63b89ca7`, `run_slot=0`, `2026-08-23T22:57:15.832788Z`. Ground truth `22:57:15.832787Z` from the raw FILETIME. **Δ = 1 µs**, and it is D-013, not drift — see section 3 |
| 5 | execute | EID 4688 for `invoice_scan.exe` | `DESTROYED` | `DESTROYED` | Unchanged and unchangeable. The Security log's first record is the EID 1102 itself; nothing predates the clear |
| 6 | execute | Marker file `invoice_scan_marker.txt` | `NOT-PARSED` | `NOT-PARSED` | Unchanged. Zero rows in the timeline name it. It remains visible only as a referenced filename inside the Prefetch record, which the parser does not emit as an event. A file-system artefact, so it follows row 3 |
| 7a | execute | Amcache | `NOT-PARSED` | `NOT-EVALUABLE` **(provisional)** | The parser exists and produced **878 rows**. `invoice_scan.exe` is in none of them — searched by path and by action across every Amcache row. That is D-028 reproduced independently. See the vocabulary note below: this verdict is a stretch |
| 7b | execute | UserAssist | `NOT-PARSED` | `NOT-PARSED` | Unchanged. UserAssist lives in `NTUSER.DAT` but the registry parser reads Run/RunOnce only |
| 8 | persist | `NTUSER.DAT` Run key | `NOT-PARSED` | **`MATCHED`** | `event_id` `c1bb6d9de5ff273f`, `\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate` → `C:\Users\janed\Downloads\invoice_scan.exe`, `timestamp_type=presence`. **In `C/Users/admin_local/NTUSER.DAT`** — see section 3 |
| 9 | logclear | EID 1102 | `MATCHED` | **`MATCHED`** | `source_locator` `EventRecordID=28201`, `2026-08-23T23:05:06.682356Z`, Δ = 6.112 s from the operator log, inside the ±60 s tolerance. **`event_id` is now `5573ac8d6a6363d2`, not the `8a5def6de6c37254` the Week 1 sheet cites** — section 3 |

### `MISSED` count: 0

Of ten rows (row 7 having split): **four `MATCHED`**, one `DESTROYED`, two
`NOT-EVALUABLE`, three `NOT-PARSED`, **zero `MISSED`**.

Week 1 was one `MATCHED` of one row the pipeline was both responsible for and
capable of. Week 3 is four of four. The recall figure `MATCHED / (MATCHED +
MISSED)` is 4/4, and it is worth saying plainly that this figure is not
impressive on its own — it is four rows, and its value is that the denominator
is honest.

### A note on the vocabulary, raised rather than resolved

Row 7a does not fit the closed vocabulary. The artefact family is parsed, the
parser worked, and the record simply is not there — the Compatibility Appraiser
had not run in the 34 minutes between execution and collection (D-028). That is
neither a parser gap (`NOT-PARSED`) nor a pipeline failure (`MISSED`), and it is
only loosely "not evaluable".

`NOT-EVALUABLE` is recorded provisionally, and the stretch is disclosed rather
than hidden. **The vocabulary needs a sixth verdict — something like
`ABSENT-IN-ARTEFACT` — and it must be agreed before Week 4 runs its
comparisons, not after.** `verification-method.md` fixed the vocabulary before
any comparison precisely so that verdicts could not be invented to fit results;
changing it now, alone, having seen the result, would be the exact failure that
rule exists to prevent. It needs both signatures.

---

## 2. The chain, as the engine produced it

Four findings, quoted from `outputs/s1_v2/findings.csv`:

| finding_id | rule | claim | interval |
|---|---|---|---|
| `3c4423d76fff90f9` | R-CORR-0001 download → execution | `observed_interval` | **2229.122025 s** |
| `a2b2369710c19fde` | R-CORR-0003 execution → Run key | `observed_occurrence` | **none, deliberately** |
| `7345f47c7a18c81e` | R-ATOMIC-0006 autorun persistence | `none` | — |
| `3d631807d9959914` | R-ATOMIC-0002 log cleared | `observed_occurrence` | — |

`2229.122025 s` is the measured 37m 09.122s. Nine earlier `invoice_scan`
downloads exist in the same history and **none of them matched**: the window and
strict ordering selected `downloads.id=13`, which is what `ambiguity_ack` in
`R-CORR-0001` said would happen and is now demonstrated rather than asserted.

`a2b2369710c19fde` carries no interval. That is the whole D-027 decision working
on the real evidence: the Run key's `presence` timestamp sits two days *before*
the download, and the finding reports the relationship without a time claim.

**Every matched event in all four findings names its `source_file` and its
`source_locator`.** That is the acceptance gate's word "traceable", checked
against the produced file rather than against the code that produced it.

---

## 3. Three things the run changed in the evidence record

### 3.1 The Week 1 sheet cites an `event_id` that no longer exists

Row 9 recorded `8a5def6de6c37254`. The same record is now `5573ac8d6a6363d2`.
Nothing about the evidence changed: `timestamp_type` became part of the
`event_id` content hash when CD-019 landed, and CD-019 records the before/after
hash vectors for exactly this reason. The Week 1 sheet is not wrong about the
record; it is stale about the identifier. Any document quoting an `event_id`
from before CD-019 needs the same treatment.

### 3.2 D-027's "every attempt wrote the payload to the same path" is too strong

D-027 explains the stale Run key by saying every attempt wrote to
`C:\Users\janed\Downloads\invoice_scan.exe`. The browser rows show otherwise —
Edge's duplicate-name suffixing means five of the nine earlier downloads went
somewhere else:

| id | time | target |
|---|---|---|
| 4 | 2026-08-20T15:36:43.686891Z | `invoice_scan.exe` |
| 5 | 2026-08-20T15:51:59.977244Z | `invoice_scan.exe` |
| 7 | 2026-08-20T16:23:32.650934Z | `invoice_scan (1).exe` |
| 8 | 2026-08-20T18:41:10.511567Z | `invoice_scan (1).exe` |
| 9 | 2026-08-20T18:41:37.428021Z | `invoice_scan (2).exe` |
| 10 | 2026-08-21T00:04:33.670147Z | `invoice_scan (1).exe` |
| 11 | 2026-08-21T00:42:46.210969Z | `invoice_scan (1).exe` |
| 12 | 2026-08-21T00:52:39.127227Z | `invoice_scan.exe` |
| **13** | **2026-08-23T22:20:06.710763Z** | **`invoice_scan.exe`** |

**The mechanism survives; the wording does not.** The Run key was written at
`2026-08-21T01:34:07.976260Z`, which is **41m 28.8s** after id 12 — the last
attempt-2 download that landed on the bare name. D-027's "roughly forty minutes
after that attempt's last download" is therefore right to the minute. What is
wrong is "every attempt": the value stayed valid because the *last* attempt-2
download used the bare path and so did attempt 3, not because all of them did.

This is a wording correction to Person B's defect entry, offered rather than
made — `docs/defect-log.md` is his.

### 3.3 The persistence is registered for `admin_local`, not for `janed`

`SecurityUpdate` is in `C/Users/admin_local/NTUSER.DAT` and points at
`C:\Users\janed\Downloads\invoice_scan.exe`. Every download in the chain is in
janed's profile. Neither ground-truth row 8 nor D-027 names the hive.

It matters for what the finding claims: the autorun fires on **admin_local's**
logon and launches a binary out of **janed's** Downloads folder. That is a
cross-profile persistence, and a reader who assumes the Run key belongs to the
user who downloaded the file would describe the scenario wrongly. `R-ATOMIC-0006`
already reports `entity.user=admin_local` alongside
`entity.exe_name=invoice_scan.exe`, so the finding is correct; it is the prose
around it that needs to catch up.

---

## 4. A-11 — limitations that change, and one that does not

Three Week 1 limitations are affected. This section states the change;
`docs/limitations-week1.md` is not edited here, because Person B revised it on
2026-08-30 and a blind overwrite of a fresh edit is how documents get flattened.

**Changed — the chain was reconstructed by hand.** Week 1 recorded that Scenario
1's download → execution → persistence → log clear had been established
manually, by Person A, using libscca and a SQLite reader outside the pipeline.
**That is no longer a limitation.** The pipeline reconstructs it: finding
`3c4423d76fff90f9` with the measured interval, `a2b2369710c19fde` for the
persistence link, `3d631807d9959914` for the clear. The hand reconstruction is
now the *independent check* on the machine one, which is a stronger position
than either alone.

**Changed — six `NOT-PARSED` ground-truth rows.** Three of the six resolved to
`MATCHED`. Three did not, and the reasons are structural rather than
provisional: `$MFT` and the marker file need a file-system parser that is not in
the seven declared families, and UserAssist needs registry coverage beyond
Run/RunOnce. Those three should be restated as scope rather than as backlog.

**Unchanged — the Guest Additions gap is permanent.** `s1_v2` carries the
VirtualBox install and the baselines do not; the guest state that could have
produced a matched baseline no longer exists. Nothing this week touches it, and
the mitigation is still feature exclusion rather than a fix.

**New, and it belongs in the limitations rather than in a rule file.** Every
correlation rule has a clean-host base rate — `R-CORR-0003` fires five times on
a collection with no attack in it, at critical severity. Schema 1.4.0 records
these in each rule's `expected` block. The limitation to state is not that the
rules are noisy; it is that **on a corpus with one attack, a chain that also
matches ordinary software cannot be evaluated for precision.** Week 4 can report
detection and base rate side by side. It cannot report precision.

---

## 5. A-12 — signature

**Person A signs evidence and forensic-semantics correctness** for the compressed
Weeks 2 + 3, on 2026-08-30, at commit `56b21d6` plus the schema 1.4.0 rule
changes.

What that signature covers:

- The ten ground-truth rows in section 1, each verdict read from the produced
  output and not from a planning document.
- The four findings in section 2, including that every matched event names its
  `source_file` and `source_locator`.
- That the rule layer's time claims match what the artefacts actually support:
  `presence` events carry no interval, `last_run` events carry no completeness
  claim, and the D-027 case is handled by design rather than by accident.
- The measured base rates in every rule's `expected` block.

What it does **not** cover, stated so the signature is not read wider than it is:

- Software and test correctness. That is Person B's signature; he has given it
  for his side at `docs/evidence/day5-run-2026-08-30.md`, and his signature does
  not extend to the correlation engine, which landed after it.
- The verdict vocabulary question in section 1. Row 7a is provisional and needs
  both signatures before Week 4 uses it.
- Anything about `R-ATOMIC-0002`'s single positive case generalising. One EID
  1102 exists in the entire corpus.

**Person B's countersignature on the Week 3 code is outstanding.** The release is
one signature short until it is given, and that is recorded here as a fact
rather than skipped.
