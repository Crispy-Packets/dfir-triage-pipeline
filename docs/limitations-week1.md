# Week 1 limitations

Every limitation here is a constraint on what the Week 4 evaluation may claim.
A limitation recorded with its measurement is a stronger position than one
discovered by a reader.

All measurements below are complete. The EVTX-dependent figures were filled
on 2026-08-28 from a full pipeline run over all three collections after the
week1/evidence-evtx merge: 892 / 916 / 817 files seen, 0 failed.

---

## Evidence and collection

**Delivery method.** `collection_s1_v2` delivers the binary by HTTP download in
Edge, with `Zone.Identifier` `ZoneId=3` confirmed. The Week 1 USB collection is
superseded and is **not evidence for any result** (CD-013).

**Clean collection roles.** `clean_b` is the reference baseline -- the only clean
collection containing benign user activity. `clean_a` was collected with no user
activity present and is an ambient-noise control: a finding raised against it is
system noise by definition, and its false-positive count is a floor, not a rate
(CD-014).

**NAT asymmetry.** Both clean collections were collected with NAT enabled; the
scenario was collected host-only. The expectation was that the clean collections
would therefore carry extra EID 7045 service installations from Windows Update
that the scenario cannot contain.

Measured 2026-08-28, the asymmetry runs the other way. `clean_a` and `clean_b`
carry 16 x 7045 each, identical service-for-service; `collection_s1_v2` carries
23. The seven additional records in the scenario are VirtualBox Guest Additions
-- `VBoxGuest.sys`, `VBoxWddm.sys`, `VBoxMouse.sys`, `VBoxSF.sys`, `VBoxSF.sys`,
`VBoxService.exe`, `WUDFRd.sys` and a bare `svchost.exe` -- installed in the
scenario guest and absent from both baselines. No 7045 in any collection is
attributable to Windows Update.

The limitation therefore is not NAT-driven service noise. It is that the
scenario guest differs from the baselines by an entire Guest Additions install,
so a 7045 present only in the scenario is not by itself evidence of the attack.
The attack's own persistence was HKCU Run, not a service, and no 7045 in the
scenario corresponds to `invoice_scan.exe`.

**Locked files were deferred, not lost.** Each KAPE ConsoleLog reports files
skipped on the first pass with `Deferring ... due to IOException` -- 153 in
`collection_s1_v2`, 200 in `clean_a`, 215 in `clean_b`. These are open handles,
chiefly EVTX and Defender logs. KAPE then reports `Deferred file count: N.
Copying locked files...` and copies each by raw handle, hashing the source. No
collection reports a hard error: excluding the benign `Target ApplicationEvents
... already processed` duplicate-target message, the error count is 0 in all
three logs. Spot-checked files present on disk at expected size, and the
`collection_s1_v2` manifest reconciles 793 of 793.

Recorded because a reader meeting 153 deferral lines in a ConsoleLog could
reasonably read them as collection failures. They are the tool's normal
fallback for locked files, and the evidence is complete.

**ConsoleLog timestamps are host-local, not UTC.** The KAPE ConsoleLogs are the
one place in the evidence set where a naive local timestamp sits beside UTC
values elsewhere: the `collection_s1_v2` log header reads
`2026-08-24 02:31:49` for a collection recorded as `2026-08-23T23:31:48Z`, a
UTC+3 offset consistent with the measured guest clock. Any figure quoted from a
ConsoleLog must be converted before it is compared with a timeline row.

**Scenario 1 was attempted three times; artifacts from the earlier attempts
survive in the collection.** Only the third attempt (download 2026-08-23
22:20:06.710763Z, 4,608 bytes from `192.168.50.2:8000`) is the run under test.
Nine earlier `invoice_scan.exe` downloads from 20 and 21 August, at 201,216 and
360,448 bytes from `192.168.50.5:8000`, are troubleshooting of transfer faults
and are present in the Edge history. The HKCU Run persistence carries a
timestamp from the second attempt because restoring the baseline did not clear
the key and every attempt used the same payload path.

The consequence for evaluation is that `collection_s1_v2` is not a single-run
collection: it holds one executed scenario and the download residue of two
abandoned ones. Detection rules must discriminate on size and source host, not
on filename. Recorded in full as D-027.

**One realistic clean collection.** False-positive measurement and anomaly-model
training draw on the same data. A third clean collection with a differing benign
workload is a Week 2 candidate. Until it exists, a false-positive rate measured
on `clean_b` and a model trained on `clean_b` are not independent.

**Manifest coverage gap.** The `collection_s1_v2` collection-time manifest covers
793 of 817 files. The 24 uncovered are registry hives, transaction logs, DPAPI
blobs and `desktop.ini`. `clean-s1-v2-sha256-supplement.csv` covers them from
receipt onward rather than from collection; the lab VM was decommissioned before
the gap was found, so collection-time hashes cannot be produced (CD-017, D-019).

**OneDrive.** Evidence was held in a OneDrive-synced folder between transfer and
ingestion, and moved out of sync scope before parsing. No integrity failure was
observed -- set comparison and hash spot-checks passed on all three collections
-- but the window existed and is recorded rather than omitted.

---

## Prefetch

**Event count is a LOWER BOUND on executions, never a total.** The artifact
records at most eight run times regardless of how many times a binary ran, so a
binary executed fifty times yields at most eight Events. The report must never
present Event count as an execution total (CD-018).

**`runCount` required a parser-level correction.** `windowsprefetch 4.0.3` reads
`runCount` at an offset that is wrong for Windows 10 version-30 records: 610 of
835 collected `.pf` files reported `len(timestamps) > runCount`, and
`INVOICE_SCAN.EXE` reported `0` against a confirmed execution. The parser reads
offset `0xC8`, where the invariant holds in 835 of 835 files. The emitted
`run_count` is therefore **not** the library's value (CD-018, D-023).

**`path` carries the executable name only.** Prefetch records referenced paths in
uppercase volume-GUID notation
(`\VOLUME{01dd01162add2da6-a62af538}\WINDOWS\SYSTEM32\NTDLL.DLL`), which cannot
string-match a 4688 `NewProcessName` under any casing. Joins use the case-folded
basename per CD-010, with full-path agreement as a corroborator where the volume
map permits it. **Known cost: basename matching joins distinct binaries sharing
a name**, measured against the clean baselines and reported in the evaluation.

**Timestamps are naive strings established as UTC.** `windowsprefetch 4.0.3`
returns run times as naive strings. The naive value was established as UTC by
comparison against ground truth (delta -6.70 s, not a whole hour) and confirmed
independently by decoding the raw FILETIME bytes, which matched the library
string to 1 microsecond. No offset correction is applied. Recorded in
`docs/evidence/prefetch-spike-s1v2.txt` and D-013.

**Prefetch rows carry no `user`.** The artifact does not record which account
executed a binary. Any user attribution for an execution must come from another
family -- 4688 where the Security log survives -- and `collection_s1_v2`'s
Security log was cleared. Execution-to-account attribution in the scenario is
therefore **not available from Prefetch alone**.

**Sub-minute delta against ground truth is expected.** Prefetch writes the run
time when the OS completes the application trace, seconds after the user action
a ground-truth log records. Only a **whole-hour** delta indicates a timezone
fault.

**Two volume serials appear, and the serial is per-record.** `a62af538` is the
target system volume; `5659c38d` carries 27-32 events per collection (2.6-3.1%).
In the clean collections those are exclusively investigator tooling
(`GKAPE.EXE`, `KAPE.EXE`, `RG.EXE`, `ROBOCOPY.EXE`, `CONSENT.EXE`,
`POWERSHELL.EXE`); in `collection_s1_v2` the same serial also carries
`EXPLORER.EXE` and `NOTEPAD.EXE`. **The serial marks which volume a binary ran
from, not whether it is tool noise** -- `KAPE.EXE` appears under both serials in
`clean_b`. Week 3's `core/entity.py` must not treat the serial as a noise
classifier (CD-010).

**Not every `.pf` is a Prefetch record.** `Op-*.pf` are SysMain operational files
that the library parses **without raising**, yielding the filename fragment as an
executable name. One fabricated event reached the timeline before the exclusion
was added. A run-summary failure count cannot detect this class of fault
(CD-020, D-025).

**Five `.pf` files are zero-filled.** `DEFRAG.EXE-738093E8` (clean_a, clean_b)
and `SVCHOST.EXE-CE29B0F4` (all three) are runs of zero bytes, present in their
SHA-256 manifests and therefore collected and transferred intact. They yield no
records rather than raising: an empty artifact is an absence of evidence, not a
parser fault (CD-020, D-024).

---

## EVTX

**EID coverage.** All six declared EIDs carry real evidence; none is
unit-test-only. Counts by event_type across the three collections
(`clean_a` / `clean_b` / `s1_v2`):

| EID | event_type | clean_a | clean_b | s1_v2 |
|---|---|---|---|---|
| 4688 | `process_exec` | 9219 | 9502 | 299 |
| 4624 | `logon` | 906 | 919 | 58 |
| 4625 | `logon_failed` | 13 | 13 | 1 |
| 7045 | `service_install` | 16 | 16 | 23 |
| 4720 | `account_created` | 4 | 5 | 0 |
| 1102 | `log_cleared` | 0 | 0 | 1 |

Two rows are worth reading carefully. `account_created` is 0 in the scenario, so
the 4720 path is exercised only by the clean collections. `log_cleared` is 1 in
the scenario and 0 elsewhere, so the 1102 path is exercised by exactly one
record in the whole corpus -- the anti-forensic action itself.

**`evtx.security` row counts.** Measured 2026-08-28: `clean_a` 10,142,
`clean_b` 10,439, `collection_s1_v2` 359. The scenario carries 3.4% of the
clean-collection volume because `wevtutil cl security` was run at
`2026-08-23T23:05:12.794670Z`. That is the expected signature of the scenario,
**not** a parser failure -- the 4688 for `invoice_scan.exe` is destroyed by
design and the ground truth says so.

The scenario's 359 reconciles exactly against EID counts established
independently before the run: 4688(299) + 4624(58) + 1102(1) + 4625(1) = 359.

The consequence for Week 4 is that no detection rate may be computed by
comparing raw row counts between the scenario and a baseline. The scenario is
missing evidence by design, and a rule that fires less often there is not
thereby less sensitive.

**Account distribution.** The machine account dominates every collection:
`WINDOWS10$` holds 7,746 of 10,158 EVTX rows in `clean_a` (76%), 7,881 of 10,455
in `clean_b` (75%), and 247 of 382 in `s1_v2` (65%). `SYSTEM` is next in all
three.

The human accounts are a small minority -- `Youssef` 1,203 and 1,212 in the two
baselines, `janed` 105 in each, `admin_local` 57 and 194. In the scenario the
order inverts: `admin_local` holds 42 rows against `janed`'s absence from the
top six, because the surviving post-clear window is the collection activity, not
the attack.

Two consequences. Any per-user baseline is really a machine-account baseline
unless machine accounts are excluded first. And `clean_b` carries 24 distinct
user spellings, two of which mean absent and four of which denote system
contexts, with the same identity appearing under more than one spelling
(CD-022) -- so a count of distinct users is a count of recorded spellings.

**`xml.etree.ElementTree` scope.** Used on evidence-derived XML generated by the
evtx library from binary structures, not on attacker-supplied documents. The
untrusted-XML threat model does not apply to this input.

---

## Investigator tool noise

KAPE's own execution artifacts are present in the evidence and are **not**
scenario activity:

- `GKAPE.EXE` and `KAPE.EXE` Prefetch records in all three collections
  (`GKAPE.EXE` in the clean collections only)
- `kape.lnk`, `KapeFiles-master.lnk` and variants under `Youssef`'s Recent folder
- KAPE's own `ConsoleLog` and `CopyLog` at the root of each collection tree,
  counted by the ingestion walker as files seen

The `Youssef` account is a researcher account, not an actor in the scenario, and
carries its own Edge profile. Rules must not attribute its activity to the
scenario.

---

## Deferred to Week 2

**Number of downloads in `collection_s1_v2` browser history** -- *measured
2026-08-30, no longer deferred.* The browser parser exists (B-5/B-6) and the
count is **20**, of which **9 are `invoice_scan.exe`**.

The ground truth records one download because one download is what the scenario
specifies. The history holds nine, and the eight extras are the first two
scenario attempts recorded in D-027: five at 201,216 bytes and three at 360,448
bytes, all from `192.168.50.5:8000` on 20 and 21 August. The scenario download
under test is the tenth artifact in the timeline -- 4,608 bytes from
`192.168.50.2:8000` at 2026-08-23T22:20:06.710763Z.

The baselines carry 10 (`clean_a`) and 11 (`clean_b`) downloads, all benign
installers and coursework, and **no `invoice_scan` artifact in either**.

The consequence for a download-to-execution rule is the one D-027 already
states: filename is not a usable join key on this corpus, because nine
downloads share the name and only one is the run under test. Size and source
host separate them.
