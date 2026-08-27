# Week 1 limitations

Every limitation here is a constraint on what the Week 4 evaluation may claim.
A limitation recorded with its measurement is a stronger position than one
discovered by a reader.

Lines marked **[PENDING EVTX]** are blocked on the EVTX parser merge and are
completed at steps 190-192 on Day 5.

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
scenario was collected host-only. The clean collections therefore contain
Windows Update and telemetry activity, including EID 7045 service installations,
that the scenario cannot contain. **[PENDING EVTX]** actual 7045 counts and
service names from step 191, to be written into CD-014.

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

**[PENDING EVTX]** Which of the six declared EIDs have real evidence coverage and
which are unit-test-only, from Person A's spike Q7.

**[PENDING EVTX]** `evtx.security` row counts per collection (step 190).
Expected substantial in both clean collections and near-zero in
`collection_s1_v2`, because `wevtutil cl security` was run at
`2026-08-23T23:05:12.794670Z`. That is the expected signature of the scenario,
**not** a parser failure -- the 4688 for `invoice_scan.exe` is destroyed by
design and the ground truth says so.

**[PENDING EVTX]** Which accounts dominate the EVTX rows per collection
(step 192).

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

**Number of downloads in `collection_s1_v2` browser history** -- deferred until
the browser parser exists. The ground truth records one download; whether the
history contains others is unmeasured.
