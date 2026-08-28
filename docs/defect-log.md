# Defect log

One entry per defect. A defect is closed when the behaviour is fixed OR when it
is established not to be a defect; both are recorded, because a defect closed as
"not a defect" is a finding, not an absence of one.

Referenced from `docs/contract-decisions.md` as "the challenges log".

---

## D-013 -- Prefetch naive timestamps: UTC or host-local?

**Status: CLOSED 2026-08-27 -- library returns UTC. No correction applied.**

`windowsprefetch 4.0.3` returns run times as naive strings
(`'2026-08-23 22:57:15.832788'`). A naive value meaning UTC and one meaning
host-local are indistinguishable from the value alone, and the parser attaches
UTC either way. Under this lab's UTC+3 host offset, guessing wrong is a silent
three-hour error that would surface at verification as clock drift rather than
as a parser bug.

Resolved by comparison against ground truth (step 119):

| | |
|---|---|
| Ground truth, Scenario1.md action 2 (Execute) | `2026-08-23T22:57:22.536771Z` |
| Library P5 slot 0 | `2026-08-23 22:57:15.832788` |
| Delta | **-6.70 s** -- not a whole hour |

Confirmed independently of the library by decoding the raw `lastRunTime` bytes
as FILETIME: `134319994358327870` -> `2026-08-23T22:57:15.832787+00:00`, which
matches the library's string to 1 microsecond. The library's `convertTimestamp`
is a bare `datetime(1601,1,1) + timedelta(microseconds=ts/10)` with no `tzinfo`
and no conversion. Host is UTC+3; a localised value would read `01:57:15`.

**Consequence:** `_records` attaches UTC via `replace(tzinfo=UTC)`. Step 144's
offset correction is NOT applied. Confirmed a second time end-to-end at step 166,
where the timeline row for `INVOICE_SCAN.EXE` reads `22:57:15.832788Z`.

The residual seconds are artifact behaviour, not drift: Prefetch writes the run
time when the OS completes the application trace, seconds after the user action.
**Only a whole-hour delta indicates a timezone fault.**

Evidence: `docs/evidence/prefetch-spike-s1v2.txt`.

---

## D-019 -- collection_s1_v2 manifest covers 793 of 817 files

**Status: OPEN -- mitigated, cannot be fully resolved.**

The collection-time manifest omits 24 files (registry hives, transaction logs,
DPAPI blobs, `desktop.ini`). `clean-s1-v2-sha256-supplement.csv` was generated
2026-08-25 from the host copy and covers them, establishing integrity from
receipt onward rather than from collection. The lab VM was decommissioned before
the gap was found, so collection-time hashes cannot be produced. `clean_a` and
`clean_b` manifests are complete, verified by set comparison. See CD-017.

---

## D-021 -- stale file counts in documentation

**Status: CLOSED 2026-08-27.**

`docs/collection-manifest.md` and `docs/lab-setup.md` claimed 876 / 900 / 793
files on disk. Actual: **892 / 916 / 817**. The 793 figure was a manifest ROW
count mistakenly written into a files-on-disk field; row counts remain 892 / 916
/ 793 and are correct where they appear as such. All corrected.

---

## D-022 -- INVOICE_SCAN .pf filename assumed superseded

**Status: CLOSED 2026-08-27 -- NOT A DEFECT.**

Steps 109/114/134 anticipated that `collection_s1_v2` would carry a new Prefetch
hash, superseding `INVOICE_SCAN.EXE-A345C2FE.pf` in the docs. The spike at 117
recorded the actual filename: **`INVOICE_SCAN.EXE-A345C2FE.pf`** -- unchanged.

`groundtruth/Scenario1.md:188` already explains why: the hash portion derives
from the executable's full path, which is identical between collections
(`C:\Users\janed\Downloads\invoice_scan.exe`). No purge was required and none
was performed.

---

## D-023 -- windowsprefetch 4.0.3 misreads runCount on version-30 records

**Status: CLOSED 2026-08-27 -- corrected in the parser adapter.**

The library reads `runCount` at offset `0xD0`
(`windowsprefetch.py:239`), which is incorrect for version-30 records. Measured
across all 835 `.pf` files in the three collections:

| offset | files where `len(timestamps) > runCount` | files reporting 0 runs despite recorded run times |
|---|---|---|
| `0xD0` (library) | **610 of 835** | many, incl. `INVOICE_SCAN.EXE` |
| `0xC8` (corrected) | **0 of 835** | **0** |

`INVOICE_SCAN.EXE` reported `runCount: 0` against an execution confirmed by
ground truth and by its own recorded run time. At `0xC8` it reports `1`.

**Fix:** `_records` reads `0xC8` for version-30 records and falls back to the
library value otherwise. The correction lives inside the library adapter
boundary, so `record_to_events` stays pure. A run count that cannot be read is
omitted from `details` rather than emitted as zero -- zero is a claim the
artifact does not make.

**Contract impact:** CD-018 as originally drafted asserted `Events <= runCount`
holds *because the library drops empty slots*. That reasoning was backwards. The
conclusion (Event count is a lower bound, never a total) is correct, but because
the run-time array is capped at eight slots. CD-018 rewritten accordingly.

---

## D-024 -- zero-filled .pf files counted as parser failures

**Status: CLOSED 2026-08-27.**

Five `.pf` files across the three collections are runs of zero bytes:
`DEFRAG.EXE-738093E8` (clean_a, clean_b) and `SVCHOST.EXE-CE29B0F4` (all three).
Sizes 3664 and 5225 bytes, every byte `0x00`. Both appear in their SHA-256
manifests with real digests, so they were collected and transferred intact --
this is not corruption in transit.

Cause is the same allocated-but-never-flushed condition already documented in
`docs/collection-manifest.md` for the original clean_a's KAPE ConsoleLog: the
filesystem allocated size but contents were never written.

The library raised `AttributeError: 'Prefetch' object has no attribute
'filenameStringsOffset'` on each, which `ingest.py` correctly caught -- but
counted as `files_failed`, breaking the `0 failed` requirement at steps 164/177
and misreporting intact evidence as a parser fault.

**Fix:** `_records` yields no records when the header is entirely zero. An empty
artifact is an absence of evidence, not a failure to read it. The guard is
narrow (all header bytes zero) so a genuinely malformed file still raises and is
counted; a test asserts both behaviours. See CD-020.

---

## D-025 -- Op-*.pf SysMain files silently fabricated events

**Status: CLOSED 2026-08-27.**

`Op-EXPLORER.EXE-7A3328DA-000000F5.pf` exists in all three collections. These
are SysMain operational files with a different internal structure.
`docs/collection-manifest.md` already stated the parser "excludes them by name
deliberately" -- but `can_handle()` returned `True` for them.

Worse than a failure: the library parsed them **without raising** and yielded the
filename fragment `Op-EXPLORER.EXE-7A3328DA` as an `executableName`. The parser
emitted it as a binary with a run time. One fabricated event reached
`outputs/s1v2/timeline.csv` (869 events; 868 after the fix).

A run-summary failure count cannot detect this class of fault, because nothing
fails.

**Fix:** `can_handle()` excludes basenames starting with `op-` (case-folded).
Two parametrised test cases cover it. See CD-020.

---

## D-014 -- ruff I001 on parser registration imports

**Status: OPEN -- anticipated, surfaces at Day 5 integration.**

Two parser registration imports written as separate lines with only
`# noqa: E402,F401` trigger `I001`. Resolution is to add `,I001` to the first
line rather than switching to the parenthesised form, which would turn every
future parser registration into a multi-line merge conflict. Recorded in
`docs/contract-decisions.md` under toolchain rules.


## D-026  NAT asymmetry limitation stated a service-noise direction that the evidence reverses

**Status:** corrected 2026-08-28.

`docs/limitations-week1.md` recorded that the clean collections, collected with
NAT enabled, would carry Windows Update EID 7045 service installations that the
host-only scenario could not. CD-014 carried the same premise.

Measured across all three collections after the EVTX merge: `clean_a` 16,
`clean_b` 16, `collection_s1_v2` 23. The clean collections carry **fewer**, not
more, and their 16 are identical service-for-service. The seven additional
records in the scenario are VirtualBox Guest Additions (`VBoxGuest.sys`,
`VBoxWddm.sys`, `VBoxMouse.sys`, `VBoxSF.sys`, `VBoxService.exe`, `WUDFRd.sys`
and a bare `svchost.exe`). No 7045 in any collection is attributable to Windows
Update.

**Why it mattered.** The limitation as written would have led Week 4 to discount
7045 findings in the baselines as NAT noise, and to treat a scenario-only 7045 as
signal. The real confounder is the opposite and larger: the scenario guest
differs from both baselines by an entire Guest Additions install.

**Fix.** Both the limitation and CD-014 now state the measured direction. The
attack installed no service -- persistence was HKCU Run -- so no 7045 in the
scenario corresponds to `invoice_scan.exe`.

**Found by:** filling the `[PENDING EVTX]` markers with real counts rather than
carrying the predicted ones forward.


## D-027  Scenario persistence predates the scenario download by two days

**Status:** recorded 2026-08-29, not a defect in the pipeline. It is a property
of the evidence that any correlation rule must account for.

The `SecurityUpdate` autorun in `collection_s1_v2` carries a key last-write time
of **2026-08-21T01:34:07.976260Z**. The scenario download it points at is
**2026-08-23T22:20:06.710763Z**. The persistence therefore appears, on
timestamps alone, to have been established two days before the file it launches
was delivered.

### What actually happened

Scenario 1 was attempted three times. Only the third is the run under test.

| Attempt | Downloads | Host | Size | Outcome |
|---|---|---|---|---|
| 1 | ids 4,5,7,8,9 -- 2026-08-20 15:36 to 18:41 | `192.168.50.5:8000` | 201,216 B | transfer faults |
| 2 | ids 10,11,12 -- 2026-08-21 00:04 to 00:52 | `192.168.50.5:8000` | 360,448 B | transfer faults |
| **3** | **id 13 -- 2026-08-23 22:20:06** | **`192.168.50.2:8000`** | **4,608 B** | **the recorded scenario** |

The operator changed the serving host and rebuilt the stand-in binary between
attempts; the three byte counts are three distinct binaries, not one file
re-fetched. The HKCU Run value was written during attempt 2 at 01:34 on 21
August, roughly forty minutes after that attempt's last download.

Restoring the baseline snapshot before attempt 3 did not clear the value: the
`Run` key persisted, and because every attempt wrote the payload to the same
path -- `C:\Users\janed\Downloads\invoice_scan.exe` -- the stale value remained
valid for the new binary and was never rewritten. The artifact is genuine
persistence pointing at the genuine payload; only its timestamp belongs to an
earlier attempt.

### Why this is recorded rather than corrected

The evidence is not edited (see the Week 1 decision on evidence integrity). A
reader meeting a persistence event two days before its download would otherwise
conclude the timeline is wrong, and the correct explanation is not recoverable
from the timestamps alone.

### Consequences

1. **A `presence` event must not be ordered against `recorded` events.** This is
   the concrete case CD-019's third timestamp type exists for. A
   download-to-persistence rule that joins on a time window will either miss
   this chain or, worse, invert it.
2. **Filename is not sufficient as a join key.** Nine earlier `invoice_scan.exe`
   downloads precede the real one. Size and source host separate them: 4,608
   bytes from `192.168.50.2` is the scenario; 201,216 and 360,448 bytes from
   `192.168.50.5` are not.
3. **The clean baselines are unaffected.** Neither `clean_a` nor `clean_b`
   contains any `invoice_scan` artifact, in any family (action 99).

### Also visible in the same window

`VBoxTray` and `SecurityHealth` autoruns carry 2026-08-23T23:13:49.701914Z --
after the log clear at 23:05:06 and before collection at 23:31:48. That is the
Guest Additions install landing inside the collection window, and it is the same
build difference recorded as D-026.


## D-028  Amcache does not corroborate the scenario execution

**Status:** recorded 2026-08-29. Not a parser fault and not fixable.

`invoice_scan.exe` executed at 2026-08-23T22:57:15.832788Z and is recorded in
Prefetch. It has **no Amcache entry**, in `InventoryApplicationFile` or in any
other subkey of `collection_s1_v2`'s `Amcache.hve`. Searched exhaustively by
key name and by every value, not only by path.

The hive is not stale. Its newest `InventoryApplicationFile` entries are the
VirtualBox Guest Additions binaries at 2026-08-23T23:15:02.514594Z -- eighteen
minutes *after* the execution and sixteen minutes before collection. The hive
was being written during the collection window; it simply never recorded this
binary.

**Why.** Amcache is populated by the Microsoft Compatibility Appraiser scheduled
task, not at process start. A binary that runs once and is collected 34 minutes
later can miss the inventory pass entirely. This is normal Amcache behaviour and
is the reason Amcache is evidence of *presence and inventory*, never of
execution timing -- which is why the parser emits `timestamp_type="presence"`.

**Consequences.**

1. A correlation rule requiring Prefetch and Amcache to agree before raising a
   finding would miss the only real detection in the corpus.
2. Amcache's value here is the 878 inventoried binaries in each collection as
   baseline material, plus SHA-1 for entries that do have one -- not as a second
   witness to the scenario.
3. The Week 4 evaluation must not report Amcache as a contributing artifact for
   Scenario 1's execution. It contributes to the baselines only.

Pinned by `tests/test_amcache.py::test_scenario_binary_is_absent_from_amcache`
so the absence is not later mistaken for a parser regression.
