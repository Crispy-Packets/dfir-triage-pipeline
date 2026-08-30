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


## D-029  EID 4720 recorded the creating account but not the created account

**Status:** fixed 2026-08-30 in `parsers/evtx_windows.py`.

The 4720 handler kept `SubjectUserName` and `SubjectDomainName` only. Those name
the account that *performed* the creation. The account that was *created* lives
in `TargetUserName`, which was discarded.

Every account-creation event therefore named the operator and never the new
account. The rows were present and correctly counted -- the defect did not lose
events -- but they were indistinguishable from one another.

### How it surfaced

A-4 requires the account-creation base rate to be measured, so Week 4 cannot
mistake a routine account creation for a detection. Counting was possible; the
purpose was not. Separating four standing lab accounts from one deliberately
staged `testuser` needs the names, and the pipeline could not supply them.

### Fix

`_details_for` now keeps `TargetUserName`, `TargetDomainName`,
`SubjectUserName` and `SubjectDomainName` for EID 4720. All four are declared in
`docs/details-schema.md` per CD-012; `SubjectUserName` had never been declared
at all and now is. Pinned by `tests/test_account_created.py`, which asserts both
that the created account is named and that creator and created stay distinct --
conflating them inverts the finding.

### Not a contract change

`Event.user` still carries `SubjectUserName` for 4720, unchanged. CD-011 defines
`user` as the account responsible for the action, and for an account creation
that is the creator. The created account is a property of the event, which is
what `details` is for.


## D-030  R-ATOMIC-0001's only finding on the scenario collection is a build artefact

**Status:** recorded 2026-08-30, not a defect in the rule or the pipeline. It is
a measured property of the corpus that Week 4 scoring must account for.

R-ATOMIC-0001 fires on EID 4688 process creations from user-writable locations.
Measured base rates: **42 in clean_a, 48 in clean_b, 1 in s1_v2**.

### The one scenario finding is not the attack

The single s1_v2 hit is `DismHost.exe` under `admin_local`'s Temp at
2026-08-23T23:12:52, part of the VirtualBox Guest Additions install that lands
inside the collection window (D-026).

`invoice_scan.exe` does not appear in this rule's output and **cannot**. Every
EID 4688 row in `collection_s1_v2` is timestamped 23:05:06 or later, because the
actor cleared the Security log at 23:05:06.614816Z. The execution was at
22:57:15.832788Z -- eight minutes earlier, inside the destroyed span. The only
surviving witness is Prefetch, which carries a bare executable name rather than
a path (CD-010), so no path-shaped condition can match it.

The rule's `false_positive_notes` predicted the cause of this correctly before
any measurement. It predicted the wrong count: the expectation was silence on
s1_v2, and the measurement is one finding on something unrelated.

### Consequences

1. **A finding count is not a detection count.** On this corpus R-ATOMIC-0001
   produces 90 baseline findings and 1 scenario finding, and the scenario
   finding is a false positive. A model reading "fired on s1_v2" as evidence of
   compromise would be reading a Guest Additions installer.
2. **The anti-forensics worked.** This is the clearest measured consequence of
   the log clear in the corpus: an indicator that should have caught the
   execution has had its evidence deleted. That is worth stating plainly in the
   evaluation rather than presenting the rule as simply ineffective.
3. **Only two atomic rules fire on the actual attack** -- R-ATOMIC-0002 on the
   log clear itself, and R-ATOMIC-0006 on the Run-key persistence.

### Not corrected

The rule is kept as written. The indicator is sound in general and its failure
here is a property of the evidence rather than a fault in the logic. Tuning it
to fire on this corpus would be fitting the rule to one scenario.


## D-031  4104 discarded the script text, which blocked an entire rule

**Status:** fixed 2026-08-30 in `parsers/evtx_windows.py`.

The 4104 handler kept the fragment identifiers and dropped `ScriptBlockText`.
The stated reasoning was that a single block can run to tens of kilobytes, that
`details` is carried in every timeline row, and that the text stays recoverable
from the source record through `source_locator`.

The first two points were sound. The third was true but not sufficient: a rule
evaluates `Event` objects and never reopens the `.evtx`, so "recoverable from
the evidence" does not mean "available to the rule layer". The consequence was
that **no field on `Event` said what a script did**, and R-ATOMIC-0003 -- one of
the six atomic rules the plan requires -- could not be written at all. It was
parked in `rules/blocked/` with three options and a stated preference.

### What the measurement changed

The size objection was tested rather than argued. Across the 3,249 script
blocks in the three collections the distribution is strongly bimodal:

| | value |
|---|---|
| median | 339 bytes |
| p90 | ~15,000 bytes |
| max | 19,919 bytes |

The large blocks are VS Code and PowerShell profile initialisation. The
attack-relevant blocks -- the five `WebClient.DownloadFile` calls that fetch
`invoice_scan.exe` -- are **112 and 113 bytes**.

So the objection holds for benign initialisation noise and not for the text a
detection rule needs. A 4,096-byte cap stores every attack block whole and
truncates only the initialisation blocks: 418 of 1,270 in s1_v2.

### Fix

Option 1 of the three in the draft. `details` now carries:

- `script_block_text` -- capped at `SCRIPT_BLOCK_TEXT_CAP` (4096 UTF-8 bytes),
  truncated on a character boundary so the value is never invalid text
- `script_block_text_bytes` -- the **full** original length, always, so a
  consumer can measure what was not recorded rather than infer it
- `script_block_truncated` -- literal `true`, present only when the cap was hit

All three are declared in `docs/details-schema.md` per CD-012, along with
`ScriptBlockId`, `MessageNumber`, `MessageTotal` and `Path`, which had been
emitted since B-8 without ever being declared -- a CD-012 gap of my own.

### The clause that makes the cap honest

A capped field may be read by **positive operators only**. `not_contains`
against a field holding the first 4 KB of a 20 KB script asserts an absence the
evidence does not support, and would read as a clean negative. That constraint
was Person A's, raised before the field existed, and it is the reason this is a
usable field rather than a misleading one.

### Consequence for the corpus

R-ATOMIC-0003 now measures 3 / 3 / 8 and detects the delivery step that
R-ATOMIC-0001 structurally cannot see (D-030): the 4688 for `invoice_scan.exe`
was destroyed by the log clear, but the PowerShell operational channel was not
cleared, so the download survives there. Scenario 1 now has three independent
surviving witnesses -- R-ATOMIC-0002 on the clear, R-ATOMIC-0003 on the
delivery, R-ATOMIC-0006 on the persistence.

Two alternatives from the draft were dropped after measurement.
`frombase64string` matched 123 blocks in each baseline against 67 in s1_v2 --
Cursor's shell integration encoding environment variables -- so it fired nearly
twice as often on clean hosts as on the scenario and inverted the rule's
discriminating power. `invoke-expression`/`iex` matched 2 against 4, too few to
carry signal. Both are sound indicators in general; they were removed because of
what this corpus measures, and that distinction belongs in the Week 4 write-up.

### Premise corrected

While blocked, the draft recorded that Scenario 1's delivery was "HTTP through
Edge, not PowerShell". The Edge download is real, but PowerShell was also used:
five `DownloadFile` blocks against both attacker hosts between 21:53:19 and
22:16:21 on 2026-08-23, all in evidence.


## D-032  CD-021's environment-variable bucket conflates two path forms

**Status:** recorded 2026-08-30. CD-021's totals are correct; its classification
is not granular enough to build a path canonicaliser against.

Verifying CD-021 against the evidence before starting B-9 reproduced every
headline figure: 55 `service_install` rows, exactly one bare filesystem path
(`C:\Windows\System32\svchost.exe`), 27 quoted-executable-plus-arguments, 7
`\SystemRoot`/UNC device paths, 6 unquoted drive paths with arguments.

The clause records the fifth form as "an environment-variable form such as
`%SystemRoot%` (14)". Measured, that bucket is two different things:

| form | count | example |
|---|---|---|
| environment variable prefix | 4 | `%SystemRoot%\system32\svchost.exe -k print` |
| **root-relative driver path** | **10** | `system32\DRIVERS\RsFx0800.sys` |

The ten are kernel driver images written relative to the system root with **no
prefix at all** -- no drive letter, no leading separator, no variable. The
Service Control Manager resolves them against `%SystemRoot%` implicitly.

### Why it matters for B-9

These two forms need opposite handling in a canonicaliser:

- `%SystemRoot%\...` **is** absolute once the variable is expanded, and the
  variable is explicit in the string, so expansion is a mechanical substitution.
- `system32\DRIVERS\...` looks like a relative path and expanding it requires
  knowing the implicit rule that the SCM applies `%SystemRoot%`. That knowledge
  is a forensic claim about how the value would have resolved, not a fact the
  artifact recorded.

A canonicaliser written from the clause as worded would treat all 14 as
prefixed, find no variable in ten of them, and either emit them unchanged as
though they were already canonical, or fabricate a root. Both are wrong in the
way CD-010 forbids.

### Resolution

CD-021's total and its conclusion stand: `path` is not a join key for
`service_install`, and no normalisation happens in Week 1. B-9 emits **no**
canonical field for any of the 55 rows, which was already the plan; this defect
records why the "expand the variable and you are done" shortcut does not exist
for ten of them. The distinction belongs with Week 3's `core/entity.py`, which
owns executable extraction from command lines.


## D-035  A test fixture emptied the parser registry, silencing later tests

**Status:** fixed 2026-08-30 in `tests/test_fault.py`.

`test_fault.py` injects a deliberately-raising parser to prove that one bad
artifact does not end a run. Its fixture appended that parser to the
module-level registry and tore down with:

```python
parsers._REGISTRY.clear()
```

`clear()` empties the **whole** registry, not just the injected entry. The
fixture's own docstring says "inject a parser that always raises, then remove
it" and warns that the registry is global state, so the intent was correct and
the call did not match it.

### What it silenced

Every collection-backed test that ran after `test_fault.py` in the same session
saw an empty registry. `collect_events` found no parser for any file, returned
zero events, and the tests that iterate over those events passed **vacuously** --
a loop over an empty list asserts nothing.

Alphabetical collection order put `test_fault.py` before `test_ingest.py`,
`test_paths.py`, `test_prefetch.py`, `test_registry.py` and
`test_script_block_text.py`, so their evidence-backed assertions had been
inert for as long as the fixture has existed.

### How it surfaced

A new B-9 test asserted that the Scenario 1 binary is reachable from three
artifact families by one join key. It failed with an empty result set, passed
when run alone, and passed in every pairwise combination tried. Only the full
suite reproduced it -- which is the signature of leaked state rather than a
logic error.

The test was right and the pipeline was right. The harness was wrong.

### Evidence that the fix restored real work

Per-collection suite runtime roughly doubled, from about 13 seconds to about
28, because those tests now parse the collections they always claimed to.

| collection | before | after |
|---|---|---|
| clean_a | 153 passed, 11 skipped | 154 passed, 10 skipped |
| clean_b | 153 passed, 11 skipped | 154 passed, 10 skipped |
| s1_v2 | 1 failed, 157 passed | 159 passed, 5 skipped |

**Fix:** hold a reference to the injected parser and `remove()` exactly it.

### Why this one is worth recording

It is the same failure mode as the rest of this log, one level up: a test suite
that reported success by default. Nothing crashed, nothing was skipped, and the
count of passing tests went **up** while the assertions were doing nothing. A
green suite is evidence only if the tests ran against what they claim to.


## D-036  Loop-only assertions could pass on empty input

**Status:** fixed 2026-08-30 in `tests/test_paths.py`.

Found by a deliberate audit for the D-035 pattern rather than by a failure. A
static scan of all 16 test files for functions whose every assertion sits inside
a `for` loop, with no guard that the loop body runs, returned five candidates.

Three were safe: they iterate module-level constants, which cannot be empty.
Two iterate parsed evidence:

| test | rows examined today |
|---|---|
| `test_original_path_is_never_modified` | 10,438 in `clean_a` |
| `test_no_canonical_field_for_any_service_install` | 10 in every collection |

Both do real work. Neither would have failed if the parsers stopped emitting --
the assertions would simply never execute, and the suite would go green. That is
precisely how D-035 stayed hidden.

**Fix:** both now count what they examined and assert a floor. The service test
asserts exactly 10, the figure CD-021 and D-032 fix; a drop to zero means the
parser stopped, not that the contract started holding.

Not a defect that ever produced a wrong result. Recorded because the audit is
the point: the same shape has now caused one real failure (D-035) and been found
twice, so it is worth checking for deliberately.


## D-037  Root-only paths produced a canonical form with no join key

**Status:** fixed 2026-08-30 in `paths.py`.

`derive("C:\\")` returned `{"path_canonical": "c:\\"}` and no basename. A root
names a directory, not a file, and every consumer of these fields is asking
about a binary -- so a drive root would have entered the pipeline as a canonical
path carrying no join key.

Found by probing inputs the corpus does not contain. Zero occurrences across all
three collections, so the gate could never have caught it, but a Startup folder
entry or a service with a directory `ImagePath` produces one and the failure
would be silent.

**The first fix was wrong**, which is worth recording. It tried:

```python
if not text.rstrip("\\/").rstrip(":"):
```

`"C:\\".rstrip("\\/")` is `"C:"`, and stripping the colon leaves `"C"`, which is
truthy. Trailing-character stripping cannot express "is this only a root". The
working check matches the shape explicitly, with the reason recorded beside it
so the same wrong simplification is not reintroduced.

Also probed and correct without change: UNC paths, paths with trailing
whitespace, unicode path components, extensionless files, and command lines
using forward slashes. Those are now tests.


## D-038  Isolation Forest cannot honour contamination on tied data

**Status:** recorded 2026-08-30, not a defect. A property worth knowing before
it is mistaken for one.

An audit check asserted that the training-set outlier rate should land near the
configured contamination of 5%. On a synthetic fixture of 100 rows drawing from
9 distinct feature values it came out at **1.0%**, which reads as a
misconfiguration.

It is not. Isolation Forest scores by how few splits isolate a point, and
identical points cannot be separated from one another, so with heavy ties the
model cannot produce a 5% tail however it is configured.

On real evidence the rate tracks the setting closely, per family:

| family | n | training outlier rate |
|---|---|---|
| `amcache` | 830 | 5.06% |
| `evtx.powershell` | 997 | 3.71% |
| `evtx.security` | 10,439 | 5.00% |
| `prefetch` | 1,248 | 5.05% |

`evtx.powershell` sits low for the same reason in milder form: its rows carry no
run count and no path, so many are identical in feature space.

The consequence for interpretation is that **the outlier rate is a floor, not a
guarantee**, and a family whose rows are largely identical will report fewer
outliers than configured. Not something to tune away -- the alternative would be
flagging arbitrary members of a tied group.

