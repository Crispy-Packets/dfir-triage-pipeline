# Defect log

One entry per defect. A defect is closed when the behaviour is fixed OR when it
is established not to be a defect; both are recorded, because a defect closed as
"not a defect" is a finding, not an absence of one.

Referenced from `docs/contract-decisions.md` as "the challenges log".

---

## Pattern: a verification that cannot fail on the thing it checks

Not a defect entry. A class this project has now hit four times, recorded here
because the individual entries do not look alike and the class does.

A check is written, it passes, and its passing is taken as evidence. The check
never had the power to fail on the claim being made. The result is worse than
no check, because a green result is read as a measurement.

**Four forms, each with its instance here:**

| form | the check examines | instance |
|---|---|---|
| **vacuous** | nothing at all | **D-061** — four grammar-invariant tests that would have passed on an empty rule set. **D-059's own audit, v1** — matched `_CHANNELS` fragments against `path.name`, found zero curated files, passed in 0.10s |
| **partial** | some of the population, silently skipping the rest | **D-054** — the CD-007 loader's regex read 30 of 58 event types, because a multi-value line matched once. The vocabulary looked complete |
| **wrong target** | something adjacent to the claim | **D-067's first check** — called `_details_for` directly, which BYPASSES the gate it was meant to verify, and covered 7 of the 19 relevant EIDs. It measured the pre-gate world and reported on the post-gate one |
| **out of scope** | correctly, but the claim is outside what it can see | **D-066** — the D-059 audit finds EIDs *absent* from a curated map. EID 4 was present and mapped to the wrong meaning. A wrong label is invisible to a coverage audit |

**The discipline.** A check earns trust only once it has been shown capable of
failing. In practice, one of:

1. **Run it against a known-bad input** and watch it fail before trusting a
   pass.
2. **Assert a minimum amount of work done** — `test_curated_eid_coverage.py`
   asserts `audited >= 5` for exactly this reason, and
   `test_ruleset_agrees_with_validator.py` asserts `len(rules) >= 10`.
3. **Route the check through the same code path the claim is about.** D-067's
   second attempt called `record_to_event`'s real gate rather than the helper
   beneath it, and could therefore have come back non-zero.
4. **State the scope the check does NOT cover**, so the next person does not
   read it as broader than it is. D-059 now says in both the entry and the
   test's docstring that it cannot verify a mapping is *correct*.

**The same failure occurs in prose, not only in tests.** On 2026-09-19 the
claim *"both scenarios ran PowerShell with `-ExecutionPolicy Restricted`"* was
written into six documents and two commit messages. It had been inferred from
one screenful — `Bypass` counted zero on `s1_v3`, and the top values there were
`Restricted` — with no row ever joined to the attack. Measured, the two
`Restricted` strings are byte-identical Windows servicing scripts present on
all five collections, and the scenario's PowerShell was interactive with no
flags at all. A reading in the right direction is not a measurement, and the
check for prose is the same: *what command established this, and could it have
come back the other way?*

Related: **D-060** (a stated gap outliving the work that closed it) is the
same disease in the documentation layer — a claim that was true when written
and that nothing re-checked.

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

## D-039  A family's feature vector collapsed to a handful of distinct rows

**Status:** found and fixed 2026-09-13.

`features.build` emitted one fixed column layout for every event whatever
artifact produced it. For `browser` rows that meant **86 downloads in `s1_v3`
produced 8 distinct feature vectors**, and 62 downloads in `clean_c` produced 4.

Six of the ten columns were execution-specific -- `run_count`,
`run_count_is_known`, `seconds_since_previous_run_of_same_executable`,
`previous_run_is_known` -- and a download has never run, so all four were 0.0 on
every row. `path_depth` was 4.0 and `path_is_user_writable` 1.0 on every row,
because every download lands in `Downloads\`. Only the hourly-density pair
varied, so the model's entire view of a download was *how many other downloads
happened that hour*.

Nothing failed. The model fitted, scored, and returned percentiles that looked
like a ranking. A split-half check on `clean_c` measured overlap **0.378**
between the two halves of one clean collection, against the >0.80 the B-12
acceptance test requires of two different collections -- the clearest sign that
the family was not being modelled at all.

**This is D-038 seen from the other side.** Isolation Forest cannot isolate
identical rows; D-038 recorded that as an outlier rate below the configured
contamination, and this is the same cause producing a meaningless ranking.

Two fixes, both measured before implementation:

1. The parser already recorded `bytes` and `mime_type` into `details` and
   neither reached the feature table. `download_size_log10`,
   `download_size_is_known` and `mime_type_is_executable` were added, then
   `filename_length` and `filename_entropy`.
2. `FAMILY_FEATURES` restricts each family to the columns its records can
   populate (`docs/per-family-features.md`, argued and committed before the
   implementation).

Browser went from 8 distinct vectors to **84 of 86 rows**. The attack entity's
rank went 116/525 to 40/525.

**What to watch for elsewhere.** Any new artifact family will inherit the same
problem unless its feature set is considered when the parser lands. The
diagnostic is cheap: build the table for one family and count
`len(set(table.rows))` against `len(table.rows)`. A ratio far below 1.0 means
the family is not being modelled, whatever the scores look like.

---

## D-040  A rule could not distinguish a payload from a system binary

**Status:** found and fixed 2026-09-13. Schema 1.5.0.

`R-CORR-0003` joins an execution to a Run key naming the same executable and
reports it at `critical`, weight 85. Its conditions could only compare a field
to a literal or a regex, so it had no way to tell
`C:\Users\...\Downloads\invoice_scan.exe` from
`C:\Program Files (x86)\...\msedge.exe`.

Measured: **five findings at `critical` on collections containing no attack** --
`msedge.exe`, `onedrive.exe`, `securityhealthsystray.exe`, `onedrivesetup.exe`
and a `cmd.exe` RunOnce uninstaller. The count was identical across `clean_a`,
`clean_b` and `s1_v2`: the scenario added one true positive and removed one
benign one, and the total did not move.

The rule's own `expected:` note had already identified this on 2026-08-30 and
had explicitly rejected the obvious fix -- suppressing those binaries by name --
as corpus-fitting that would not survive a different estate. That rejection was
correct and is not overturned.

**The fix is a shape predicate.** `is_user_writable` names no binary; it asks
where one lives, which is a property of the finding rather than of this lab, and
would behave identically on an estate this corpus has never seen. It is the same
reasoning `features.py` uses for `path_is_user_writable`, and the two layers
share the marker list so the rule engine and the anomaly layer cannot disagree
about the same path.

**The subtle part is the ordering.** System locations are tested first.
`C:\Program Files\Common Files\Users Guide\` contains the substring `users`,
and checking the writable markers first would call a Program Files path
user-writable. `tests/test_shape_operators.py` pins it.

Effect: `clean_a` 5 -> 1, `clean_b` 5 -> 1, `s1_v2` 5 -> 2, with
`invoice_scan.exe` retained in both scenario collections. The survivor on each
clean host is per-user OneDrive under `AppData\Local` -- a genuine
user-writable autorun, structurally identical to the attack, and the honest
limit of the indicator. **Better, not fixed.**

---

---

## D-041  Every SAM account resolved as `RID-nnnn`, and nothing raised

Found 2026-09-17, during the first measurement of the SAM parser.

`_names_to_rid` reads the `Names` subkey, whose layout is unusual: each account
is a **subkey named after the account**, and the RID is held in the default
value's **type field** rather than in its data. The value's data is unrelated
bytes; reading it resolves nothing.

The parser checked `isinstance(rid, int)`. **regipy returns that field as a
decimal string** — `'500'`, `'1000'` — because the RID is not one of the `REG_*`
constants the library can name, so it falls back to `str()`. The check rejected
every account, the map came out empty, and the parser fell through to its
`f"RID-{rid}"` branch on all seven accounts of every hive.

**Why it was not caught by the code:** the output was well-formed and true.
`RID-1000` is a correct identifier for that account. Nothing raised, no field
was missing, and the event count was right. Only reading the measurement output
beside the probe output — which had listed `Administrator`, `janed`,
`admin_local` by name — showed the names had been dropped.

**Effect on rules.** `Event.user` is a join key (`entity.user`, the only
joinable identity field besides `entity.exe_name`), so a `sam` step would have
joined on `RID-1000` and a Security 4624 step on `vboxuser`. Every correlation
across the two would have matched nothing, silently, and the base rate would
have measured 0 — indistinguishable from "this does not happen".

**Fix:** `_coerce_rid` accepts an int or its decimal text, and rejects `bool`
explicitly (`bool` subclasses `int`, so `True` would otherwise coerce to RID 1).
Which form arrives is a library detail that may change; both are handled rather
than pinned to the one observed.

Guarded by `TestCoerceRid` and by `test_accounts_are_named_not_numbered`, which
asserts no user string begins with `RID-` and names the offenders when it fails.

**Same class as D-023** (`windowsprefetch` misreading `runCount` at the wrong
offset on all 835 `.pf` files): a library returned something plausible, the
parser accepted it, and only a measurement against known ground truth exposed it.

---

## D-042  The SAM event timestamp restated the last-logon time and mislabelled it

Found 2026-09-17, in the same measurement.

The parser first timestamped each account event with the user key's last-write
time and labelled it `presence`, by analogy with the registry Run keys (D-027).

Measured across all five collections: **the key's last-write time is exactly the
last-logon FILETIME** on every account with a non-zero logon count, because
Windows rewrites the user key on each logon. The event was therefore carrying
one fact twice, and `presence` understated what the artefact actually records —
SAM knows *when* the account last authenticated, and the event said only that
the account exists.

**Fix:** an account that has logged on carries the logon time with
`timestamp_type=last_run`; one that never has falls back to the key write and
`presence`, which is then the correct label because no logon time exists.

**Consequence for the rule schema.** `sam` is the first family whose
`timestamp_type` varies by record, so the static `TIMESTAMP_TYPE_BY_ARTIFACT`
map can state only the dominant case. `MIXED_TIMESTAMP_TYPE` now names such
families, and `validate_rules.py` rejects a windowed step selecting one unless
it excludes the never-logged-on records (`details.last_logon not_equals never`,
or the equivalent in a `none` group).

Without that guard a `sam` step would pass the existing presence check on the
strength of its dominant mapping, while still admitting records whose timestamps
cluster at image-build time — producing correlations with whatever else happened
during Windows setup. CD-019 records the amendment.

---

## D-043  An ESE `DateTime` column arrived as raw float64 bits in an int

Found 2026-09-17, probing `SRUDB.dat` before writing the SRUM parser.

`dissect.esedb` declares SRUM's `TimeStamp` column `JET_coltyp.DateTime` and
returns `4676592689485971456`. The declared type invites the assumption that the
value is a converted datetime, or failing that a tick count in some epoch.

It is **neither**. The int is the raw 8 bytes of an OLE automation date — a
float64 counting days from 1899-12-30 — delivered without reinterpretation.
The bits must be re-read as a float:

    struct.unpack("<d", struct.pack("<Q", 4676592689485971456))[0]
      -> 46274.1875 days
      -> 1899-12-30 + 46274.1875 days = 2026-09-09T04:30:00Z

**Why it would not have been caught.** Dividing by any plausible tick scale
yields a number, `datetime` accepts it, and every event lands consistently about
148 million years from now. No exception, no null, no failure count: the CSV
would be internally consistent and uniformly wrong. Sorting still works. Only
comparing an event against a known collection window exposes it.

**Fix:** `ole_timestamp` reinterprets the bits, rejects NaN and infinity, and
rejects any result outside 1995-2100 rather than clamping it — a timestamp the
parser cannot vouch for is an absence, and a clamped one is invented. A real
`datetime` is passed through unchanged, so a future `dissect` release that
converts the column itself does not break the parser.

Guarded by `TestOleTimestamp`, which pins the exact measured int against the
exact measured time, and by `test_timestamps_land_in_the_collection_window`.

**Third in the family with D-023 and D-041**: a library returned something
plausible, the parser accepted it, and only measurement against ground truth
exposed it. The pattern is now explicit in the parser-writing sequence — probe
the bytes, then write.

---

## D-044  The first explanation for SRUM's missing scenario binary was wrong

Recorded 2026-09-17 because the error is instructive, not because code changed.

`invoice_scan.exe` appears nowhere in SRUM on `s1_v3`. The explanation reached
for first, and measured: SRUM's last flush was **11:48:00** and the payload ran
at **11:50:09**, so zero rows exist at or after the execution for any program.
True, and it looked complete.

`s1_v2` refutes it as a general claim. There SRUM flushed **325 rows after** the
22:57:15 execution and the binary is *still* absent. Had only `s1_v3` been
checked, the write-up would have carried a confident single-cause explanation
that the other scenario collection contradicts.

The measured cause on `s1_v2`: SRUM **samples running processes** rather than
recording starts. It does name short-lived user binaries elsewhere on that host
(49 rows under `\Users\`, including installers in `AppData\Local\Temp`), so the
barrier is not that user programs are ignored — it is that every program SRUM
names ran long enough to cross a sampling interval, and the payload exits
immediately.

Both causes are recorded, and the duration limit is now a "cannot attest" clause
in the attestation matrix rather than a note about one collection. **A limit
established on one collection is a hypothesis; the second collection is the
test.**

---

## D-045  Four task definitions raised because `<Date>` carried a UTC offset

Found 2026-09-17, on the first ingest run with the scheduled-task parser.

    parser scheduled_tasks failed on
      C/Windows/System32/Tasks/Microsoft/Windows/Multimedia/SystemSoundsService
      ValueError: timestamp must be UTC (zero offset), not a local offset

`parse_registration_date` attached UTC to a naive value -- D-013's decision, and
correct -- and passed an already-aware value straight through. `<Date>` is
usually naive, so the offset-bearing case was never exercised until real files
were read.

Measured across four collections: **86 naive, 4 offset-bearing, none with `Z`**.
The offset ones read `2005-06-23T13:48:00-08:00`.

**The two cases need OPPOSITE handling, which is why this is a decision rather
than a coercion.** A naive value is the subject machine's wall clock with no
zone stated, so UTC is attached; converting would apply the analyst's zone to
the subject's clock. An offset-bearing value DOES state its zone, so it is
converted, which preserves the instant -- attaching UTC instead would silently
move the event eight hours and nothing would raise.

**CD-019's validation caught it.** `Event.__post_init__` rejects a non-zero
offset outright, so the parser failed loudly on one file per collection rather
than emitting five events an hour off. This is the contract working as intended:
the failure count named the file, and `RunStats.failures` carried the reason.

Effect: `s1_v3` 221 events with 1 failure -> **222 events, 0 failures**.

Guarded by `TestParseRegistrationDate::test_every_result_is_zero_offset`, which
asserts the property CD-019 enforces rather than the four values observed, and
by `TestOffsetRegression`, which pins the literal failing string and checks the
instant is preserved rather than merely stripped.

---

## D-046  `can_handle` dropped five real tasks by testing for an extension

Found 2026-09-17, before the parser ran -- caught by checking the corpus rather
than by a failure.

Task definitions carry no file extension, so the first `can_handle` rejected any
name containing a dot. Measured: **5 of 220 names on `s1_v3` contain one**.

    GoogleUpdaterTaskSystem152.0.7933.0{170F6A46-...}
    .NET Framework NGEN v4.0.30319
    .NET Framework NGEN v4.0.30319 64
    .NET Framework NGEN v4.0.30319 64 Critical
    .NET Framework NGEN v4.0.30319 Critical

Four of them BEGIN with a dot. All five are ordinary tasks.

**Why it would not have been caught by the run.** A file `can_handle` rejects is
counted as SKIPPED, not failed. The run summary would have reported 215 handled
and 5 skipped with no error, and 215 task events is a plausible-looking number
against a directory nobody counted. The same shape as D-025 in reverse: there
the filter was too loose and fabricated records, here too tight and silently
dropped them.

**Fix:** reject by known non-task names (`SA.DAT`, `desktop.ini`, `Thumbs.db`)
and by the legacy `.job` binary format, rather than by "has a dot". `parse` also
checks the root element is `Task`, because a name-based filter cannot know what
a file contains.

Guarded by `test_every_file_on_disk_is_handled`, which asserts `can_handle`
accepts all 220 files actually present and names any it rejects.

---

## D-047  A second parser for NTUSER.DAT would never have run

Found 2026-09-17, before the parser ran -- caught by reading `find_parser`
rather than by a failure.

`ntuser_explorer.py` was written as a normal parser class with `can_handle`
matching `*/ntuser.dat` and a `register()` call at the bottom. That is the
pattern every other parser in this pipeline follows, and here it silently does
nothing:

    def find_parser(relative_path):
        for parser in _REGISTRY:
            if parser.can_handle(relative_path):
                return parser        # THE FIRST match, and only the first
        return None

`registry.py` is imported earlier in `parsers/__init__.py` and already claims
NTUSER.DAT for the Run/RunOnce keys. The new parser would have sat in the
registry, matched nothing, and produced zero events -- with no error, no
failure count, and a passing test suite, because every unit test called the
class directly rather than going through dispatch.

**Fix:** `registry.RegistryParser.parse` delegates to
`ntuser_explorer.explorer_events`, which is a plain function rather than a
registered parser. The modules stay separate because they answer different
questions -- what persists versus what this person did -- and neither set of
decisions should have to be read to understand the other.

`explorer_events` declines quietly on any path that is not an NTUSER.DAT,
because `registry` also hands it SOFTWARE hives.

Guarded by `test_the_registry_parser_owns_the_file`, which asserts through
`find_parser` that `registry` is the parser NTUSER.DAT dispatches to -- the
property that makes delegation necessary -- and by
`test_a_non_ntuser_path_yields_nothing`.

**The general hazard:** a registry keyed on first-match makes "one file, several
families" an ordering problem. The SYSTEM hive (three families) and SRUM (two)
avoided it by emitting everything from one parser. This is the first case where
the families genuinely belonged in separate modules.

---

## D-048  A validator guard no rule could ever satisfy

Found 2026-09-17, on adding `userassist` to `MIXED_TIMESTAMP_TYPE`.

D-042 introduced a check: a windowed step selecting a family whose
`timestamp_type` varies by record must exclude the records that carry a key's
last-write time rather than an observation. For `sam` that is spelled

    details.last_logon not_equals never

`userassist` has the same mixed shape -- a real FILETIME gives `last_run`, a
zero falls back to the key write and gives `presence` -- so it was added to the
same set. But **UserAssist's presence records carry no `last_logon` field at
all**, and no other detail distinguishes them. The guard was therefore
unsatisfiable: every windowed `userassist` rule would be rejected, with no
wording that could make it pass.

An unsatisfiable guard is not a safety property. It is a family that silently
cannot be used, and the error message would have told the rule author to add a
condition that does not exist.

**Fix:** `_excludes_never_used` accepts the GENERAL form --
`timestamp_type equals last_run` in `all`, or `timestamp_type equals presence`
in `none` -- alongside the two `sam`-specific spellings. The general form works
for any mixed family, present and future, because `timestamp_type` is the field
the distinction is actually made on.

**Worth stating as a rule:** when a check is extended to a second family, check
that the second family can satisfy it. The first family's spelling is not
evidence that a general property was expressed.

---

## D-050  A generator holding a file descriptor exhausted the process limit

Found 2026-09-17, when the full suite began failing with 15 errors after the
browser-profile parser landed.

    OSError: [Errno 24] Too many open files:
      '%USERPROFILE%\dfir-evidence\collection_s1_v3\C\$Extend\$J'

**The failure surfaced in the wrong parser.** Every reported failure was in
`test_usn_journal.py`, which opens one file with `read_bytes()` and holds no
descriptor at all. It failed because it happened to be the next thing to open a
file after the limit was reached.

**The cause was two parsers and one test-suite habit, compounding.**

`timeline.py` and `srum.py` both had this shape:

    def _rows(abs_path):
        connection = sqlite3.connect(...)      # or abs_path.open("rb")
        try:
            yield from connection.execute(...)
        finally:
            connection.close()

`yield from` inside `try/finally` holds the descriptor open for as long as the
CALLER takes to consume the generator -- and the caller is itself a generator
feeding a whole ingest run. The `finally` does not run until the outer
generator is exhausted or collected.

That alone was survivable. What made it fatal is that the suite called
`collect_events` **65 times across 22 test bodies**, each walking an entire
collection and opening every SQLite and ESE file in it. As parsers accumulated,
the descriptor count per walk grew until the limit was hit mid-run.

**Fixes, all three:**

1. `timeline._rows` fetches eagerly with `.fetchall()` and returns a list; the
   connection closes before the function returns.
2. `srum.parse` collects into a list inside the `with` block and yields from
   the list afterwards, so the handle closes when reading finishes.
3. `tests/conftest.py` gained `cached_collect_events`, which memoises the
   ingest per collection for the session. Five walks instead of sixty-five.

**The suite went from 8m13s to 1m46s** as a side effect, which is the clearer
signal that re-ingesting per test was wrong regardless of descriptors.

**The general hazard:** `yield from` inside a resource-holding `try/finally` is
not equivalent to reading the resource and yielding afterwards. It looks
correct, it passes in isolation, and it fails only under concurrency with other
resource holders -- reported at whichever unlucky caller asks for the next
descriptor.

---

## D-051  The textbook timestomping indicator fires on 27% of a clean host

Found 2026-09-17, on the first measurement of the `$MFT` parser.

`$STANDARD_INFORMATION` timestamps are settable through a documented API;
`$FILE_NAME` timestamps are not. A file whose `$SI` creation PRECEDES its `$FN`
creation has therefore been backdated -- this is the standard NTFS
anti-forensics indicator, and it was implemented here as a `si_precedes_fn`
detail.

Measured before the rule that would have consumed it was written:

    collection_s1_v3    94,262 of 351,088 records    27%
    collection_clean_c  99,955 of 287,983 records    35%

The same files lead both lists: `$Recycle.Bin`, `PerfLogs`, `Program Files`,
`Common Files`, `microsoft shared`, `en-US`.

**The cause is ordinary and universal.** A file laid down from a Windows
install image carries the image's `$SI` and receives a fresh `$FN` when it is
written to this volume. That describes every OS file on every Windows machine.
Refining by "unique `$SI` value" did not help either: 96,343 of the 99,955 on
`clean_c` have a non-shared `$SI`, because the image's files were built at
many different times.

**An indicator with a 27% base rate on a collection containing no attack is not
an indicator.** Shipping it would have attached a `timestomped` detail to a
third of the filesystem, and any rule reading it would have fired constantly.

**Fix:** the flag is not emitted. Both timestamps ARE emitted as details, so an
analyst can make the comparison against a specific file of interest; the
pipeline does not make the claim wholesale. The parser carries the measurement
at the emission site so the next person to reach for the indicator sees why it
is absent, and `test_no_timestomping_verdict_is_emitted` pins the absence.

**This is the rule the project already had, applied to a derived signal rather
than to a base rate**: measure before asserting. The difference here is that
the assertion would have been a per-event detail rather than a rule, which is
exactly where an unmeasured claim is easiest to ship unnoticed.

---

## D-052  Two files were called unparseable without the claim being tested

Found 2026-09-17, when the assessment was challenged.

Three files were reported to the user as "not parseable", with a reason given
for each. Two of the three reasons were wrong, and neither had been tested --
both judgements came from reading a header, not from attempting a parse.

**`$LogFile`** was dismissed because its first four bytes are `RSTR`, a restart
area rather than a record signature. Measured: **16,382 `RCRD` pages, 4001 of
4001 sampled with a valid update sequence array, zero torn**, and the string
`invoice_scan` present seven times. The page structure is the same shape `$MFT`
uses -- a format this pipeline already parses.

**`$T`** was dismissed as "TxF metadata, no per-file records". Measured:
**147,668 printable characters of Component Based Servicing XML**, naming
KB5033052, 47 component version changes and 2 deployment installs.

**`MpWpp*.bin`** was the one correct dismissal, and testing it produced a
better reason than the original guess: no ETW marker, and the only readable
strings are the filename and a timezone reference. The payload is keyed to a
TMF schema absent from the collection.

**The failure mode is specific and worth naming.** Every other wrong claim in
this project was a number asserted without measuring. This was a
CAPABILITY claim asserted without attempting -- "I cannot parse this" reads as
a technical limit, so it invites no verification, while functioning exactly
like an unmeasured base rate. The standing rule now covers both: measure before
asserting a number, ATTEMPT before asserting an inability.

**Two further errors inside the fix**, recorded because they show the same
pattern at smaller scale:

Recovering names from `$LogFile` produced truncated fragments, because the
length/namespace byte pair that marks a `$FILE_NAME` also matches at offsets
INSIDE a long name -- UTF-16 puts a zero high byte after every ASCII character,
and 0 is a valid namespace. Two byte-level filters were written to reject
them. **Both were reasoned from what the bytes ought to look like, and both
changed nothing** -- the output was byte-identical each time.

The rule that worked was derived from the OUTPUT instead: a genuine filename is
not a strict suffix of another genuine filename on the same page. 1,496 of
18,534 removed, 8%, with no scenario name shadowed. Cross-page fragments
survive, and rather than guess a third time that limit is stated in the
parser's docstring and pinned by a test.

`$T` likewise defeated three attempts to parse it as XML: the declaration
starts at byte 3, TxF injects 290 pairs of `\x01\x00` mid-attribute, and
removing them still leaves a document `ET.fromstring` cannot balance. It is
recovered by pattern, and the docstring says it is never parsed as a tree.

---

## D-053  `immutable=1` hid every uncommitted row, and the absence looked like evidence

Found 2026-09-17, when the user challenged the "SQLite journals are not
evidence" exclusion.

`timeline.py` opened `ActivitiesCache.db` with `immutable=1`, which is the
correct flag for reading evidence in place: it prevents SQLite replaying the
write-ahead log, so the collected file is never modified (CD-016).

**It also ignores the WAL entirely**, and the WAL is where the newest rows live.

    collection_s1_v3, vboxuser
      rows with the WAL ignored    182
      rows with the WAL replayed   205      23 rows only in the log

    collection_clean_b, admin_local
      database  4,096 bytes, EMPTY
      -wal      1,734,552 bytes, 17 activities including notepad.exe

**The second case is the serious one.** `admin_local`'s database is genuinely
empty, and this project recorded the conclusion that followed: "an account that
logged on but never used the Activity Feed". A test asserted it. The docstring
explained it. It was wrong -- the account used the feed normally and none of it
had been checkpointed.

An unread WAL does not produce an error or a gap. It produces a SMALLER,
INTERNALLY CONSISTENT answer that invites a confident wrong conclusion.

**Fix:** the database and its `-wal`/`-shm` are copied to a temporary directory
and opened normally THERE, so SQLite performs the recovery on the copy. The
originals are only ever read -- verified by hashing both before and after a
parse, unchanged. A collection with no `-wal` behaves exactly as before.

**Scope check done 2026-09-17, and the browser parsers are NOT affected.**
Every database the pipeline queries was counted both ways -- `immutable=1`
against a copy with its journals replayed -- across all five collections and
all seven queried tables. **Zero differences.**

The reason is structural rather than luck, and is pinned by
`tests/test_sqlite_journal_coverage.py` so it does not have to be re-derived:

    browser profiles   `-journal`, 8,720 bytes   ROLLBACK journal
    ActivitiesCache    `-wal`, up to 1.8 MB      WRITE-AHEAD log

A rollback journal holds UNDO data for a transaction that may be aborted;
nothing committed waits in it, so ignoring it loses nothing. A WAL holds rows
that ARE committed but not yet checkpointed. The two are not interchangeable,
and `immutable=1` is safe against one and blinding against the other.

The test fails loudly if a browser profile ever switches to WAL mode, which is
the condition that would make this conclusion stale.

**Same family as D-051 and D-052.** D-051 was a derived signal asserted without
measuring; D-052 was a capability asserted without attempting; this is a
NEGATIVE RESULT asserted without checking whether the reading method could see
the data. All three produce output that looks correct.

## D-054  Twenty-eight event_types CD-007 documented were invisible to the validator that enforces CD-007

Found 2026-09-17, at the start of the rules-coverage phase, before any rule was
written against the 31 families added this session.

`rules/validate_rules.py` builds its `event_type` vocabulary by regex over
`docs/contract-decisions.md`: `r"->\s+(\S+)\s+(\S+)\s*$"`, one token for the
artifact and one for the event_type, anchored to the end of the line. It
existed to read the vocabulary FROM the contract rather than duplicating it —
the intent recorded when CD-007 was first written.

Every mapping this session added that named MORE THAN ONE event_type on a line
failed to match, silently. Not an error: the regex simply produced no capture
for that line, and the loader moved on. `load_cd007_event_types` returns a
`set`; a value never added is indistinguishable from a value that was never
meant to exist.

Confirmed by calling the loader directly rather than reading the regex and
guessing: vocabulary size was **30** before the fix. Cross-checked against
every literal string parsers actually pass as `event_type=`, twenty-eight were
missing, all of them from a multi-value line:

    app_opened / app_engaged                    (timeline)
    file_created / file_deleted /
      file_renamed_from / file_renamed_to        (usn -- file_deleted alone
                                                   happened to predate this and
                                                   was already in the 30)
    page_visited / dom_storage /
      background_transfer                        (webcache)
    servicing_pending / component_version_change  (txf_pending)
    process_exec / file_reported /
      scan_skipped / av_service_started           (defender_mplog)
    400 ps_engine_start, 403 ps_engine_stop,
      600 ps_provider_start                       (evtx.ps_classic)
    1116 malware_detected, 1117 malware_remediated,
      5001 defense_disabled, 5007 defense_configured  (evtx.defender)
    811, 812 logon_ui                             (evtx.winlogon)
    2004/2005/2006/2033 rule added/changed/
      deleted/all deleted                         (evtx.firewall)
    3, 4, 59, 60 job created/cancelled,
      transfer started/completed                  (evtx.bits)

**Every rule ever written against any of these event_types would have failed
`validate_rules.py` with `event_type 'app_engaged' is not in CD-007` —**
wrong, because CD-007 does document it, in prose a human reads correctly and a
regex anchored on `\S+\s*$` does not. The validator would have reported a
correct-shaped rule as broken, and the fix a person reaches for first is to
loosen the regex or hand-add an exception, which is how a vocabulary drifts
from its source document. Caught here because the coverage inventory for the
rules phase started by calling the loader and printing its result, rather than
assuming CD-007's prose was sufficient because the doc read correctly.

**Fix:** every multi-value CD-007 line was split into one `-> artifact
event_type` line per value — the format the first six mappings already used,
and the only format the regex was ever built to parse. No prose was changed,
only the tabular lines. Re-run: vocabulary size **58**, matching every
event_type string a parser emits with two exceptions (`file_modified` and
`log_ahead_of_hive`, both confirmed to be `details` keys, not event_types, by
grep against the parser source — correctly absent).

**Same family as D-050 through D-053: a mechanism that looks correct because
its narrow success case was the only one exercised.** The first six mappings
in CD-007 were all single-value and the regex was written and tested against
them; every mapping added after inherited a format the regex was never
extended to parse, and nothing failed until a rule tried to select on one of
the missing values.

## D-055  `evtx.ps_classic` was taken for a field it never extracts

Found 2026-09-17, while measuring which families could widen R-ATOMIC-0003's
`select`.

CD-007 states the reason this channel was added, explicitly:

> `evtx.ps_classic` closes a gap the attestation matrix has carried as stated
> since it was written: EID 600 holds HostApplication, the full command line
> of the process that started PowerShell, and it is present when script-block
> logging is off and 4104 holds nothing.

`_details_for()` in `evtx_windows.py` has branches for 4624/4625, 4688, 4720,
1102, 7045, 4104, 5861 and 21/25. **There is no branch for 400, 403 or 600**,
so `keep` falls through to the empty tuple and every `ps_classic` row is
emitted with `details == {}`. Measured on `s1_v3`: **0 of 203 rows carry any
details at all.** `HostApplication` appears nowhere in the parser source.

The field is really there. Confirmed by reading a raw record rather than by
trusting either the doc or the parser:

    <EventID Qualifiers="0">600</EventID>
    ...
      HostName=ConsoleHost
      HostVersion=5.1.19041.2673
      HostApplication=powershell.exe -ExecutionPolicy Restricted
                      -Command Write-Host 'Final result: 1';

160 EID 600 records on `s1_v3`, in
`C/Windows/System32/winevt/logs/Windows PowerShell.evtx`.

**The channel delivers an event_type and a timestamp and nothing else.** It
attests that PowerShell ran, which `evtx.powershell` and `ps_history` already
attest; the one thing it was taken to supply — the command line that survives
when script-block logging is off — is parsed away. A rule written against the
stated justification would find nothing to read.

Note on the measurement itself: the first scan for these records returned
**zero on all five collections** and was WRONG. `rglob("Windows PowerShell.evtx")`
from the collection root found nothing, while the parser reported 160 rows
from the same collection. Two reading methods disagreeing is the D-053 signal,
and the reconciliation — walking `*.evtx` and counting EventIDs per file —
showed the parser right and the scan wrong. **The defect was nearly filed
against the parser on the strength of a scan that could not see the file.**
The rule that caught it is the one D-053 established: when a negative result
contradicts another method, check the reading method before believing the
negative.

**Not fixed here.** Extracting `HostApplication` is a parser change with a
`details` key that must be declared in `docs/details-schema.md` first (CD-012),
and it lands in the parser layer rather than in the rules work this was found
during. Recorded so the attestation matrix stops crediting `ps_classic` with a
capability the code does not have: its row in Section 1 and Section 6.3 of
`docs/artifact-attestation-matrix.md` both now say so.


### Resolved 2026-09-19

`_details_for`'s EID-800 branch is widened to `(400, 403, 600, 800)`. No new
reader was needed: `parse_ps_detail_block` already read this shape, and the
positional-`Data` fix (D-059) had already made the fields reachable. The branch
was simply never widened to the three EIDs the channel was added for.

`host_application` is capped exactly as `ps_command_line` and
`script_block_text` are -- `host_application_bytes` always carries the REAL
length and `host_application_truncated` appears when the cap was hit -- because
it is a command line and can run long.

**Measured before widening:** `HostApplication` is present on **100%** of rows
on all three EIDs in all five collections (400: 93/94/91/17/26,
403: 82/82/62/13/17, 600: 578/584/563/104/160). CD-007's claim about this
channel was correct; only the extraction was missing.

**Measured after:** `evtx.ps_classic` rows with empty details fall from 100% to
**0 of 763** on `clean_a` and **0 of 203** on `s1_v3`.

Asserted in `TestPsClassicLifecycleCarriesHostApplication`, including the
truncation contract and a regression guard that EID 800 still distinguishes
`ps_command_line` (what the pipeline invoked) from `host_application` (what
launched the host).

### The field arrives with an inverted base rate, and that is the finding

The obvious predicate on this field -- `-ExecutionPolicy Bypass` is suspicious
-- is **backwards in this corpus**. Measured immediately after the fix:

| collection | rows whose `host_application` contains `Bypass` |
|---|---|
| clean_a | **640** |
| s1_v3 | **0** |

On host 1 the `Bypass` invocations are Chocolatey, VS Code and the project's
own `day1-install.ps1` / `02-clean-b.ps1` provisioning scripts. It is a HOST
artifact, not a scenario one: 640/640/460 on host 1 and **zero on both host 2
collections**, clean and scenario alike.

**Correction, 2026-09-19.** This entry first said *"both scenarios ran
PowerShell with `-ExecutionPolicy Restricted`"*. **That was never measured** --
it was inferred from `Bypass` counting 0 on `s1_v3` while the top
`host_application` values there were `Restricted`, with no row ever joined to
the attack. Measured properly (`docs/evidence/t1059-predicate-2026-09-19.md`):

* there are exactly **two** `Restricted` strings in the corpus and both are
  **byte-identical on all five collections** -- `Write-Host 'Final result: 1'`
  and an `$InboxIMEs` inventory block, both Windows servicing scripts;
* `restricted` fires 56/56/72/**104**/**138**, i.e. on every collection and
  MOST on `clean_c`, which is clean. It is not a corpus-fitted predicate, it
  is a non-discriminator;
* the scenario's PowerShell was **interactive** -- bare `powershell.exe` with
  no flags, 149 rows on `s1_v2` and 65 on `s1_v3`, matching the 180 and 90
  typed commands in `ps_history`. An interactive session carries no launch
  flags, so **no flag-based predicate can detect this scenario at all**.

The finding stands and is stronger than stated: not "the textbook predicate is
inverted" but "neither candidate flag discriminates, and the scenario produced
no flag to match.

This is the fourth technique in the project whose textbook indicator fires on
the clean hosts and not the attack -- after T1136.001 (account creation),
T1052.001 (removable media) and the naive form of T1070.004. Recorded as a
predicate warning in `docs/details-schema.md` beside the key itself, where
someone writing a rule will meet it. The field is declared because it is real
evidence, not because a predicate on it is calibrated.

`event_type` and `path` are unchanged for all three EIDs, so **no `event_id`
changes** from this fix -- `details` is not a hash input (CD-002). That was
checked rather than assumed.

## D-056  A benign autorun scored identically to the payload, and the scorer could never have fixed it

Found 2026-09-17, by running the pipeline end to end on `s1_v3` and reading the
entity table rather than the finding list.

    94 (from 145 across 2 rules)  [critical] entity.exe_name=invoice_scan.exe
    94 (from 145 across 2 rules)  [critical] entity.exe_name=onedrive.exe

Both matched `R-CORR-0003` (weight 85) and `R-ATOMIC-0006` (weight 60). The
entity scorer combines distinct rule weights with diminishing returns, so both
combined to 94. **OneDrive was reported as a critical entity, tied with the
payload, at the top of the table.**

**The trap is that this had already been "fixed" once.** `entity_score.py`'s
docstring cites this exact pair as the case that justified replacing a clamped
sum with diminishing returns: under the old scheme both scored 145 clamped to
100, and the fix moved them to 94. The pair was used as the worked example of
a solved problem. It was not solved -- it went from indistinguishable at 100 to
indistinguishable at 94.

No combination function could have solved it. Both entities matched the same
two rules, so both carried the same two weights, and any order-independent
function of equal inputs returns equal outputs. **The scorer was validated
against the failing case's numbers instead of its cause.**

**The cause was in the rules.** `R-CORR-0003`'s persistence step required
`is_user_writable`, and OneDrive's per-user install at
`AppData\Local\Microsoft\OneDrive\OneDrive.exe` genuinely satisfies it. The
rule's own `expected:` note had recorded that residual on 2026-09-13 and
called it "the honest limit of this indicator" -- correctly, as a base-rate
observation, and without noticing that the same residual was putting a benign
binary level with the payload in the ranked output an analyst actually reads.

**Fix:** a second shape predicate on the same step, separating where software
is ACQUIRED (Downloads, Desktop, Temp, Public) from where it is INSTALLED
(Program Files, a system directory, a vendor's own versioned directory under
AppData). Measured against the full autorun population across all five
collections -- 55 values -- it matches **2 of 2 payload values and 0 of 53
benign ones**.

    R-CORR-0003   before  1 1 2 1 2     after  0 0 1 0 1
    s1_v3 entity table:  invoice_scan.exe 94 critical (sole critical)
                         onedrive.exe     60 high (fifth)
    s1_v2 entity table:  invoice_scan.exe 98 critical (top)

`R-ATOMIC-0006` was deliberately left broad and still fires 8/8/4/1/2.
Narrowing it identically would have improved its base rate while removing the
pipeline's ability to see an `AppData\Roaming\<random>\` payload, which is the
canonical real-world form of this technique and a shape this corpus happens not
to contain. Trading worst-case coverage for a better number on this corpus is
the corpus-fitting both rules' notes already reject.

**Same family as D-051 and D-055, and the sharpest instance of it.** D-051 was
a derived signal asserted without measuring; D-055 was a channel taken for a
field nothing extracts; this was a fix verified against the symptom it was
supposed to remove. All three produce output that looks correct. The specific
lesson: **an entity-score tie is a report that the rules did not discriminate.
It is evidence about the rule set, not a defect in the scorer.**

## D-057  Winlogon 811/812 drop the only field that distinguishes them, and two EIDs are discarded unseen

Found 2026-09-18 by the family signal survey, which flagged `evtx.winlogon` as
having `details == {}` on **all 1,913 rows across four collections** — and by
then checking the raw records rather than concluding the artefact was empty.

**The records are not empty.** Every 811 and 812 carries two named fields:

    <EventData>
      <Data Name="Event">0</Data>
      <Data Name="SubscriberName">GPClient</Data>
    </EventData>

`_details_for()` has no branch for 811 or 812, so `keep` falls through to the
empty tuple and both fields are dropped. **Structurally identical to D-055**
(`evtx.ps_classic` 400/403/600), found in a different family three weeks of
parser work apart, which is what makes it a pattern rather than an oversight:
a channel gets an entry in `_CHANNELS` and an EID map, and the corresponding
`_details_for` branch is a separate edit nothing forces.

`SubscriberName` is the field that makes the row mean anything. 811/812 are a
notification dispatched to a subscriber and its completion; the subscriber
named is what says WHICH subsystem was notified. Without it the family emits
1,913 rows that differ only in timestamp.

**Two EIDs are discarded without ever being seen.** The same raw read found:

    EventID counts on clean_b: {1: 21, 2: 21, 811: 158, 812: 158}

EIDs 1 and 2 are not in `WINLOGON_EIDS`, so `_artifact_for()` maps them
nowhere and they are dropped. Unlike the generic `evtx.x.*` fallback — which
exists precisely so an unstudied channel still lands somewhere — an unmapped
EID inside a CURATED channel is silently lost. **The generic fallback does not
protect curated channels**, and nothing measures what a curated map omits.

**A separate claim this corrects.** `docs/artifact-attestation-matrix.md`
records that 811/812 "do not name a principal at all". The record carries
`<Security UserID="S-1-5-18">`. The matrix's CONCLUSION stands — S-1-5-18 is
SYSTEM, the service dispatching the notification, not the account logging on —
but its stated reason was wrong, and the corrected reason is stronger: the
channel names a principal and that principal is never the user.

**Not fixed here.** Extracting `SubscriberName` needs a `details` key declared
under CD-012 first, and deciding what EIDs 1 and 2 attest to is a curation
question, not a bug fix. Recorded so that:

* the family survey's verdict reads `parser-blocked`, not `no discriminator` —
  a family cannot be said to lack discriminating content while its content is
  being discarded;
* the audit that should exist — every curated channel's EID map compared
  against the EIDs actually present in the evidence — is written down as
  missing rather than assumed done.

## D-058  User and host entities accumulate weight for existing, and outrank the payload

Found 2026-09-18, in the pre-ablation check of clean-host entity scores. The
pipeline's headline — "`invoice_scan.exe` is the sole critical entity on both
scenario hosts" — is true and hides this.

**Top entity per collection, measured:**

    clean_a    entity.user=youssef        97   38 findings, 5 rules
    clean_b    entity.user=youssef        97   40 findings, 5 rules
    clean_c    entity.user=vboxuser       92    3 findings, 3 rules
    s1_v2      entity.exe_name=invoice…   99    4 findings, 4 rules
    s1_v3      entity.exe_name=invoice…   99    3 findings, 3 rules

`youssef` scores 97 on a collection containing no attack.

**Correction, 2026-09-18, on measuring this properly.** The first version of
this entry said `youssef` "outranked `invoice_scan.exe` outright until
R-CORR-0006 moved the payload from 94 to 99". That was true when observed and
is no longer: measured across all five collections, **no clean-host entity of
any kind outscores the payload** -- 97 and 92 sit below 99 on both scenario
hosts. The defect is not an inversion. It is a **two-point margin between "the
person who uses this laptop" and "the payload", on a scale that mixes entity
kinds whose scores are not comparable.** The correction matters because an
inversion would demand an urgent fix and a narrow margin demands a structural
one.

**The cause is not a mis-firing rule.** R-ATOMIC-0001's 42 findings on
`clean_a` spread over **17 distinct `exe_name` entities** (largest:
`dismhost.exe`, 19), and no binary rises above 45. The rules behave as
designed and the binary ranking is sound.

The cause is that **a user entity aggregates rules that are not evidence of
anything when combined.** `youssef` is named by:

    R-ATOMIC-0001  installs software from a Downloads folder
    R-ATOMIC-0006  has a OneDrive autorun under AppData
    R-ATOMIC-0009  has a local account
    R-CORR-0002    mistyped a password, then logged in
    R-CORR-0005    that account was created and later used

Five independent rules, five weights, combined by diminishing returns to 97.
Each is individually reasonable. Their conjunction describes **an ordinary
person using an ordinary computer**, and the scorer cannot tell that from
corroboration, because `entity_score.aggregate` treats "distinct rules agreeing
on one entity" as strengthening regardless of what the entity IS.

**`entity.host` is the same defect in a sharper form.** `entity.host=windows10`
scores 88 on `clean_a` from **48 findings across 3 rules**. There is exactly
one host per collection, so a host entity aggregates every finding in the run
— a sum of unrelated evidence attached to a label that cannot discriminate by
construction. `core/entity.py` already records that `host_key` is "defined for
reporting; not joinable (schema 4.5)". It is excluded from JOINS and not from
SCORING, and nothing states why those should differ.

**DECIDED 2026-09-18 on measurement: Option B, rank entity kinds
separately.** Full working in `docs/evidence/entity-scoring-d058-2026-09-18.md`.

Three candidates were simulated against the real findings rather than reasoned
about, and two failed:

* **A, declare a rule class** (inventory vs detection) and let only detection
  rules aggregate. **Its premise is false.** Measured, R-ATOMIC-0001 feeds 36
  binary entities, 7 user and 3 host; R-ATOMIC-0006 feeds 9 and 11. The same
  finding names the executable AND the account that ran it, which is correct
  behaviour. Rules do not partition into classes, so A means hand-labelling
  against the evidence.
* **C, drop `entity.host` from scoring.** Leaves `entity.user=youssef` at 97
  as the top entity on two clean collections. Removes the 94-on-`s1_v2` host
  artifact and not the defect.
* **B, a ranked table per entity kind.** Addresses the actual error, which is
  a category error: a user's 97 and a binary's 99 do not measure the same
  thing. Subsumes C, needs no schema change, and touches `entity_score.py`
  plus the `run.json` shape rather than all 15 rule files.

**What B exposes, and the reason the decision is not merely tidy-up.**
Restricted to binaries the separation is already there and was hidden:

    clean_a  86 high      clean_b  86 high      clean_c  75 high
    s1_v2    99 CRITICAL  s1_v3    99 CRITICAL

Thirteen points, and **no clean collection produces a critical binary at all**.
That discriminator existed the whole time; users and hosts sharing the table
concealed it.

**What B does not fix:** `youssef` still scores 97 among users. Separating the
kinds stops that contaminating the binary ranking; it does not make the user
score meaningful. Whether a user entity should aggregate rule weights at all
is a further question.

### Landed 2026-09-19 — Option B, with `entity.host` excluded rather than tabled

**The host table question was decided by its row count.** Option B as written
gave every kind its own ranked table, `entity.host` included. There is exactly
ONE host per collection — `windows10`, `windows10`, `windows10`,
`win-l0cdivojagf`, `winvm` — so a host table is a single row, which is not a
ranking. Combined with the fact that a host entity aggregates every finding in
the run, the honest treatment is to stop scoring it: `core/entity.py` already
said `host_key` is "defined for reporting; not joinable", and this entry
already noted that nothing stated why joins and scoring should differ. Now
they agree. The host is still reported, as collection metadata, which is where
a single-valued fact belongs.

**Implementation.**

* `entity_score.SCORED_ENTITY_KINDS` — `entity.exe_name`, `entity.user`.
  `aggregate()` filters on it, so exclusion happens once and no consumer can
  reintroduce the host by accident.
* `entity_score.aggregate_by_kind()` — one worst-first table per kind, every
  declared kind present even when empty, so a consumer never distinguishes
  "no such kind" from "none found".
* `entity_score.summary_lines_by_kind()` — the terminal summary, headed per
  kind.
* `run.json` **1.0.0 → 1.1.0**, additively: `entities` keeps its name, shape
  and ordering (it simply no longer contains host rows, because they are no
  longer scored) and `entities_by_kind` is new. `_by_kind` partitions the
  already-ranked list rather than re-aggregating, so the two views cannot
  disagree.

**Verified against all five collections, and the claim this change was made
for reproduces exactly:**

| collection | top binary | score | severity | top user | score |
|---|---|---|---|---|---|
| clean_a | `cursorusersetup-x64-3.15.6.exe` | 86 | high | youssef | 97 |
| clean_b | `7z2602-x64.exe` | 86 | high | youssef | 97 |
| clean_c | `npp.8.9.8.installer.x64.exe` | 75 | high | vboxuser | 92 |
| s1_v2 | `invoice_scan.exe` | **99** | **critical** | admin_local | 93 |
| s1_v3 | `invoice_scan.exe` | **99** | **critical** | vboxuser | 88 |

Thirteen points of separation, and **no clean collection produces a critical
binary**. Scored host entities: **0** on every collection.

**What this does NOT fix, restated because it is easy to lose.** `youssef`
still scores 97 among users. Separating the kinds stops that contaminating the
binary ranking; it does not make the user score meaningful. Whether a user
entity should aggregate rule weights at all remains open.

Asserted in `TestEntityKindsAreRankedSeparately` (6 tests), including that a
finding naming both a host and a binary keeps the binary — excluding a kind
must not discard a finding's other entities.

**Consequence discharged:** `docs/evidence/layer-ablation-2026-09-18.md` now
carries a SUPERSEDED banner with the post-change binary figures, because every
rules-side rank in it was measured against pre-D-058 scoring. A re-measured
ablation remains outstanding (D-062).

**For Person A:** `run.json` is 1.1.0. The change is additive and the existing
`entities` array is unchanged in name, shape and order, so a consumer that
ignores `entities_by_kind` keeps working — with the one behavioural
difference that host rows no longer appear, which is the fix itself.

**The immediate consequence, and the reason this is logged before the layer
ablation rather than after:** the ablation reports where the attack entity
ranks. That number is only meaningful if the entities ABOVE and BELOW it are
ranked sensibly. Reporting "the attack ranks 1 of 5 on `s1_v3`" while
`youssef` would rank 1 of 26 on a clean collection measures the rule set's
ability to find a payload on a host where a payload exists, not its ability to
tell the two apart.

**Same family as D-056**, one level up. D-056 was two entities of the same kind
scoring identically because the rules did not separate them. This is entities
of DIFFERENT kinds being placed on one scale where their scores are not
comparable — a user's 97 and a binary's 99 do not mean the same thing, and the
table presents them as if they do.

## D-059  The curated channels discard 49% of their own records, and nobody had counted

Found 2026-09-18 by the audit D-057 said was missing. D-057 recorded that
`Microsoft-Windows-Winlogon/Operational` contains EIDs 1 and 2 that no map
claims and the parser drops. The obvious question — *how many others?* — had
never been asked of any curated channel.

**Measured across all five collections:**

    family             mapped  present  dropped   rows kept   rows dropped
    evtx.bits               4       13        9       2,189          1,055
    evtx.defender           4       17       16       2,048          1,226
    evtx.firewall           4        6        4         983          3,049
    evtx.powershell         1        6        5       4,363          1,017
    evtx.ps_classic         3        4        1       2,566             30
    evtx.rdp                2       13       11          83            508
    evtx.security           5       46       41      21,692         14,479
    evtx.system             1       90       89          91          8,829
    evtx.winlogon           2        4        2       2,229            234
    evtx.wmi                1        5        4          73          4,129
    ------------------------------------------------------------------------
    TOTAL                                            36,317         34,556

**A curated channel keeps 51% of its records and drops the rest**, and the
drop is invisible: `_artifact_for()` resolves a curated channel to its family
before any EID check, so the generic `evtx.x.*` fallback — which exists
precisely so an unstudied channel still lands somewhere — never sees them.
An unmapped EID in a GENERIC channel becomes a `log_record`. The same EID in a
CURATED channel is destroyed.

**Selectivity is correct and is not the defect.** A curated map is a
deliberate choice, most EIDs in a channel are noise, and CD-007 is explicit
that this pipeline does not invent semantics for EIDs it has not studied. The
defect is that **there was no difference between "considered and rejected" and
"never seen"**, and no way to tell which had happened for any of 189 EIDs.

Three of the dropped EIDs are not noise:

* **`evtx.security` 4672, 2,360 rows.** Special privileges assigned to a new
  logon. Corrected in the technique grid earlier the same day, where it had
  been described as "off by default" — it is on by default and abundant, and
  is the natural corroboration for `lsa_policy`, whose own rule is blocked on
  the SID/name join.
* **`evtx.security` 5379, 6,117 rows.** Credential Manager read. The largest
  single dropped EID in the corpus.
* **`evtx.ps_classic` 800, 30 rows.** `docs/artifact-attestation-matrix.md`
  carries "legacy PowerShell EID 800 ⛔" as a STATED GAP, with ⛔ defined as
  "not parsed by this pipeline". **The channel has been parsed since this
  session's EVTX work.** The gap was recorded against a channel and is really
  against an EID inside a channel the pipeline now reads, so the matrix
  understates what is available while appearing to state a limit honestly.

**Fixed by a test, not by a parser change.**
`tests/test_curated_eid_coverage.py` requires every EID present in a curated
channel to be either mapped or listed in `UNMAPPED_BY_DESIGN` with a reason.
Selectivity survives; silence does not. Mapping any particular EID remains a
separate decision needing a CD-007 entry and a details-key declaration.

### What this audit does NOT verify (scope, added 2026-09-19)

**It finds EIDs that are ABSENT from a curated map. It cannot tell whether a
mapped EID is mapped CORRECTLY.** A wrong label and a right one are
indistinguishable from outside the parser: both appear in `_mapped_eids`, both
produce rows, and the audit's question -- "is this EID accounted for?" -- is
answered "yes" either way.

**D-066 is the instance.** `evtx.bits` EID 4 was mapped to
`bits_job_cancelled` and is the job COMPLETION summary. It was present in the
evidence and present in the map, so this audit passed over it on every run.
Finding it needed a different question -- reading the records against each
other -- which no coverage audit asks.

A second scope limit, already noted in the code: the check is **per
collection**, so an EID significant only in aggregate across all five does not
trip the `SIGNIFICANT_ROWS` threshold.

Both limits are now stated in the test's own docstring, so the next reader
meets them where the green result is produced. See the **verification-coverage
pattern** at the top of this log: this is its "out of scope" form.

**The test itself had this defect first, which is why it asserts it cannot
pass vacuously.** Its first version matched `_CHANNELS` fragments against
`path.name`. The fragments begin with `/` because the parser matches them
against a relative POSIX path, so nothing matched, zero files were examined,
and it passed in 0.10 seconds. A green audit that audits nothing is worse than
no audit, so the test now asserts a minimum number of curated files examined
before it is allowed to report success.

## D-060  A stated gap outlived the work that closed it

Found 2026-09-18 while acting on D-059.

`docs/artifact-attestation-matrix.md` carried, in the `evtx.powershell` row's
corroboration column:

    legacy `Windows PowerShell` EID 800 ⛔

with ⛔ defined at the foot of that table as "not parsed by this pipeline".
True when written. **The legacy channel was parsed on 2026-09-17**, five
curated channels landing together, and the marker stayed — because EID 800 was
being dropped INSIDE the now-parsed channel, so nothing contradicted the
statement from either direction. The matrix said "not parsed"; the channel was
parsed; the EID was not; and all three were simultaneously true in a way that
concealed the real state.

**This is D-054's class, in the opposite direction.** D-054 was a document
asserting event_types the validator could not see. This is a document
asserting an ABSENCE that its own project had removed. Both are claims
measurement falsifies, and neither had anything watching it.

**The gap is now closed rather than merely re-labelled.** EID 800 is mapped
(CD-007, 2026-09-18) and emits `host_application`, `ps_command_line`,
`ps_script_name`, `ps_user_id` and `ps_sequence_number`, declared in
`docs/details-schema.md` first per CD-012. Measured 10/10/10/0/0 — flat on
host 1 and absent on host 2, so it does not discriminate by volume and no rule
is written on its presence. It is taken for the field.

**The root cause reached further than EID 800.** `_event_data()` keyed
entirely on the `Name` attribute:

    for node in root.findall("e:EventData/e:Data", NS):
        name = node.get("Name")
        if name:                      # <- unnamed elements dropped silently
            out[name] = node.text or ""

The legacy PowerShell channel writes **unnamed** `<Data>` elements holding a
tab-indented `key=value` block. Every record of that channel therefore reached
`_details_for()` as an empty dict, which is the mechanism behind D-055 as well
— 400/403/600 were not merely missing a `keep` tuple, their fields were
unreachable. Unnamed elements are now kept under positional keys and
`parse_ps_detail_block()` reads them.

**D-055 is NOT closed by this.** 400/403/600 still emit no details, because
each needs its own decision about what it attests and its own declared keys.
What changed is the blocker: it was "the data cannot be reached", it is now
"nobody has decided what to keep". The attestation matrix row says so.

Effect on the audit: `evtx.ps_classic` becomes the first curated channel with
**zero dropped EIDs** — 4 present, 4 mapped. The corpus-wide figure moves
34,556 → 34,526 dropped rows, which is the honest size of this change: 30
rows, and a field nothing else in the pipeline carries.

## D-061  Four grammar-invariant tests would have passed on an empty rule set

Found 2026-09-18 by a bounded audit of the whole suite for the vacuous-pass
shape, prompted by that shape appearing twice in two days.

**The shape:**

    for x in <discovery>:        # yields nothing
        assert something(x)      # never runs
    # test passes, having checked nothing

Audited by AST rather than by grep: a test whose assertions all sit inside a
loop over a discovery expression (`rglob`, `glob`, `load_rules`,
`collect_events`, …), with no assertion outside that loop and no count guard.
45 test files, 5 candidates, 4 real.

**The four, all in `tests/test_ruleset_agrees_with_validator.py`:**

    test_every_correlation_rule_names_a_shared_entity
    test_every_presence_step_is_excluded_from_the_window
    test_every_rule_records_its_measured_base_rate
    test_every_window_justification_cites_a_number

Each loops over `load_rules(RULES_ROOT, include_disabled=True)` and asserts
inside the loop. **Nothing in the suite asserted the rule set is non-empty**,
so had the loader ever returned `[]` all four would have reported success.
Demonstrated rather than argued: `load_rules` on an empty tree returns 0
rules, and all four then iterate zero times.

These are not incidental tests. They are the ones enforcing that a presence-
typed step never enters a sliding window (**D-027**) and that every rule
carries a measured base rate — the two disciplines this project's rule set
rests on. Silence there would be the most expensive silence in the suite.

**Fix:** one shared `every_rule` fixture asserting `len(rules) >= 10` before
returning them. Four tests take the fixture instead of calling the loader, so
a future test gets the guard by asking for it rather than by remembering.

**The fifth candidate is a false positive and stays as it is.**
`test_lnk.py::test_protocol_links_yield_nothing` calls `pytest.skip` when its
discovery finds nothing, which is the correct handling — an absent artefact
class is not a failure. The audit script does not model skip-on-empty, and
that limitation is recorded here rather than worked around, because a checker
that silently reclassifies its own false positives is the thing this entry is
about.

**Third occurrence of this shape in this repository**, which is why it was
audited rather than fixed case by case:

* `rules/blocked/` emptied when R-ATOMIC-0003 moved into `atomic/`, and the
  test guarding it "iterated over nothing and proved nothing" until it was
  rewritten to build its own fixture. The note is still in that test.
* `tests/test_curated_eid_coverage.py` matched `_CHANNELS` fragments against
  `path.name` when those fragments begin with `/`, examined zero files and
  passed in 0.10 s (**D-059**).
* These four.

The first was fixed in place, the second by an explicit non-vacuity assertion,
and only after the third did anyone ask how many others there were. **A defect
found twice is a defect class; the audit is the response to the class.**

## D-062  Baseline: the anomaly layer is scoped to 7 families and the ablation measures it before any ML work

Found 2026-09-18 by the layer ablation, run after the rules-coverage work
froze.

**The headline measurement, host 2 (`clean_c` -> `s1_v3`):**

    2026-09-13, 7 families     attack entity ranks   40 of 525   (top 7.6%)
    2026-09-18, 38 families    attack entity ranks  134 of 892   (top 15.0%)

**This is a baseline, not a regression.** The parser work did not harm the
anomaly layer: the layer was never extended to see what the parsers added. The
entity denominator grew with the event pool while the model stayed fitted on
the original seven families, so the attack entity's percentile fell without
anything about the model changing. A workstream-sequencing fact, recorded so
the number is not read as damage.

The 2026-09-13 figure is not wrong — it measured a different pipeline — and
the comparison is the point: it establishes where the ML layer stands
**before** any ML work, which is the only honest starting point for deciding
whether that work is worth doing.

**The cause is not the model. `features.FAMILY_FEATURES` still contains
exactly seven entries:**

    amcache, browser, evtx.powershell, evtx.security, evtx.system,
    prefetch, registry

Those are the original seven families. **Not one of the 31 families added
across this session and the last has a feature set**, and
`features_for_family()` falls back to the full `FEATURE_NAMES` for anything
missing — which is precisely the failure `docs/per-family-features.md` was
written to prevent: a family receives columns its records cannot populate
(`run_count` for a deletion, `download_size_log10` for a registry value), the
columns are constant, and Isolation Forest spends splits partitioning nothing.

**Measured on `s1_v3`: 5 families are modelled out of 126 present.**

    modelled: amcache, evtx.powershell, prefetch, services, shimcache
    scored rows: 3,019 of 453,082 events

`services` and `shimcache` reach the model only through that same fallback.
Everything else is either below `MIN_TRAINING_ROWS` or unmodellable.

**So the denominator grew and the signal did not.** `evaluation.rank_entities`
draws entities from the scored rows, the event pool grew roughly 70% in
entity terms (525 -> 892), and the model behind the ranking is unchanged from
2026-09-13. The attack entity did not get harder to find; it got diluted.

**Per-family contribution, and this is the more serious half.** No family
places the attack entity in its own top decile:

    host 1   bam 33.3%   prefetch 41.0%   shimcache 79.2%   userassist 86.3%
    host 2   prefetch 63.2%   amcache 89.3%

**The anomaly layer contributes nothing to finding this payload on either
host.** The `both` figure of 1/1193 and 1/894 is the RULES layer placing it
first and the ML ranking appended behind; ML alone puts it at 298/1189 and
134/892, outside any review budget.

That is consistent with what `CLAUDE.md` already says -- "the anomaly layer
ranks; it does not detect" -- but the ranking claim itself now needs
restating, because top-7.6% and top-15.0% support different sentences.

**Not fixed here.** Adding feature sets for 31 families is per-family work
requiring a leakage test each (`docs/feature-decisions.md`'s standard), and
several families have no obvious numeric feature at all -- `recyclebin`
carries a size and a path, `lnk` carries volume metadata, `txf_pending`
carries neither. Whether the anomaly layer should cover them, or should be
explicitly scoped to execution-shaped families and say so, is a design
decision and belongs with the ML stage record rather than with a quick patch.

**What must NOT happen meanwhile:** quoting 40/525 or "top 7.6%" as the
current figure. `CLAUDE.md` and `docs/feature-decisions.md` both carry it,
both now qualified with the date and the family count they describe. **A rank
figure quoted without its pipeline version is the defect class here**, not the
particular number -- the 2026-09-18 figures need the same treatment the moment
anything below them moves.

**THE ABLATION MUST BE RE-MEASURED AFTER D-058 LANDS.** Its rules-side ranks
were taken against the current entity scoring, which D-058 will change: a
clean-host user scores 97 against the attack binary's 99, and any of the three
candidate fixes alters what "rank 1 of 5" means. The figures in
`docs/evidence/layer-ablation-2026-09-18.md` therefore describe **pre-D-058
scoring** and are superseded the day that decision lands. Stated here because
a deferred re-measurement is the thing that gets lost.

**Update 2026-09-18, after D-063.** Skipping undeclared families instead of
defaulting them changed the measurement again, in the direction the diagnosis
predicted: modelled families 5 -> 3 (`services` and `shimcache` were reaching
the model only through the fallback), scored rows 3,019 -> 2,180, entities
892 -> 443, attack rank 134 -> 81. The PERCENTILE barely moved -- 15.0% to
18.3% -- which is the confirmation that the denominator, not the model, was
carrying the earlier change.

## D-063  An undeclared family was handed every feature and modelled anyway

Found 2026-09-18 while investigating D-062's cause.

`features.features_for()` ended:

    return FAMILY_FEATURES.get(family, FEATURE_NAMES)

A family with no entry received **the full fifteen-column vocabulary**, and
`PerFamilyModel.fit` then modelled it like any declared one. The docstring
said so deliberately, and its reasoning was sound for the situation it was
written in: a new parser scoring with redundant columns is merely diluted,
whereas silently dropping a column its artifact does populate would be wrong.

**That reasoning inverted at 31 families.** `FAMILY_FEATURES` still listed the
original seven while the pipeline parsed 38, so every family added across two
sessions took columns its records cannot populate -- `run_count` for a
deletion, `download_size_log10` for a registry value -- and a constant column
spends splits partitioning nothing. `docs/per-family-features.md` was written
to prevent exactly this and was being bypassed by the default.

**The layer therefore appeared to cover 38 families while its feature table
covered 7, and nothing reported the difference.** `UnscoredFamilies` already
existed to record *why* a family is not modelled -- below `MIN_TRAINING_ROWS`,
or too few distinct vectors -- and "nobody declared its features" was not one
of the reasons it could give.

**Fix:** `features.is_declared()`, and `fit` skips an undeclared family with
that reason recorded. `features_for` keeps its fallback for `family is None`
and for callers wanting the full vocabulary; the fitting path no longer
reaches it.

**Measured effect on `s1_v3`**, and it is a correction rather than an
improvement:

    modelled families   5 -> 3   (amcache, evtx.powershell, prefetch)
    scored rows     3,019 -> 2,180
    entities          892 -> 443
    attack rank       134 -> 81   (15.0% -> 18.3%)

**`services` and `shimcache` were reaching the model only through the
fallback** -- neither has ever had a declared feature set. Their removal is
the honest state, not a loss: they were being scored on columns nobody chose
for them.

The percentile barely moved, which is the point. The denominator was carrying
D-062's apparent change, not the model.

**Asserted, not just documented.**
`tests/test_features.py::TestUndeclaredFamiliesAreNotModelled` fails if an
undeclared family reaches `model.models`, checks the skip reason names
`FAMILY_FEATURES`, and carries a control -- a declared family with identical
rows IS fitted -- so the test cannot pass because `fit` is broken outright.
One config change would otherwise re-introduce the default silently.

The row count it uses is derived from `MIN_TRAINING_ROWS` rather than
hard-coded, so raising that floor cannot make the assertion vacuous (D-061's
shape).

## D-064  The removable-media evidence is the operator's own collection workflow

Found 2026-09-18, inspecting the T1052.001 backlog row before writing a rule
for it.

`docs/technique-coverage-grid.md` listed **T1052.001 Exfiltration over USB** as
`observable-unwritten`, on the strength of a real and often-repeated finding:
two LNK files on `s1_v2` name removable volume serial `18334A83`, label `JOE`,
**which no other family in the pipeline mentions in any collection**. CD-013
was reopened on that basis.

**The signal is as clean as advertised.** `drive_type` measured across all
five collections:

    clean_a  fixed 95              clean_b  fixed 100
    s1_v2    fixed 135, REMOVABLE 9
    clean_c  fixed 66              s1_v3    fixed 71

Nine rows on one scenario collection, zero everywhere else. By base rate alone
it is the most discriminating single field measured in this project.

**Then read the rows.**

    2026-08-20 14:35   E:\collection_clean_a
    2026-08-20 14:48   E:\collection_clean_b
    2026-08-21 01:48   E:\collection_s1
    2026-08-21 17:22   E:\handoff
    2024-09-10 16:48   E:\Camera
    2020-10-09 14:14   E:\Camera\2020-10-09-171406379.mp4   (x3)

**It is the USB stick the operator used to carry the collections off the
host.** Two of the folders browsed are named `collection_clean_a` and
`collection_clean_b` — this project's own evidence — and they were opened on
2026-08-20, BEFORE the `s1` collection directory existed. `handoff` is what it
sounds like. The remaining rows are personal media from 2020 and 2024 that
came with the stick.

A rule on `drive_type: removable` would fire 9 times on `s1_v2`, zero times on
the clean collections, look like a perfect discriminator, and **detect the
evidence-handling procedure**.

**Same class as the `ps_history` leakage recorded in
`docs/feature-decisions.md`**, and it went undetected for longer because the
base rate looked better. `ps_history` at least contained commands; this is a
field whose values are 9-vs-0 and whose meaning is the opposite of what the
count suggests.

`s1_v3`, the other scenario host, carries **zero** removable rows. A signal
present on one of two scenario hosts, where on that host it is the collection
method, is not a signal.

**T1052.001 moves from `observable-unwritten` to `not-observable` in this
corpus**, with the reason stated. The capability is real — `lnk` and
`jumplist` do record removable-volume serials and labels that survive the
device's removal, and CD-013's original point stands — but **this corpus
cannot calibrate a rule for it**, because its only removable-media activity is
the operator's.

**The collection constraint this establishes is C-01 in
`docs/scenario-design-constraints.md`.** This entry records what was measured;
that document records what the next scenario must do differently.

**What would make it writable:** a collection where removable media is used
for something other than evidence transport, and where the collections are not
staged through the volume being measured. That is a collection-design
constraint worth recording for any future scenario: **the evidence must not
leave the host by a route the pipeline parses.**

## D-065  `evtx.bits` records a complete download and the parser keeps only the timestamp

Found 2026-09-18, measuring the T1071.001 backlog row.

`docs/artifact-attestation-matrix.md` credits this family with the one thing no
other family can supply:

> `evtx.bits` matters because a background transfer is a download that leaves
> NO BROWSER HISTORY -- the browser family cannot see it at all.

**Measured: `details == {}` on every `evtx.bits` row, in every collection.**
The family emits an `event_type`, a timestamp, and nothing else. It cannot
name a URL, a destination, a size or an owner.

**The raw records carry all of it.** EID 59 (transfer started) on `s1_v3`:

    name          C:\Users\vboxuser\AppData\Local\Temp\{...}-MicrosoftEdgeUpdateSetup_X86_1.3.265.7.exe
    url           http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/1c7f...
    bytesTotal    1781080
    fileTime      2026-08-28T17:51:09Z
    transferId    722D5450-63C7-41F2-A871-B1CBA9E7BCBC

EID 60 adds `hr` (the result code) and `bytesTransferred`; EID 3 carries
`jobTitle`, `jobOwner` and **`processPath`** -- the process that created the
job; EID 4 carries `bytesTransferred` and `fileCount`.

A source URL, a local destination path, a byte count and the responsible
process. That is a more complete download record than the `browser` family
produces, and all of it is discarded.

**Third instance of the same defect** -- D-055 (`evtx.ps_classic` 400/403/600),
D-057 (`evtx.winlogon` 811/812), and now this. In each case a channel was
added to `_CHANNELS` with an EID map and **no matching branch in
`_details_for`**, so the family appears in the timeline carrying nothing. The
pattern is now established beyond doubt: adding a channel is two edits and
nothing forces the second.

Unlike the other two, these records use `<Data Name="...">` attributes, so
`_event_data` reaches them already -- the fields are sitting in the `data`
dict and `_details_for` simply has no `elif` for 3/4/59/60. This one is a
`keep` tuple and a details-schema declaration, not a new reader.

**The consequence for the backlog.** T1071.001 was listed as
`observable-unwritten` on the strength of this family plus `webcache`
`background_transfer`. Measured, neither can currently support a rule:

* `evtx.bits` -- 254/288/351/95/111 rows, no fields at all.
* `webcache` `background_transfer` -- 38/50/71/5/20 rows, and the `url`
  field holds a **cache-entry GUID**, not a URL. Every row's
  `cache_directory` is under a Store or ContentDeliveryManager app package:
  these are OS app-content fetches, not user-attributable downloads.

T1071.001 therefore moves to `blocked` with this defect named, not to
`not-observable`: the evidence is present and rich, and a parser change makes
it writable.
### Resolved 2026-09-19 -- and two claims in this entry were wrong

The `keep` branches are in (`3/4/5` and `59/60`), `processPath` on EID 3 now
reaches `_path_for`, and every key is declared in `docs/details-schema.md`.
Measured after the change: **0 of 505** `evtx.bits` rows on `clean_a` and
**0 of 231** on `s1_v3` carry empty details, against 100% before. Row counts
rose 498 -> 505 and 225 -> 231 because EID 5 is now read at all (D-066).

An EID 3 row now carries `Event.path`, the derived path fields and
`entity.exe_name` -- so a background transfer is joinable to an execution, which
is the part of this family that no other family can supply.

`jobOwner` is also wired to `Event.user` on EIDs 3/4/5, so the family joins on
`entity.user` as well. It was left None in the first pass of this fix, which
would have limited every join to `exe_name` on EID 3 alone. `core/entity.py`
already folds `NT AUTHORITY\LOCAL SERVICE` to `None` via `SYSTEM_CONTEXTS`, so
OS-owned jobs correctly contribute no principal -- checked before wiring rather
than after. EIDs 59/60 carry no owner at all and cannot attribute; only the
EID 3 that created the job can, through its `jobId`.

**This entry claimed a destination path that is not there.** It quoted a
raw EID 59 record as carrying a local destination in `name`. Measured across all
five collections, `name` is the job DISPLAY NAME: a title (`Font Download`,
`Edge Component Updater`) on **252/286/349/89/105** rows and a filesystem path
on only **2/2/2/6/6**, every one of those Edge Updater, which happens to name
its jobs after the target file. It is the same value as EID 3's `jobTitle` for
the same job id. **The local destination is not recorded in this channel.** The
attestation matrix's wording was corrected with it.

**And `bytesTotal` on EID 59 is frequently a sentinel.** 10/9/9/7/7 rows carry
`18446744073709551615` -- `UINT64_MAX`, meaning the size was unknown when the
transfer began. A numeric predicate against that matches everything, so the key
is not kept on EID 59 at all: excluded rather than filtered, so it can never
carry a sentinel. EID 60 carries the real size.

### The consequence for T1071.001 is NOT what this entry predicted

This entry said the technique moves to `blocked` rather than `not-observable`
because "a parser change makes it writable." **The parser change is done and it
is still not writable**, for a reason no parser change can fix.

Measured, the URL host of **every** BITS transfer in the corpus -- the host
counts sum to the full 59/60 row count on all five collections, so this is every
transfer, not a top-N:

| collection | transfers | hosts |
|---|---|---|
| clean_a | 254 | `msedge.b.tlu.dl.delivery.mp.microsoft.com` 124, `g.live.com` 98, `oneclient.sfx.ms` 17, `fs.microsoft.com` 13, `msedge.f.tlu...` 2 |
| clean_b | 288 | same five |
| s1_v2 | 351 | same five |
| clean_c | 95 | the above plus `edgedl.me.gvt1.com` 4 |
| s1_v3 | 111 | same as clean_c |

**Every transfer on every collection, clean and scenario alike, is Microsoft or
Google update infrastructure.** Both scenarios delivered the payload over
`WebClient.DownloadFile`, not BITS. There is no positive class: no
attacker-controlled background transfer exists anywhere in this corpus to
calibrate a rule against, and a rule keyed on these hosts would encode the
update endpoints of two vendors.

**T1071.001 moves from `blocked (D-065)` to `measured-no-discriminator`** -- the
same state as T1053.005 and T1027, and for the same reason. The family is now
parsed, rich and joinable, and the technique is unwritable on this evidence
because the evidence does not contain it. That is a scenario-design fact
(`docs/scenario-design-constraints.md`), not a parser one.

**Fixing the parser was still right.** The data was real and discarded; a
family that cannot say what it saw is a defect whether or not a rule wants it
today. "No rule can use it" would have been the same mistake as calling
`evtx.winlogon` disqualified when it was a parser bug.


### event_id changes from D-065/D-066

`event_id` hashes `event_type` and `path` (CD-002), so two of these changes
alter ids. Recorded per CLAUDE.md. Representative rows, first of each type by
`source_locator`:

| collection | event_type | locator | old id | new id | why |
|---|---|---|---|---|---|
| clean_a | `bits_transfer_started` | EventRecordID=101 | `82834ead5b7c9264` | `82834ead5b7c9264` | unchanged -- details are not hashed |
| clean_a | `bits_transfer_completed` | EventRecordID=102 | `86cf33ff4fc69589` | `86cf33ff4fc69589` | unchanged |
| clean_a | `bits_job_created` | EventRecordID=104 | `b539a1a99e1a85b4` | `2e59efdcfe4038a5` | **path** now set from `processPath` |
| clean_a | EID 4 | EventRecordID=103 | `fa9983f63295c553` (`bits_job_cancelled`) | `ef02cdfcf0bdbf0c` (`bits_job_completed`) | **event_type** corrected (D-066) |
| s1_v3 | `bits_transfer_started` | EventRecordID=105 | `41db2013fa9e815c` | `41db2013fa9e815c` | unchanged |
| s1_v3 | `bits_transfer_completed` | EventRecordID=106 | `ac85d3ddd6ca19d6` | `ac85d3ddd6ca19d6` | unchanged |
| s1_v3 | `bits_job_created` | EventRecordID=102 | `41cd0fa80aa71b13` | `dc11dc7e46e9365c` | **path** now set |
| s1_v3 | EID 4 | EventRecordID=100 | `be0201c2cadab8af` (`bits_job_cancelled`) | `b4b7b3069b346efb` (`bits_job_completed`) | **event_type** corrected |

EID 5 rows have no prior id: they were not parsed before (7 on `clean_a`, 6 on
`s1_v3`).

Every `bits_job_created` and every EID 4 row in every collection changes id.
EIDs 59 and 60 are unaffected -- `details` is not a hash input, so enriching
them does not move their ids, which is the property that made this check worth
running rather than assuming.

## D-066  `evtx.bits` EID 4 was labelled a cancellation and EID 5 was not read at all

Found 2026-09-19, reading the raw BITS records before declaring keys for D-065.
Found by an advisor challenge to an existing label, not by a failing test: the
sample EID 4 record carried `fileCount=1, bytesTransferred=55` for a job whose
EID 60 showed all 55 bytes transferred, which is not what a cancellation looks
like.

`BITS_EIDS` mapped:

    4: ("bits_job_cancelled", "bits transfer job cancelled")

**Measured, and the label is wrong.** Per job, across `clean_a` and `s1_v3`:

| check | clean_a | s1_v3 |
|---|---|---|
| jobs carrying BOTH an EID 4 and an EID 5 | **0** of 117 | **0** of 51 |
| jobs with an EID 4 whose own EID 60 has `hr != 0` | **0** | **0** |
| EID 4 `bytesTransferred` vs that job's EID 60 `bytesTotal` | equal | equal |

A cancellation does not transfer every byte it asked for, and 117 EID 4 records
tracking 123 EID 60 records is not a cancellation rate. **EID 4 is the job
completion summary.**

**EID 5 is the cancellation, and it was never mapped**, so every cancellation in
the corpus was discarded unseen -- 7 rows on `clean_a`, 6 on `s1_v3`. It carries
`User`, `jobTitle`, `jobId`, `jobOwner` and `fileCount` and, tellingly, **no
`bytesTransferred`**: nothing was moved.

**Fix:** `4 -> bits_job_completed`, new `5 -> bits_job_cancelled`, CD-007
updated, both asserted in `tests/test_evtx_windows.py`.

**This is a class the D-059 coverage audit cannot catch.** That audit finds EIDs
present in the evidence and *absent* from the curated map. EID 4 was present in
both. An EID mapped to the wrong meaning looks identical to a correct mapping
from the outside, and only reading the records against each other shows it. The
audit is not at fault; the gap is real and is now named.

`event_type` is hashed into `event_id` (CD-002), so every EID 4 row's id
changes. Recorded in D-065 below with the EID 3 path change.

## D-067  `_details_for` and `_user_for` dispatch on the EID alone, on every channel

Found 2026-09-19 while adding the BITS `keep` branches (D-065), by asking what
happens when an uncurated channel carries EID 3.

`record_to_event` looks the artifact up in a table of curated channels. When
there is no entry the row is correctly labelled `log_record` -- and then falls
through to `details={**_details_for(eid, data), **_path_details(eid, data)}`
and `user=_user_for(eid, data)` regardless. Those functions branch on the EID
and nothing else, so a generic channel carrying EID 3, 4, 5, 21 or 25 would be
given whichever curated channel's keys use that number.

The BITS work makes this concrete: 3, 4 and 5 are among the most reused event
IDs in the Windows log estate.

**Measured before fixing, across all five collections: zero generic-channel rows
currently produce details from a claimed EID.** No uncurated channel in this
corpus happens to carry the field *names* a curated branch keeps. So this fired
on nothing, and is **latent, not active**.

**Fixed anyway**, because the corpus is not the worst case and the next
collection is not bound by what this one happened to contain. `details`, `user`
and `path` are now gated on the channel being curated.

**The gate REMOVES nothing, and that needed measuring properly rather than
asserting.** The first check called `_details_for` directly -- which bypasses
the gate, so it measured the pre-gate world -- and covered only the seven
BITS/RDP EIDs. The question that matters is different: a generic channel
carrying EID 4688 with `NewProcessName` would have had a `path` before this
change and would lose it, and **`path` is hashed into `event_id`** (CD-002), so
that would be an unrecorded hash change.

Re-measured across all five collections against **every** EID with a branch in
`_details_for`, `_user_for` or `_path_for` (3, 4, 5, 21, 25, 59, 60, 400, 403,
600, 800, 1102, 4104, 4624, 4625, 4688, 4720, 5861, 7045):

    generic-channel rows carrying one of those EIDs   4,491
    of those, rows the gate removes anything from         0

So no generic row loses details, user or path, and **no `event_id` changes from
this fix**. The defect was latent in the strict sense: structurally wrong,
firing on nothing.

Asserted in `TestBitsCarriesTransferDetail::
test_a_generic_channel_does_not_borrow_bits_keys`.


**Was "not fixed here" until 2026-09-19**, on the grounds that a `keep` tuple
needed its details keys declared under CD-012 first. Both happened the same
day; see the resolution recorded under D-065 above.


---

## D-068  The collection manifest documents three of the five collections

Found 2026-09-20 during the ranking-signal evaluation, while looking for a
collection timestamp for `clean_c` to test C-06 against. There is none.

`docs/collection-manifest.md` documents `collection_clean_a`,
`collection_clean_b` and `collection_s1_v2` — the three **host-1**
collections. It carries their collection timestamps, operator accounts, file
counts, KAPE CopyLog names and the provenance narrative for each.

**`collection_clean_c` and `collection_s1_v3` appear nowhere in it.** Measured:
zero occurrences of either name, and the only `collection_*` strings in the
file are the three above. Both host-2 collections are used throughout the
evidence documents — `clean_c` is the training baseline the anomaly layer is
fitted on, and `s1_v3` is one of the two scenario collections every rule base
rate is quoted against.

**Why this is a defect and not a to-do.** The manifest is an attestation
artifact: it is where a reader establishes what was collected, from which
machine, by which operator, at what time, and under what constraints. Two
fifths of the corpus is outside it. Every five-collection figure in this
project — every base rate, the phase-span distribution, the D-058 entity
scores — rests partly on collections the manifest does not attest.

**This is the same class as D-059**, recorded in the verification-coverage
pattern at the top of this log: *an audit that cannot fail on the thing it
checks*. D-059's coverage test found EIDs absent from a map and could not see
a mis-mapped one. Here the manifest attests provenance for the collections it
lists and is silent — not wrong, silent — about the ones it does not. A reader
checking "is this corpus documented" gets a yes from a document covering 60%
of it. The failure mode is **partial coverage**, the second form in that
table.

**Consequence already hit.** C-06 (clean baseline must be collected before the
scenario runs) is stated and checkable for host 1, where the manifest gives
2026-08-23T23:31:48Z for `s1_v2` against 2026-08-24T17:44:56Z and
2026-08-24T18:58:05Z for the two baselines — an 18-hour inversion. **It cannot
be checked for host 2 at all**, because neither `clean_c` nor `s1_v3` has a
recorded collection time. Whether host 2 repeats the same ordering mistake is
currently unknowable from the repository.

**Not fixed here.** Writing the missing rows requires the collection
timestamps, operator accounts, file counts and CopyLog names for both host-2
collections, and those are facts about how the collections were taken. They
are not derivable from the repository, and **inferring them from `CLAUDE.md`'s
summary table or from the evidence tree would be the stale-claim class this
log exists to catch** — a document asserting a state it has not established.
The correct fix is for whoever took the collections to supply the values, or
for them to be read from the KAPE logs inside the collections themselves and
recorded as derived rather than attested.

**What the entry establishes now:** the gap is measured and named, C-06's
host-2 check is blocked on it, and no figure in the project should be
described as "documented across five collections" until it is closed.


---

## D-069  `evtx.defender` is typed but carries no details: four EIDs, zero keys

Found 2026-09-20 while sorting external rule sets. Eight candidate rules from
SigmaHQ and Hayabusa targeted this family; all eight failed on fields, and the
reason is a parser gap rather than a property of the technique.

**What CD-007 declares.** Four EIDs, each with an event type:

    Defender/Operational  1116  ->  evtx.defender  malware_detected
    Defender/Operational  1117  ->  evtx.defender  malware_remediated
    Defender/Operational  5001  ->  evtx.defender  defense_disabled
    Defender/Operational  5007  ->  evtx.defender  defense_configured

The parser's comment (`parsers/evtx_windows.py:138-147`) states the intent
plainly: *"1116/1117 are a detection and its remediation -- the only family in
this pipeline that records an AV verdict at all. 5001 is real-time protection
being DISABLED, which is a defence-evasion artifact (T1562.001)."*

**What it actually produces.** `_details_for` has **no branch for any of the
four**. Measured across `clean_a` and `s1_v2`:

    evtx.defender   event_types = {defense_configured: 1030}
    details keys    = []   <- ZERO

1,030 rows carrying an event type and nothing else. `ThreatName`, `Path`,
`ProcessName`, `Action`, `NewValue`, `OldValue` and `FeatureName` are present
in the EVTX record and are all discarded.

**The consequence, which is the point of this entry.** A row that says
`defense_configured` and nothing more cannot answer *which* setting changed,
*from what*, or *to what*. So:

  * **Defender exclusion paths are invisible.** An actor adding
    `Add-MpPreference -ExclusionPath C:\Users\Public` before dropping a
    payload produces a 5007, and this pipeline records that *something* was
    configured. That is the single most common pre-drop evasion step and the
    family that should catch it is blind to it.
  * A detection (1116) cannot name the threat or the file, so the one family
    that carries an AV verdict cannot report the verdict.
  * **`defense_disabled` (5001) measured ZERO rows** on both collections
    surveyed, against 1,030 for 5007. Whether that is correct or a second
    gap is not established here.

**This is the same shape as D-055 and D-065**, and it is the third instance:
a channel parsed and typed while the fields that give it meaning are dropped,
so the family looks covered from the grid and answers nothing at row level.
D-065 was BITS, D-055 was `ps_classic`, this is Defender.

**Not fixed here.** The fix is a `keep` tuple per EID plus a CD-012
declaration in `docs/details-schema.md` before any key is emitted, and that is
parser work, outside the scope of the rule batch that found it. It is
tractable -- D-065 is the worked example, and the same `keep`-branch pattern
applies.

**Until it is fixed, `evtx.defender` supports no rule at all.** The eight
external candidates are recorded in the sort output rather than written, and
the technique-coverage grid should not read this family as available.


---

## D-070  A parser fix does not produce a rule, and nothing tracks the gap

Found 2026-09-20, prompted by the observation that `evtx.bits` and
`evtx.ps_classic` were both repaired in the parser work and neither acquired
a rule.

**Measured. Of the 38 families CD-007 declares, 14 are named by the `select`
block of any rule:**

    evtx.security 13   registry 5   recyclebin 3   evtx.system 3
    browser 3   prefetch 2   lnk 2   srum 1   services 1
    jumplist 1   evtx.wmi 1   evtx.rdp 1   evtx.powershell 1   amcache 1

**Twenty-four families are parsed and read by no rule**, including both
families whose parser defects were fixed specifically to make them usable:

  * **`evtx.bits` (D-065, fixed 2026-09-19).** The fix landed `url`, size,
    `hr`, `jobOwner` and a joinable `entity.exe_name` from EID 3's
    `processPath`; D-066 corrected the EID 4/5 labels. Measured, the family
    now carries 1,241 rows across five event types with 14 details keys.
    **No rule selects it.** The reason is recorded and is not an oversight:
    T1071.001 measured `measured-no-discriminator` because every BITS
    transfer in the corpus is vendor update traffic, so there is no positive
    class. The parser is fixed; the technique is still unwritable *here*.
  * **`evtx.ps_classic` (D-055).** 1,489 rows across four event types with
    seven details keys including `host_application` and `ps_command_line`.
    **No rule selects it.** R-ATOMIC-0003 reads `evtx.powershell` (4104)
    only, and was never widened to the classic channel -- which is what D-055
    was found while investigating.

**Why this is a defect and not a backlog item.** The grid tracks TECHNIQUE
coverage, and the defect log tracks parser correctness. Neither tracks the
state *"family parses correctly, carries usable fields, and no rule reads
it"*. So a family can pass every check the project runs and contribute
nothing, and the only way to notice is to grep the `select` blocks, which
is what produced the table above.

The two states are genuinely different and the distinction is the entry:

  * **`evtx.bits`** -- no rule is CORRECT. C-05: the scenario never delivered
    over BITS, so there is nothing to detect. Writing one would encode two
    vendors' update endpoints.
  * **`evtx.ps_classic`** -- no rule is an OMISSION. The channel records
    engine start/stop and the host application for every PowerShell session,
    including the interactive `powershell.exe` sessions the T1059.001 work
    measured at 149 rows on s1_v2 and 65 on s1_v3. Nothing reads them.

**Not fixed here.** The `ps_classic` gap is a candidate Class 2 rule and is
NOT written in this batch, because the honest predicate is not obvious: the
measured base rate is 1,141 `ps_provider_start` rows on two collections, and
"a PowerShell session started" is not a detection on any host where
PowerShell is used. Naming it costs nothing; writing a bad rule for it would.

**What would close this**: a per-family column in the coverage grid recording
*parsed / has usable fields / read by a rule*, so the gap is visible without
grepping. Proposed, not built -- the grid is a shared document and the column
affects how Person A reads it.


## D-071

**`phase:` is a mandatory schema key added inside a Person A file, and it is a
schema change that the version string does not record.**

Filed 2026-09-20, with the change. Status: point 2 RESOLVED the same day
(schema 2.1.0, f655858 + the follow-up commit). Point 1 OPEN for Person A
review; the code is committed and green.

**What was added.** A top-level `phase:` key on every rule, closed set
`delivery` / `execute` / `persist` / `destroy`. Three lines of enforcement in
`rules/validate_rules.py`: a `PHASES` frozenset, `"phase"` appended to
`REQUIRED_TOP`, and one `report.error` beside the existing `severity` check.
All 24 rules tagged. `Rule.phase` added to `core/ruleset.py`, defaulted to
`""`, read by nothing.

**Why this is filed rather than just done.** Two things about it are not
routine, and both were decided rather than defaulted:

1. **It crosses the ownership line that `class:` deliberately did not.**
   `rules/**` is Person A's per `rules/schema.md:12` and
   `shared/CONTRACT-RULES.md` section 5. When `class:` was added on 2026-09-20
   the same question came up and was answered the other way: enforcement went
   into `core/entity_score.py` and `tests/`, and the validator was left alone,
   leaving "`rules/schema.md` has no paragraph on `class:`" as a pending
   Person A item. The `phase:` brief asked for the validator change directly,
   so it was made. The result is that the two sibling metadata fields are
   enforced in two different places for no reason intrinsic to either.
   `rules/schema.md` now owes a paragraph on **both**.

2. **RESOLVED -- a rule stamped `2.0.0` briefly failed the `2.0.0`
   validator.** For one commit, `phase:` was required while every rule still
   declared the version that did not require it. `SCHEMA_MAJOR_COMPATIBLE`
   does not catch this -- it checks the major only -- so the inconsistency was
   invisible to the gate and recorded here instead.

   Closed on Person B's instruction the same day: *"Adding a required field is
   breaking; 2.0.0 rules failing a 2.0.0 validator is the wrong end state."*
   `SCHEMA_VERSION` is now `2.1.0`, all 24 rule files are restamped (from a
   mix of `1.2.0`, `1.3.0` and `2.0.0`), and `rules/schema.md` carries the
   header bump and a changelog row. That row states plainly that, unlike every
   other minor bump in its table, 2.0.0 files do **not** still load, and that
   strict semver would call this major -- the label is Person B's call, made
   explicit rather than hidden by the number.

   Stamping 1.x files to 2.1.0 is safe for behaviour: `schema_version` is read
   in `core/ruleset.py` only to check major-compatibility and then stored, and
   nothing in the loader or engine branches on it. It does propagate into
   `Finding.rule_version` / `schema_version` and therefore into `run.json` and
   the HTML report, which is an output change and not a ranking one.

**What is NOT affected.** No rule predicate, `expected:` block, weight,
severity, or `class:` value changed -- the diff is 24 files at exactly +1 line
each. Nothing reads `Rule.phase`, so matching and scoring are bit-identical
and the entity-identity check was not re-run (its inputs did not move). The
Class 2 exclusion in `entity_score.aggregate` is untouched.

**The five-stage set, and where it parts company with the ranking map.**
The set was four on the first commit, matching
`docs/evidence/phase-span-2026-09-20.md`. Person B widened it to five the same
day, with the reason: *"The four-stage map came from the scenario, not a
taxonomy -- egress and exfil belong in the set."* That is the corpus-fit risk
the phase-span document states about itself, now acted on: the map's stages
are the four steps this scenario happened to contain, which is a property of
the corpus rather than of intrusions.

`exfiltrate` therefore exists in the rule schema and **not** in the ranking
map, and the two layers now disagree about exactly one event type:
`network_usage`, which the map files under EXECUTE because it has no exfil
bucket, and which R-ATOMIC-0014 (T1041) declares `exfiltrate`. The map was
not edited to match -- it records a measurement, and editing it would make it
assert something it never measured. The disagreement is deliberate, is scoped
to that one type, and
`tests/test_schema_v2_features.py::TestEveryRuleDeclaresAPhase` drops
`network_usage` from its lookup with that reason written beside it.

**One assignment remains judgement rather than lookup.** R-ATOMIC-0010 and
0013 are T1052.001 and R-ATOMIC-0014 is T1041, so all three are now lookups
against the technique. R-ATOMIC-0012 is not: it selects `file_opened`, which
the map leaves unmapped as a record-keeping type, and its technique is
T1204.002 -- user execution via a shortcut carrying arguments. It stays
`execute`. It was grouped with 0010 and 0013 in the first report because all
three select the same event type, and that grouping was read as three exfil
rules; the technique field is what settles it.

**What would close this**: Person A's ruling on where enforcement belongs,
a `schema.md` paragraph for `class:` and `phase:`, and a decision on whether
the schema version moves.
