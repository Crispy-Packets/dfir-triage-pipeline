# Contract decisions

Status: DRAFT - requires Person A sign-off before parser work begins.
Signed by Person A on: __________

---

CD-001  confidence scale: ordinal ("high","medium","low"). Describes confidence in the
        ACTION claim only (did this thing happen). Path or attribution uncertainty goes
        in details, never by lowering confidence.

CD-002  event_id: sha256 over
        timestamp|source_artifact|event_type|action|source_file|source_locator|path,
        0x1F separated, first 16 hex chars. Derived property, not a stored field.
        Deterministic across runs by design. Rationale: uuid4 would make two runs over
        the same collection produce different CSVs, breaking the determinism gate,
        timeline hashing, output diffing and regression tests.

        Verification vector, for checking an implementation against this clause:
            timestamp      = 2026-08-10T10:32:07.000000+00:00
            source_artifact= prefetch
            event_type     = process_exec
            action         = executed invoice_scan.exe
            source_file    = C/Windows/Prefetch/INVOICE_SCAN.EXE-A1B2C3D4.pf
            source_locator = run_slot=0
            path           = (empty)
            -> event_id      f38faa7761e41e80
        A hash loop with the fields in a different order, a different separator or a
        different timespec produces a STABLE but WRONG id that no behavioural test can
        detect. This vector is the only check for that class of error.

CD-003  source_file: collection-relative POSIX string (e.g. "C/Windows/prefetch/X.pf").
        Never absolute, never platform-specific separators. Rationale: absolute paths
        differ per machine, break shared expected-value tests, and leak host paths
        into the report.

        Applies equally to the SHA-256 evidence manifests under groundtruth/, which
        store a RelativePath column rather than Get-FileHash's absolute Path.

CD-004  source_locator: MUST be unique within a source_file.
        EVTX uses "EventRecordID=<n>". Prefetch uses "run_slot=<i>".
        A loop counter is NOT acceptable: it is stable within a run but does not
        resolve back to the evidence. CONSTRAINS PERSON A'S EVTX PARSER.

        Day 3 confirmation against real evidence: no duplicate .pf basenames exist in
        the scenario1 collection, so source_file plus source_locator is jointly unique
        for Prefetch. Day 5 confirmation for EVTX: EventRecordID is unique within each
        .evtx across all three collections, with no gaps, established by Person A in
        groundtruth/scenario1-verification.md. The clause is confirmed for both
        parsers.

CD-005  Event is frozen (immutable after construction). details is compare=False,
        which keeps Event hashable despite holding a dict. Week 3 annotations attach
        to Finding / EntitySummary records keyed by event_id, never back onto Event.

CD-006  Timestamps: timezone-aware with utcoffset() == 0. Serialised with
        isoformat(timespec="microseconds") in both the hash input and the CSV column,
        so hash input is fixed-width and column width does not vary. Parsers
        normalise; the model rejects.

        WARNING, and the reason this clause is not sufficient on its own: the guard
        checks the OFFSET, so a value that is tz-aware with a zero offset passes even
        if it is wrong. Calling .astimezone(timezone.utc) on a NAIVE datetime treats
        it as LOCAL time and shifts it by the host offset; the result is tz-aware,
        zero-offset, accepted by the model, and wrong by exactly the local offset.
        Parsers must use .replace(tzinfo=timezone.utc) for values documented as UTC
        and .astimezone(timezone.utc) only for values that already carry an offset.
        Which case applies is determined by execution during each parser's library
        spike, not by assumption. See D-013 in docs/defect-log.md.

CD-007  Fixed event vocabulary. Both parsers draw from the same strings so the
        timeline does not fragment into synonyms.

        Security.evtx  4624  ->  evtx.security  logon
        Security.evtx  4625  ->  evtx.security  logon_failed
        Security.evtx  4688  ->  evtx.security  process_exec
        Security.evtx  4720  ->  evtx.security  account_created
        Security.evtx  1102  ->  evtx.security  log_cleared
        System.evtx    7045  ->  evtx.system    service_install

        Registry hives  Run/RunOnce  ->  registry  persistence_autorun
        Edge History    downloads    ->  browser   file_download
        PowerShell/Operational 4104  ->  evtx.powershell  script_block
        Amcache.hve InventoryApplicationFile -> amcache  program_inventoried

        Added 2026-09-15, after measuring that KAPE collects 105 EVTX channels
        and this pipeline parsed three. Both carry their payload under UserData
        rather than EventData, which is why _user_data had to be generalised
        first: a record read with the wrong extractor parses without raising and
        yields an event with no fields.

        WMI-Activity/Operational  5861  ->  evtx.wmi  wmi_subscription
        TerminalServices-LSM      21,25 ->  evtx.rdp  rdp_session

        Added 2026-09-17. ONE FILE, THREE FAMILIES: the SYSTEM hive holds three
        structurally different artefacts with different timestamp semantics,
        and folding them into one family would mix presence with last-run.

        SYSTEM AppCompatCache  ->  shimcache  program_shimcached
        SYSTEM bam/dam         ->  bam        process_exec
        SYSTEM Services        ->  services   service_registered

        `program_shimcached` is deliberately NOT `process_exec`. Windows 10 and
        11 populate the compatibility cache on enumeration as well as on run,
        so a Shimcache entry attests PRESENCE and nothing stronger. Spelling it
        process_exec would let a correlation rule join it to a download and
        claim an execution the artefact never recorded.

        `bam` DOES emit process_exec, sharing the string with Prefetch and 4688
        by the same contract that governs those two: a second spelling for one
        concept silently breaks every chain joined on event_type.

        Added 2026-09-17. SRUM, the only artefact in this pipeline that
        attests to HOW MUCH DATA an application moved.

        SRUDB.dat {973F5D5C-...}  ->  srum       network_usage
        SRUDB.dat {D10CA2FE-...}  ->  srum       resource_usage

        ONE FAMILY, TWO EVENT TYPES, which is the opposite of the SYSTEM hive's
        choice and for a consistent reason: Shimcache, BAM and Services have
        different TIMESTAMP SEMANTICS and had to be separated. SRUM's two
        providers share one clock, one id map and one flush cycle -- they are
        two measurements of the same sampling run -- so they share a family and
        differ by event_type.

        `network_usage` is deliberately NOT `file_download`. A download is a
        transfer with a source URL and a target path, which the browser records;
        SRUM records an application's byte counters over an interval and names
        neither endpoint. Spelling them the same would let a rule claim a URL
        that no artefact holds.

        `resource_usage` carries no execution claim either, and is NOT
        `process_exec`. SRUM samples running processes; a row means the program
        was alive during an interval, which is weaker than Prefetch's claim and
        arrives without a start time.

        Added 2026-09-17. The SAM hive, which is not a log and survives a
        Security-log clear intact.

        SAM Domains\Account\Users -> sam        local_account

        `local_account` is a new event_type rather than a reuse of
        `account_created`. 4720 records a CREATION EVENT; SAM records that an
        account EXISTS NOW, with a logon count SAM maintains itself. Spelling
        them the same would let R-CORR-0005 join a SAM record as if it were a
        creation and report an interval between an account existing and an
        account signing in, which is not a claim about anything.

        The distinction is the same one drawn for `service_registered` below,
        and it exists for the same reason: an account created before the log's
        retention window, or after a clear, is in SAM and nowhere else.

        `service_registered` is distinct from `service_install` (System 7045).
        7045 records an INSTALLATION EVENT; the registry records that a service
        EXISTS NOW. A service installed before the log's retention window, or
        after a System-log clear, exists in the registry and nowhere else --
        which is the point of parsing it.

        5861 is the only WMI EID taken. 5857-5860 are provider lifecycle and
        query telemetry written constantly by normal Windows operation; 5861
        records a PERMANENT event subscription, which is the artifact fileless
        WMI persistence leaves (T1546.003).

        21 and 25 are the only TerminalServices EIDs taken. Both carry the
        `Address` field, which separates a remote session from a local console
        one; 22/23/24/39/40 describe the end of a session rather than its
        origin.

        Prefetch also emits process_exec. This sharing is deliberate: Week 3's
        correlation rules join on event_type plus entity, so a second spelling
        for the same concept would silently break the download-to-execution
        chain. CONSTRAINS PERSON A'S EVTX PARSER.

CD-008  Side effect of CD-005: two Events differing ONLY in details compare equal
        and deduplicate in a set. Accepted, because source_locator distinguishes
        all real records (CD-004). Revisit if a future parser cannot supply a
        distinguishing locator.

CD-009  Week 1 timezone assumption: Prefetch last-run times are FILETIME in UTC;
        EVTX TimeCreated/@SystemTime is UTC. Parsers convert explicitly and never
        rely on the reader's local conversion. Recorded per-artifact in
        docs/timezone-assumptions.md.

---

CD-010  Entity identity is DERIVED, not stored.

        `path` holds the value exactly as recorded by the artifact. It is provenance
        and is never normalised. CD-003 governs source_file, not path.

        The same executable appears in incompatible forms across artifact families:
            Prefetch     \VOLUME{01d1e...}\USERS\JANED\DOWNLOADS\INVOICE_SCAN.EXE
            EVTX 4688    C:\Users\janed\Downloads\invoice_scan.exe
            Amcache      drive-letter path
            Registry Run may be quoted and carry arguments
        None of these string-match. Joining on `path` would silently produce zero
        correlations: correct rows, no findings, no error.

        Entity identity is therefore computed in Week 3 by a documented
        normalisation - lowercased, volume-GUID and device notation resolved to a
        drive letter where determinable, arguments stripped, surrounding quotes
        removed - into Finding / EntitySummary records, never written back onto
        Event.

        Parsers MUST preserve enough raw material for that derivation to be
        possible. Specifically, Prefetch records the volume-notation path AND the
        executable name separately in details. CONSTRAINS BOTH PARSERS.

        AMENDED 2026-08-27 with spike evidence.

        Prefetch records referenced paths in volume-GUID notation, uppercase.
        Observed in collection_clean_b, windowsprefetch 4.0.3:

            \VOLUME{01dd01162add2da6-a62af538}\WINDOWS\SYSTEM32\NTDLL.DLL
            \VOLUME{01dd01162add2da6-a62af538}\WINDOWS\SYSTEM32\KERNEL32.DLL
            \VOLUME{01dd01162add2da6-a62af538}\WINDOWS\SYSTEM32\KERNELBASE.DLL
            \VOLUME{01dd01162add2da6-a62af538}\WINDOWS\SYSTEM32\LOCALE.NLS
            \VOLUME{01dd01162add2da6-a62af538}\WINDOWS\SYSTEM32\APPHELP.DLL

        Security 4688 records NewProcessName as C:\Windows\System32\ntdll.dll.
        These cannot string-match under any casing.

        Parsers emit path values exactly as the source artifact records them.
        A parser must never rewrite volume notation into a drive letter: that
        asserts a mapping the artifact does not contain, and a wrong mapping
        silently falsifies evidence while provenance still resolves.

        Normalisation is owned by core/entity.py. The volume-serial to
        drive-letter map is read from the collection manifest. The serial is
        available from the Prefetch record as volSerialNumber (observed value
        'a62af538'; note the attribute is NOT volumeSerialNumber, which does
        not exist on this library).

        Primary join key: case-folded executable basename, available from
        executableName without resolving any volume.

        Full-path agreement, where the volume map permits it, is a
        corroborator: it raises entity score and appears in the report, but is
        not required for a chain to form.

        Known cost: basename matching joins distinct binaries sharing a name.
        Measured against the clean baselines and reported in the evaluation.

        TWO volume serials appear in the collected Prefetch, not one. Measured
        in collection_clean_b, 2026-08-27:

            a62af538   1216 events, 146 distinct binaries -- the target system
                       volume. This is the serial CD-010 refers to throughout.
            5659c38d     32 events,   6 distinct binaries -- CONSENT.EXE,
                       GKAPE.EXE, KAPE.EXE, POWERSHELL.EXE, RG.EXE,
                       ROBOCOPY.EXE. Exclusively investigator tooling: this is
                       the collection tool volume, not the target disk.

        The volume-serial map in core/entity.py must therefore distinguish the
        target volume from the collector's own, and events on 5659c38d are tool
        noise by definition -- not scenario activity and not benign user
        activity for false-positive purposes. Reported in the evaluation rather
        than silently dropped.

CD-011  event_id is unique WITHIN a collection, not globally.

        source_file is collection-relative (CD-003), so identical artifacts in
        clean_a and scenario1 produce identical event_ids. Both clean baselines are
        taken from restores of the same snapshot and will contain byte-identical
        prefetch entries.

        Timelines from different collections must not be concatenated without
        carrying the collection name alongside, external to the Event record. This
        matters in Week 4, where clean_a and clean_b are combined for model
        training.

CD-012  details key schema is documented per event_type in docs/details-schema.md,
        maintained as each parser lands. The Week 4 feature extractor reads these
        keys directly, so an undocumented or renamed key breaks feature extraction
        silently.

CD-013  Removable-media initial access (ATT&CK T1091) is out of scope as a
        detection target: USBSTOR and setupapi.dev.log are not among the seven
        declared artifact families.

        The Week 1 Scenario 1 collection delivered the binary by removable
        media. It is superseded and is not evidence for any evaluation result.

        collection_s1_v2 delivers the binary by HTTP download in Edge, with
        Zone.Identifier ZoneId=3 confirmed. The download -> execution sequence
        rule is evaluable against collected evidence.

        Removable-media delivery is recorded in Future Work. Having considered a
        vector and excluded it with a stated reason is a stronger position than not
        having addressed it.

CD-014  Clean collection roles.

        clean_b is the reference baseline: the only clean collection containing
        benign user activity. Used for rule-engine false-positive measurement
        and as the training set for the optional anomaly layer.

        clean_a is an ambient-noise control, collected with no user activity
        present. A finding raised against it is system noise by definition; its
        false-positive count is a floor, not a rate.

        Both clean collections were collected with NAT enabled; collection_s1_v2
        was collected host-only. The clean collections therefore contain
        Windows Update and telemetry activity, including EID 7045 service
        installations, that the scenario cannot contain. Rules matching 7045
        account for this and the exclusion is reported.

        With one realistic clean collection, false-positive measurement and
        anomaly-model training draw on the same data. A third clean collection
        with a differing benign workload is recorded as a Week 2 candidate.

        7045 counts are recorded at step 191 once the EVTX parser is merged.

        Day 5 measurement, 2026-08-28. The NAT asymmetry recorded when this clause
        was written predicted extra EID 7045 service installations in the clean
        collections. The measurement is the reverse: clean_a and clean_b carry 16
        each, identical service-for-service, and collection_s1_v2 carries 23. The
        seven extra are VirtualBox Guest Additions, present in the scenario guest
        and absent from both baselines. No 7045 in any collection is attributable
        to Windows Update.

        This does not weaken clean_b as the reference baseline, but it changes what
        a 7045 finding means: a service present only in the scenario is explained by
        the Guest Additions difference before it is explained by the attack. The
        attack persisted via HKCU Run and installed no service.

CD-015  SHA-256 manifests are read with encoding="utf-8-sig". Verified BOM-free
        on 2026-08-25 (first bytes 22 52 65). utf-8-sig reads both forms, so the
        setting is safe regardless of how a future manifest is written.

CD-016  Evidence lives outside the repository, at %USERPROFILE%\dfir-evidence
        on Person B's host. Nothing under it is tracked, ignored, or reachable
        by any git operation.

        Reasoning: git clean -xdf removes ignored files. An ignore rule protects
        the repository from the evidence, not the evidence from the repository.
        The collections/ ignore rule is retained as defence in depth.

        Only the SHA-256 manifests and groundtruth/Scenario1.md enter version
        control. Note that .gitignore's negation is !groundtruth/*.csv --
        single-level. A manifest placed in a subdirectory would be silently
        dropped by git add.

CD-017  The collection-time manifest for collection_s1_v2 covers 793 of 817
        files. The 24 uncovered are registry hives, transaction logs, DPAPI
        blobs and desktop.ini. clean-s1-v2-sha256-supplement.csv, generated on
        2026-08-25 from the host copy, covers them and establishes integrity
        from receipt onward rather than from collection. The lab VM was
        decommissioned before the gap was found, so collection-time hashes for
        these files cannot be produced. clean_a and clean_b manifests are
        complete, verified by set comparison. See D-019.

CD-018  Prefetch emits one Event per populated entry in the run-time array.
        The artifact records at most eight run times regardless of how many
        times the binary ran, so Event count is a lower bound on executions,
        never an upper bound, and the report must not present it as a total.

        runCount as returned by windowsprefetch 4.0.3 is NOT a reliable
        cross-check. The library reads it at offset 0xD0, which is incorrect for
        version-30 records: measured on 2026-08-27, 610 of 835 .pf files across
        the three collections reported len(timestamps) > runCount at that
        offset, and INVOICE_SCAN.EXE reported runCount 0 against a confirmed
        execution.

        The parser reads offset 0xC8 instead, where the invariant
        len(timestamps) <= runCount holds in 835 of 835 collected files and no
        file reports zero runs while carrying run times. The corrected value is
        emitted in details as run_count. A run count that cannot be read is
        omitted from details rather than emitted as zero: zero is a claim the
        artifact does not make. The offset correction lives in _records, inside
        the library adapter boundary, so record_to_events stays pure. See D-023.

CD-019  timestamp_type is a required Event field over a closed vocabulary:

            recorded   the source logged the event as it occurred (all EVTX EIDs)
            last_run   the artifact records only the most recent occurrence
                       (Prefetch)
            presence   the artifact evidences existence, not execution
                       (Shimcache, Amcache)

        Amended 2026-09-17, SAM. The vocabulary is defined by SHAPE, not by
        artifact: `last_run` means "the artifact records only the most recent
        occurrence", and SAM's last-logon -- one overwritten slot behind a count
        of 13 logons -- is exactly that shape despite recording an
        authentication rather than an execution. It takes `last_run`. A new
        `last_logon` term was considered and rejected: it would split one
        concept in two and break every rule reasoning over recency.

        SAM is also the first family whose timestamp_type VARIES BY RECORD. An
        account that has logged on carries a real FILETIME; one that never has
        falls back to the key's last write and emits `presence`. The static map
        in validate_rules.py can only state the dominant case, so
        MIXED_TIMESTAMP_TYPE names such families and a windowed step selecting
        one must exclude the never-used records explicitly.

        Validated in __post_init__; a value outside the set raises ValueError.
        It participates in the event_id content hash, so the same observation
        claimed as 'recorded' and as 'last_run' is not the same event. It is
        column 2 of the CSV, beside timestamp_utc, because it qualifies it.

        Hash vectors recorded at the change (fixture: 2024-01-15T12:00:00+00:00,
        prefetch, process_exec, executed, Windows/Prefetch/NOTEPAD.EXE-A1B2C3D4.pf,
        run_0, C:\Windows\System32\notepad.exe):
            before  37bdad927b68753b   (7 hashed fields)
            after   63673bce6a5c5e04   (8 hashed fields, timestamp_type=last_run)

CD-020  Not every file under Windows/Prefetch with a .pf extension is a
        Prefetch record.

        Op-*.pf are SysMain operational files with a different internal
        structure. windowsprefetch 4.0.3 parses them WITHOUT raising and yields
        the filename fragment as an executable name: Op-EXPLORER.EXE-7A3328DA
        was emitted as a binary with a run time. Silent fabrication, not a
        failure, so a run-summary failure count cannot detect it.

        can_handle excludes them by basename prefix. Three such files exist, one
        per collection. See D-025.

        A .pf allocated by the OS but never flushed is collected as a run of
        zero bytes. Five exist across the collections (DEFRAG.EXE-738093E8 in
        clean_a and clean_b, SVCHOST.EXE-CE29B0F4 in all three); each appears in
        its SHA-256 manifest, so they were collected and transferred intact. The
        parser yields no records for them rather than raising: an empty artifact
        is an absence of evidence, not a parser fault, and raising would inflate
        the failure count. The guard is narrow -- all header bytes zero -- so a
        genuinely malformed file still raises and is counted. See D-024.

---

## Facts established by execution during Week 1

Not contract clauses, but observations that constrain implementation and must not be
re-derived or contradicted.

**Collected path shapes are lowercase.** `C/Windows/prefetch/` and
`C/Windows/System32/winevt/logs/`, not the capitalised forms every planning document
assumed. Both parsers lowercase before matching, so casing is not relied on, but a
case-sensitive rule written against the assumed shape would have matched zero files
with no error. Confirmed against the real scenario1 tree on Day 3.

**Op-prefixed Prefetch files are not Prefetch records.** `Op-EXPLORER.EXE-*.pf` are
SysMain operational files with a different internal structure. The Prefetch parser
excludes them by name deliberately; allowing them through would produce an
unexplained entry in the run summary's failure list.

**The KAPE collection tree is flat.** Root is `C\` with no hostname or timestamp
prefix, and KAPE's own ConsoleLog and CopyLog sit alongside it at the top level.
Those two files are counted by the ingestion walker and are collector output rather
than evidence from the target machine - worth one line in the evaluation write-up.

**Toolchain rules that reject otherwise-correct code.** Under
`select = ["E","F","I","UP","B"]` with `target-version = "py311"`:
  - UP017 rejects `UTC = timezone.utc`. Use `from datetime import UTC`.
  - B017 rejects `pytest.raises(Exception)`. Assert the specific type;
    FrozenInstanceError subclasses AttributeError.
  - I001 rejects the two parser registration imports written as separate lines with
    only `# noqa: E402,F401`. Add `,I001` to the first, or use the parenthesised
    form. This surfaces at Day 5 integration, when the merge conflict is resolved by
    keeping both lines.


CD-021  Event.path for service_install carries the service ImagePath exactly as the
        7045 record writes it, which is a command line and not a path. Measured
        across all three collections on 2026-08-28: 54 of 55 service_install rows are
        not a bare filesystem path. Five forms occur -- quoted executable followed by
        arguments (27), an unquoted drive path with arguments (6), a \SystemRoot or
        UNC device path (7), an environment-variable form such as %SystemRoot% (14),
        and a bare drive path (1).

        Amended 2026-08-30 (D-032). The fourteen are two distinct forms, not one.
        Four carry an explicit variable (%SystemRoot%\system32\svchost.exe -k
        print, and %SystemRoot%\System32\VBoxService.exe). The other ten are
        root-relative driver images with no prefix at all --
        system32\DRIVERS\RsFx0800.sys and similar -- which the Service Control
        Manager resolves against %SystemRoot% implicitly. Every total in this
        clause was re-verified on 2026-08-30 and reproduces exactly; only the
        classification is refined, because a canonicaliser cannot treat an
        explicit variable and an implicit root alike.

        No normalisation is applied in Week 1. CD-010 already forbids a parser from
        rewriting what the artifact recorded, and inventing a path here would fabricate
        one for 54 of 55 rows. The consequence is that path is not a join key for
        service_install and must not be string-matched against Prefetch or 4688 paths.
        Week 3's core/entity.py owns extraction of the executable from the command
        line; until then the field is source text, not an identifier.

CD-022  Event.user carries the account exactly as the artifact recorded it. No case
        folding, no domain stripping, no mapping of well-known SIDs to a canonical
        name. Measured on clean_b, 2026-08-28: 24 distinct values across 10,455 EVTX
        rows.

        Scope note added 2026-08-30. Those 10,455 rows are evtx.security and
        evtx.system only, which was every EVTX row that existed when the figure
        was taken. The PowerShell channel was added afterwards (B-8), so the
        same collection now yields 11,452 EVTX rows and 26 distinct values. The
        two extra values are NT Service account spellings from the operational
        channel; the clause and its reasoning are unchanged. Re-verified in the
        original scope on 2026-08-30 and the figure reproduces exactly.

        Two of those values mean absent -- the empty string (6 rows) and the literal
        "-" (134 rows) -- and they are not interchangeable: "-" is a value the log
        wrote, whereas empty is a field the parser found missing. Four denote system
        contexts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, LocalSystem), and the same
        identity appears under more than one spelling, LOCAL SERVICE alongside
        NT AUTHORITY\LOCALSERVICE.

        Normalising these is a Week 3 decision, not a Week 1 one, because the mapping
        is a forensic claim about identity and belongs with the entity resolver that
        also owns volume-serial to drive-letter mapping. Recording it here fixes the
        Week 1 behaviour as deliberate rather than accidental: a rule reading user
        must match the recorded forms, and a count of distinct users is a count of
        recorded spellings, not of accounts.


CD-013 addendum, 2026-08-28. The re-collected scenario used no USB device at any
point. A residual USBSTOR enumeration for a Kingston DataTraveler 3.0 survives in
the collection_s1_v2 SYSTEM hive from the superseded first attempt; it is absent
from both baselines, and every recorded path for the delivered binary across
NTUSER.DAT, Edge History, ActivitiesCache.db, Defender MPLog and the recycle-bin
$I records is C:\Users\janed\Downloads\invoice_scan.exe. Removable-media
access stays out of scope, and no Week 1 result rests on the device. Recorded
because a USBSTOR key in an evidence hive otherwise invites the inference that
delivery was by USB. See docs/lab-setup.md.
