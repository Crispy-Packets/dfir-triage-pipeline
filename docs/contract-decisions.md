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
        for Prefetch. EventRecordID uniqueness within each .evtx remains to be
        confirmed by Person A.

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
        spike, not by assumption. See D-013 in the challenges log.

CD-007  Fixed event vocabulary. Both parsers draw from the same strings so the
        timeline does not fragment into synonyms.

        Security.evtx  4624  ->  evtx.security  logon
        Security.evtx  4625  ->  evtx.security  logon_failed
        Security.evtx  4688  ->  evtx.security  process_exec
        Security.evtx  4720  ->  evtx.security  account_created
        Security.evtx  1102  ->  evtx.security  log_cleared
        System.evtx    7045  ->  evtx.system    service_install

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

CD-013  USB-based initial access (ATT&CK T1091) is out of scope.

        Reconstructing it requires USBSTOR registry and setupapi.dev.log parsing,
        neither of which is among the seven declared artifact families. Adding an
        eighth family mid-project is scope creep.

        Ground-truth scenarios therefore use browser-sourced delivery, which
        produces artifacts within scope: browser history, Zone.Identifier, MFT.

        Removable-media delivery is recorded in Future Work. Having considered a
        vector and excluded it with a stated reason is a stronger position than not
        having addressed it.

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
