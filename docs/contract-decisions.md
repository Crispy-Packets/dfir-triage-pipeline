# Contract decisions

Status: DRAFT - requires Person A sign-off before parser work begins.
Signed by Person A on: __________

CD-001  confidence scale: ordinal ("high","medium","low"). Describes confidence in the
        ACTION claim only (did this thing happen). Path or attribution uncertainty goes
        in details, never by lowering confidence.

CD-002  event_id: sha256 over
        timestamp|source_artifact|event_type|action|source_file|source_locator|path,
        0x1F separated, first 16 hex chars. Derived property, not a stored field.
        Deterministic across runs by design. Rationale: uuid4 would make two runs over
        the same collection produce different CSVs, breaking the determinism gate,
        timeline hashing, output diffing and regression tests.

CD-003  source_file: collection-relative POSIX string (e.g. "C/Windows/Prefetch/X.pf").
        Never absolute, never platform-specific separators. Rationale: absolute paths
        differ per machine, break shared expected-value tests, and leak host paths
        into the report.

CD-004  source_locator: MUST be unique within a source_file.
        EVTX uses "EventRecordID=<n>". Prefetch uses "run_slot=<i>".
        A loop counter is NOT acceptable: it is stable within a run but does not
        resolve back to the evidence. CONSTRAINS PERSON A'S EVTX PARSER.

CD-005  Event is frozen (immutable after construction). details is compare=False,
        which keeps Event hashable despite holding a dict. Week 3 annotations attach
        to Finding / EntitySummary records keyed by event_id, never back onto Event.

CD-006  Timestamps: timezone-aware with utcoffset() == 0. Serialised with
        isoformat(timespec="microseconds") in both the hash input and the CSV column,
        so hash input is fixed-width and column width does not vary. Parsers
        normalise; the model rejects.

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