Status: DRAFT — requires Person A sign-off before parser work begins.

Signed by Person A on: \_\_\_\_\_\_\_\_\_\_



CD-001  confidence scale: ordinal ("high","medium","low"). Describes confidence in the

&#x20;       ACTION claim only (did this thing happen). Path or attribution uncertainty goes

&#x20;       in details, never by lowering confidence.



CD-002  event\_id: sha256 over

&#x20;       timestamp|source\_artifact|event\_type|action|source\_file|source\_locator|path,

&#x20;       0x1F separated, first 16 hex chars. Derived property, not a stored field.

&#x20;       Deterministic across runs by design. Rationale: uuid4 would make two runs over

&#x20;       the same collection produce different CSVs, breaking the determinism gate,

&#x20;       timeline hashing, output diffing and regression tests.



CD-003  source\_file: collection-relative POSIX string (e.g. "C/Windows/Prefetch/X.pf").

&#x20;       Never absolute, never platform-specific separators. Rationale: absolute paths

&#x20;       differ per machine, break shared expected-value tests, and leak host paths

&#x20;       into the report.



CD-004  source\_locator: MUST be unique within a source\_file.

&#x20;       EVTX uses "EventRecordID=<n>". Prefetch uses "run\_slot=<i>".

&#x20;       A loop counter is NOT acceptable: it is stable within a run but does not

&#x20;       resolve back to the evidence. CONSTRAINS PERSON A'S EVTX PARSER.



CD-005  Event is frozen (immutable after construction). details is compare=False,

&#x20;       which keeps Event hashable despite holding a dict. Week 3 annotations attach

&#x20;       to Finding / EntitySummary records keyed by event\_id, never back onto Event.



CD-006  Timestamps: timezone-aware with utcoffset() == 0. Serialised with

&#x20;       isoformat(timespec="microseconds") in both the hash input and the CSV column,

&#x20;       so hash input is fixed-width and column width does not vary. Parsers

&#x20;       normalise; the model rejects.

