# Per-artifact timezone assumptions

One line per parser, appended in parser order. Append only; never rewrite an entry.
Every parser normalises to UTC at parse time (CD-006); the Event model rejects
anything with a non-zero offset.

prefetch - last-run timestamps are Windows FILETIME, defined as UTC. Converted
           directly, no local-time inference applied. Confirmed against library
           version <pinned on Day 4>.
evtx     — <Person A>

CD-006 (docs/contract-decisions.md) specifies: parsers must use
.replace(tzinfo=timezone.utc) for values documented as UTC and
.astimezone(timezone.utc) only for values that already carry an offset.

evtx library and pin: evtx==0.12.1
TimeCreated/@SystemTime is UTC per the Microsoft event schema.
Every value observed across all three collections is Z-suffixed with six
fractional digits.
parse_systemtime converts an explicit offset rather than overwriting the
timezone, in conformance with CD-006.
That conversion branch and the seven-digit fractional truncation branch are
covered by unit test only, because no collected evidence exercises either.

timestamp_type - closed vocabulary: recorded, last_run, presence. Validated on
                 construction. Participates in the event_id content hash.
prefetch       - windowsprefetch 4.0.3 returns run times as naive strings
                 ('YYYY-MM-DD HH:MM:SS.ffffff'). Parsed with fromisoformat and
                 the naive value ESTABLISHED AS UTC. Never astimezone() on a
                 naive value.

                 Verdict method (step 119, 2026-08-27): the library's string for
                 INVOICE_SCAN.EXE reads 2026-08-23 22:57:15.832788 against a
                 ground-truth execution of 2026-08-23T22:57:22.536771Z. Delta
                 -6.70s, not a whole hour. Confirmed independently of the
                 library by decoding the raw lastRunTime bytes as FILETIME
                 (134319994358327870 -> 2026-08-23T22:57:15.832787+00:00),
                 matching the library string to 1 microsecond. The library
                 applies no conversion. Host is UTC+3; a localised value would
                 have read 01:57:15. Step 144's offset correction is NOT
                 applied. See docs/evidence/prefetch-spike-s1v2.txt and D-013.

                 The residual seconds are artifact behaviour: Prefetch writes
                 the run time when the OS completes the application trace, a few
                 seconds after the user action the ground truth records. Only a
                 WHOLE-HOUR delta indicates a timezone fault.
