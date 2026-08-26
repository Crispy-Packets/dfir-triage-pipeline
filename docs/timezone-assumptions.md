# Per-artifact timezone assumptions

One line per parser, appended in parser order. Append only; never rewrite an entry.
Every parser normalises to UTC at parse time (CD-006); the Event model rejects
anything with a non-zero offset.

prefetch — last-run timestamps are Windows FILETIME, defined as UTC. Converted
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
