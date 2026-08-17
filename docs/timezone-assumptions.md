# Per-artifact timezone assumptions

One line per parser, appended in parser order. Append only; never rewrite an entry.
Every parser normalises to UTC at parse time (CD-006); the Event model rejects
anything with a non-zero offset.

prefetch — last-run timestamps are Windows FILETIME, defined as UTC. Converted
           directly, no local-time inference applied. Confirmed against library
           version <pinned on Day 4>.
evtx     — <Person A>