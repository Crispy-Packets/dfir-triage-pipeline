# OD-01 Phase 6 — relational / cross-family features (2026-09-22)

**Pre-registered before the run.** The anomaly layer has never seen the entity's
*chain* signal — how many families it appears in, how long its activity spans,
whether a download precedes execution. This is the one feature family left
untried. It was deferred three times with a consistent reason: the deterministic
rules already encode that signal (the R-CORR correlation rules and the verdict
panel), so feeding it to the ML is re-deriving what the rules already prove. This
probe measures whether the ML sees it *independently* or merely re-derives it.

The "both" layer is already 1/444; this probe changes only the **ML-only** rank
and answers "does the anomaly layer independently rank the chain." It does not
change the headline — the layer ranks, the rules detect.

## Provenance discipline (why three features, not four)

`phase_span` is **excluded**. It is computed from `rule.phase` on `Finding`
objects — the verdict panel piped back into the ML. Any hand-built
artifact→phase map is the same rule taxonomy re-encoded. It cannot be an input
under any framing.

The three admitted features are computed from **raw events only**, one row per
entity, over all 38 parsed families:

| feature | definition | provenance |
|---|---|---|
| `family_count` | distinct `source_artifact` over the entity's events | raw |
| `activity_span_hours` | last − first event timestamp | raw (difference, not wall-clock — D-074 safe by construction, still leak-tested) |
| `download_precedes_exec` | 1 if a browser row ts < min exec-family ts | raw, but *is* the R-CORR download→exec check from raw events |

If `download_precedes_exec` is the column that moves the rank, the finding is
stated plainly: **the ML re-derived the rule.**

## Pre-registered outcomes

- rank improves **and** payload's feature values are shared with the installers
  (npp, onedrivesetup) → rule re-derived, not independent signal.
- rank improves **and** payload is isolated on the relational columns →
  independent signal (the interesting case).
- flat → relational signal is not rank-bearing for the ML.
- any column fails the +6.0pp leak bar → dropped, named.
- fails distinct-ratio (0.25) or row-floor (50) guard → that is the result;
  guard not relaxed.

## Result

**Outcome 1 (pre-registered): the rank improves, but by re-deriving the rule.**
The relational pseudo-family ranks the payload **2/443** (raw) and **1/443**
once a timestamp confound is removed — but the improvement is not independent
chain signal. It is the download→exec rule, re-encoded.

### The rank is carried by `download_precedes_exec`, which is the R-CORR set

Exactly **three** entities in s1_v3 have `download_precedes_exec = 1`:

    invoice_scan.exe            [11 families, 46.8 h, dl<exec 1]   <-- payload
    npp.8.9.8.installer.x64.exe [ 9 families, 81.4 h, dl<exec 1]
    vlc-3.0.23-win64.exe        [ 8 families, 34.8 h, dl<exec 1]

That is the R-CORR download→exec correlation set — the same entities the rules
already surface. A rare binary value is anomalous to any scorer (IF and MODA
agree: both rank the payload 2/443), so the ML is not seeing the chain; it is
re-deriving the one rule that already fires on it. `family_count` does not
isolate the payload either — `vboxtray.exe` spans 10 families and is benign, and
the payload's `[11, 46.8, 1]` sits beside npp's `[9, 81.4, 1]`, not apart from
it.

### The payload is tied with the installers, not separated from them

Removing the timestamp confound (below) lifts the payload to rank 1/443, but the
top three share **one identical anomaly score** (0.98357): invoice_scan, npp and
vlc are indistinguishable to the model. Rank 1 is a tie-break by name, not
separation. An analyst handed this ranking sees the attack tied with two
legitimate installers — which is the deferral's point: the relational features
carry the download→exec signal and nothing that distinguishes a malicious
download from a benign one. That distinction is what the *rules* provide
(R-CORR + the verdict panel), and it is why the "both" layer is 1/444 while this
ML-only view is a 3-way tie.

### Sensitivity 1 — the timestamp confound (labelled, not the headline)

The raw run put `vlc` at rank 1 on a 3.73-million-hour activity span. That value
is the **FILETIME zero sentinel** (`1601-01-01`), emitted by `browser_profile`
and `ntfs_logfile` rows and confirmed by inspection, not chosen by rank. Excluding
timestamps before `2000-01-01` (justified as pre-XP, a value filter not a rank
filter) removes it; the payload then ranks 1/443 as the tie above. Either way the
finding is unchanged — the confound moved *other* rows, never the payload's
membership in the download→exec trio.

### Sensitivity 2 — the pre-registered drop path fails the guard

With `activity_span_hours` dropped (the leakiest by construction), the two
remaining columns — `family_count` (int) and `download_precedes_exec` (binary) —
collapse to **12 distinct vectors over 368 training rows, ratio 0.033**, far
below the 0.25 distinct-ratio floor. Not modellable. This is a pre-registered
outcome, reported, not worked around: two low-cardinality columns cannot support
a per-entity forest.

### Leakage and guards (full 3-column set)

    column                    baseline  best    delta   verdict
    family_count               54.6      55.5   +0.9    clean (< +6.0)
    activity_span_hours        54.6      56.7   +2.1    clean (< +6.0)
    download_precedes_exec     54.6      54.6   +0.0    clean

    distinct-ratio 0.886 (368 rows, 326 distinct)  PASS
    row floor 50                                    PASS
    clean_c self-outlier rate (IF)  0.052           in band

No column trips the +6.0pp leak bar, so the rank is not a collection-identity
artifact — it is genuine signal, that genuine signal just being the rule.

## What Phase 6 settles

The relational / cross-family lever — the one feature family the ML had never
seen — was built, leak-tested, guarded, and measured. It ranks the payload
1–2/443, higher than any single artifact family (amcache 1.0% was the prior
best). But the rank is carried entirely by `download_precedes_exec`, which
selects exactly the R-CORR download→exec set, and the payload lands in a 3-way
tie with two benign installers it cannot be told apart from. The ML re-derives
the rule; it does not see the chain independently. This is the reason the lever
was deferred three times, now measured rather than asserted.

It is **not** a shipping candidate, and not because it failed — because it
succeeded at the wrong thing. Adding it would feed the verdict panel's own output
back into the triage ranking and report a rank the rules already produce (and
produce *better*: the rules separate the payload from the installers; the ML ties
them). Isolation Forest stays the default; no flag is added for this lever. The
headline is unchanged: the anomaly layer ranks, the rules detect, and the "both"
layer at 1/444 is the deterministic rules doing the separating.
