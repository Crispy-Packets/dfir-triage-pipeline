# A disk-image triage pipeline: architecture, method and measured limits

Thesis-chapter framing. Every figure below carries the command or document that
produced it; where a thing was not measured, it says so instead of estimating.
The four principles this work settled are stated in full in
`docs/principles.md` and summarised here in the position where they did their
work.

> **Scope of this chapter:** it describes the 24-rule build evaluated on the
> lab collections, the same build as the final report. Six server rules
> (R-ATOMIC-0019 to 0023, R-CORR-0007) and the evaluation on a real Windows
> Server 2022 break-in were added afterwards; see
> `docs/evidence/srv22-analysis.md`.

---

## 1. Problem

A disk-image triage tool reads a forensic collection — event logs, registry
hives, filesystem metadata, application artifacts — and must answer one
question for an analyst under time pressure: **which entities on this host
deserve attention first, and on what evidence?**

Two failure modes make that answer worthless rather than merely wrong.

The first is a **ranking that cannot be defended**. A score built from rules
whose accuracy was never measured produces an ordering nobody can justify
under questioning. The number exists; the warrant does not.

The second is a **coverage claim that conflates categories**. "We detect 30
techniques" says nothing unless a reader can tell which were validated against
an intrusion, which are written but never exercised, and which are impossible
given the evidence collected. Those are three different statements and only
one of them is a property of the tool.

The architecture below is organised around keeping those three apart.

## 2. Architecture

    KAPE collection (disk artifacts)
        |
        v
    38 curated parsers  -----------------> Event(timestamp, source_artifact,
        |                                        event_type, path, details{})
        v
    timeline (normalised, provenance-carrying)
        |
        v
    rule engine  -- 24 rules, atomic + correlation
        |
        +-- Class 1 (corpus-validated, 15) --> entity_score --> VERDICT panel
        |                                          |
        +-- Class 2 (known-behavior, 9) -----------|--------> CONTEXT panel
                                                   |
    anomaly layer (Isolation Forest, 7 families) --+--------> PRIORITISATION panel

Three properties of this shape carry the argument.

**Provenance is structural, not annotation.** Every `Event` requires
`source_file` and `source_locator` at construction; a parser cannot emit a row
that does not name the record it came from. Every finding names the events that
produced it. An analyst can always walk from a score back to a byte offset.

**The identity of an event is a content hash, not a row number.** `event_id` is
SHA-256 over the timestamp, artifact, type, action, provenance pair, timestamp
type and path — deliberately *not* over `details`, so enriching a parser's
extracted fields does not rewrite the identity of events already recorded.
That property was relied on when nine detail keys were added late in the work
(§5.3) and verified before relying on it, not assumed.

**The Class 1/Class 2 fork is the load-bearing split** and is the subject of
principle 1.

## 3. The Class 1 / Class 2 split

A detection rule can be sound and have no evidence behind it: it expresses a
real intrusion behaviour, its logic is defensible, and the validation corpus
never did that thing. Deleting it discards real coverage; keeping it as an
equal destroys the meaning of every number the tool reports.

**Class 1 (`corpus-validated`)** fires on the intrusion, does not fire on the
clean baseline, and carries measured per-collection base rates. It produces the
verdict and the score.

**Class 2 (`known-behavior`)** expresses a real behaviour the corpus never
exercised. It ships a documented false-positive profile instead of a detection
rate — because a detection rate would be fabricated — and produces context,
never rank.

Three engineering consequences follow, and each was learned by getting it
wrong first:

1. **Enforce where the number is computed.** The filter lives in
   `entity_score.aggregate`, not in the rule loader. A load-time check covers
   only rules that arrive through the loader; an object built by hand in a
   test, or any path reaching the engine without the validator, slips past it.
   One filter at the point of aggregation covers every path by construction.

2. **Choose the failure direction.** An unrecognised class string is treated as
   *unscoreable*, so a typo costs a contribution rather than inventing one. The
   typo itself is caught separately by a closed-set test over the files on disk.

3. **The split must survive into the output.** This is the half that was
   missing for a day: the score was correctly filtered while the report still
   rendered every finding under a heading reading "Verdict". A reader does not
   see the aggregation function; they see the page. Recorded as D-072, fixed by
   carrying `rule_class` into `run.json` (1.1.0 → 1.2.0), `findings.csv` and a
   separate context panel.

## 4. Evidence-class taxonomy

Before asking whether a technique is implemented, ask what kind of evidence it
would require. Four classes, and the boundary is the **collection method**, not
the parser:

| class | meaning | count |
|---|---|---|
| `disk-resident` | survives on disk; in scope | 27 |
| `requires-telemetry` | live/agent only — Sysmon, EDR, packet capture | 6 |
| `requires-domain` | written on a domain controller, not this endpoint | 6 |
| `requires-memory` | volatile only | 0 in this grid |

The last three eliminate candidates **structurally**. No amount of parser work
reaches them because the bytes were never collected, and that remains true if
the pipeline is rewritten.

The distinction this enforces is the point:

* *"Not observable in this evidence class"* is a claim about the world. It is
  stable, and a reader can act on it — by changing the collection, the only
  thing that would help.
* *"We did not implement it"* is a claim about effort. Reporting the second as
  the first inflates apparent coverage and misleads about what collecting
  differently would buy.

Each `not-observable` row names its specific missing observable — a packet
capture, EID 4769, `NTDS.dit` — rather than resting on the category.

## 5. Results

### 5.1 Ranking separation

Measured 2026-09-20 through the CLI on all five collections, reading
`run.json` (`run_json_version` 1.2.0). `SCORED_ENTITY_KINDS` is
`entity.exe_name` and `entity.user`, and the two rank **separately** -- so the
separation must be read per kind. Reporting one kind's spread as the result
is the comparison error the tables below exist to prevent.

**Executables (`entity.exe_name`) -- the payload is the top row and the margin
is clean:**

| collection | top executable | score | severity |
|---|---|---|---|
| clean_a | `cursorusersetup-x64-3.15.6.exe` | 86 | high |
| clean_b | `7z2602-x64.exe` | 86 | high |
| clean_c | `npp.8.9.8.installer.x64.exe` | 75 | high |
| **s1_v2** | `invoice_scan.exe` | **99** | **critical** |
| **s1_v3** | `invoice_scan.exe` | **99** | **critical** |

This is the 99-vs-86 headline, and it holds: the scenario payload outranks the
highest-scoring clean executable by 13 points on host 1 and 24 on host 2, and
is the only entity of either kind reaching `critical`.

**Users (`entity.user`) -- the margin is much narrower, and on host 1 it
inverts:**

| collection | top user | score | severity |
|---|---|---|---|
| clean_a | `youssef` | 97 | high |
| clean_b | `youssef` | 97 | high |
| clean_c | `vboxuser` | 92 | high |
| s1_v2 | `admin_local` | 93 | high |
| s1_v3 | `vboxuser` | 88 | high |

A clean host's ordinary user scores **97**, above the top user on either
scenario collection. Users accumulate autorun and account findings through
normal use, and nothing in the rule set distinguishes a busy legitimate user
from a compromised one. **The user ranking does not separate the scenario at
all** -- 99-vs-97 is the best case, and it is a comparison across kinds rather
than within one.

The honest statement of the result is therefore narrower than the headline:
**the separation is a property of the executable ranking.** The pipeline
identifies the payload, not the actor. That is the useful half for triage --
an analyst is pointed at `invoice_scan.exe` -- but a reader who takes "99 vs
86" as the tool's general discrimination will overestimate it, because the
same corpus puts a clean user at 97.

Class 2 findings appear in `findings.csv` and the context panel and contribute
zero to every score in both tables.

### 5.2 Coverage

24 rules — 15 Class 1, 9 Class 2. Eight grid states, because a two-state grid
forces honest answers into the wrong box:

| state | rows | meaning |
|---|---|---|
| `covered` | 11 | validated rule, measured base rates |
| `covered-known-behavior` | 10 | rule exists, corpus never exercised it |
| `observable-unwritten` | 9 | evidence present, rule not yet written |
| `measured, not exercised` | 2 | parsed and measured; behaviour absent |
| `measured-no-discriminator` | 13 | present in both classes, nothing separates |
| `not-observable` | 12 | evidence class excludes it |
| `structurally-out-of-scope` | 1 | — |
| `blocked` | 3 | specific named obstacle |

`measured-no-discriminator` is the most valuable state and the one a binary
grid destroys: it is a *measured negative*, and re-opening it wastes the
measurement that closed it. `observable-unwritten` is a backlog item. They look
identical in a binary grid and imply opposite next actions.

### 5.3 Parser depth

Measured across all 38 curated families and five collections, 3.08M rows.
Three families produced rows with zero detail keys — parse *success* without
parse *depth*. Two were repaired and one closed by decision:

| family | rows | before | after |
|---|---|---|---|
| `evtx.firewall` | 983 | 100% empty | **0%** |
| `evtx.defender` | 2,048 | 100% empty | **0%** |
| `evtx.winlogon` | 2,229 | 100% empty | unchanged, by decision |

`evtx.winlogon` carries exactly two fields across 2,229 rows: `Event` = 0 and
`SubscriberName` = `GPClient`. Two constants. Extracting them would add
declared keys that discriminate nothing.

Two null results are worth as much as the repairs: **no family declares a
detail key it never populates**, and the thin families are thin because the
artifact is thin, not because fields were dropped.

### 5.4 The anomaly layer: a measured negative

The unsupervised layer **ranks; it does not detect**. Nothing is flagged as an
outlier in either scenario collection. The 1-of-894 headline is the *rules*
layer placing the entity first with the anomaly ranking appended behind it; the
anomaly layer's own best position for the attack entity is 40th of 443.

**Coverage was tested directly and is not the limit.** All 38 parsed families
were evaluated for anomaly-model candidacy, not just the seven modelled:

| stage | families | result |
|---|---|---|
| parsed | 38 | every curated family |
| declared with a feature set | 7 | the artifacts that carry behavioural numerics |
| actually fit on clean_c | 3 | `amcache`, `prefetch`, `evtx.powershell` (the rest fail the row-count or distinct-vector guard) |
| undeclared, no usable key | 27 of 31 | carry no numeric/shape field a forest column could be computed from |
| undeclared, carry a key | 4 of 31 | `services`, `shimcache`, `evtx.bits`, `userassist` — tested |
| survive declaration + guards | 1 | `evtx.bits`, which carries **no attack row** |

The extension to all four candidates was built behind an off-by-default flag and
measured both ways: it added exactly one fitted family, one the attack never
touches, and moved the attack rank the wrong way. Coverage is not the limit
because the unmodelled families either do not carry the attack entity, do not
carry numeric variance, or carry it mid-distribution. The limit is that a disk
artifact records, about a single execution, only that it was unusual — and on a
real host, being unusual is not rare (`docs/evidence/od-01-phase3-feature-ceiling.md`).

**One leakage defect was found by this work and fixed (D-074).** The two
per-hour density features encoded *when the collection was taken* on the
families whose rows are timestamped by collection rather than by a per-event
clock. Removing them from the shared feature set — re-adding each only to the
families where it measured clean — did not cost rank; it recovered it, moving
the attack entity from 79th to 40th, because the leaking columns had been
promoting a crowd of collection-timing outliers above the quiet payload. The
fitted set was unchanged, so this is a cleaner ranking, not a different model.

**No accuracy figure is computable and none is given.** Four attack events in
2,304 is not a labelled test set, and labelling by collection would measure
collection identity — `hour_of_day` scores 86% that way, which is why it is an
excluded feature. With one ground-truth entity, every ranking metric reduces to
its position, so position is what is reported.

## 6. Two defect patterns

Both are failures of *verification* rather than of code, and both pass every
test present, because in each case the test is not looking at the thing.

### 6.1 Verification that cannot fail on the thing it checks

A passing check means nothing until you know it *could* have failed. Five ways
it cannot, each observed more than once in this project:

| pattern | the check examines | symptom |
|---|---|---|
| vacuous | nothing at all | iterates an empty collection; passes instantly |
| partial | some of the population, silently | population looks complete; never counted |
| wrong target | something adjacent to the claim | calls under the gate, bypassing it |
| out of scope | correctly, but cannot see the claim | an audit for *absent* entries cannot find a *wrong* one |
| in prose | nothing — asserted in a document | reads as established; never ran |

Countermeasures, in order of cost: assert the population size, not just the
result; route the check through the same code path as the claim; break the
thing deliberately once and watch the check go red; treat any document
assertion as unverified until a command produced it.

### 6.2 The parser drops the meaning-bearing field

A parser reports success, rows appear, counts look plausible — and the one
field a rule would need was never extracted. Every rule against that family is
unwritable and the reason is invisible from the row count. This is worse than a
parser that fails, which is loud.

**Measure parse depth, not parse success:** rows produced, distinct detail keys
carried, and whether those keys include the fields a rule would need. Only the
third answers the question.

Five instances were found in total, and the audit that found the last two is
the reason that count is a total rather than a floor. One of them corrected its
own defect entry: the report claimed a firewall channel "carries nothing that
says which rules were deleted, by whom, or from what profile", and measurement
showed the record carries all three on 936 of 936 rows. The parser was
discarding them. The entry was wrong about the *reason* while right about the
symptom, and the correction is recorded rather than quietly overwritten.

## 7. Limitations

**The single-scenario ceiling, first and largest.** Every rule was written
against one intrusion's four steps. `s1_v3` re-ran that scenario on a second
host and settled reproducibility; it could not settle generalisation, because
re-testing the same hypothesis against the same shape cannot. The 99-vs-86
separation is a real result *about that chain*. Whether it is a result about
intrusions is unestablished, and unfalsifiable from inside this corpus. The
corpus is final at five collections (`clean_a`, `clean_b`, `clean_c`, `s1_v2`,
`s1_v3`); no second scenario was collected, and none is planned.

**No accuracy, no lift, no ROC.** One ground-truth entity (§5.4).

**The Class 2 rules are unvalidated, by design.** Nine of the twenty-four rules
express real intrusion behaviours this corpus never exercises. They ship a
measured false-positive profile in place of a detection rate, never contribute
to the entity score, and are labelled `known-behavior` precisely so a rule with
no positive instance cannot move the headline separation. Validating them would
take a second scenario that performs those behaviours — which was not collected
(§7, first item). They are included as documented capability, not as tested
detection.

**Base rates come from five collections on two hosts.** That is enough to
reject a rule that fires on clean data; it is not a base-rate study.

**Operator contamination is present and measured, not eliminated.** The
operator's own shell history and the collection media appear in the evidence;
both are documented as constraints rather than filtered, because filtering them
would be unmeasurable.

**Two defects remain open by choice**, both parser-side, both with the reason
recorded rather than the work hidden.

## 8. Future work

1. **A second, differently-shaped scenario** — the only thing that would raise
   the single-scenario ceiling and validate the Class 2 rules against a corpus.
   It was not collected for this project and is not planned; the corpus is
   final. This is named as the largest open question, not as scheduled work.
2. **`evtx.firewall` rules** — the family became readable only at the end of
   this work; base rates must be measured before any rule is written, in that
   order.
3. **Cross-family field comparison in the rule grammar** — required to express
   the SAM-vs-4624 log-tampering discriminator, which measures cleanly but is
   inexpressible. Deliberately deferred: on this corpus it only corroborates an
   existing rule (`docs/open-decisions.md`, OD-02).

## 9. What the work is actually claiming

Each principle converts a judgement into a measurement, then makes the
measurement hard to skip. Class is enforced where the score is computed rather
than trusted. Evidence class is decided by what the collection physically
contains. Grid states are reachable only by measurement. Verification is
checked for its ability to fail.

The recurring failure is the same one each time: **something that looks like
evidence but was never produced by running anything.** A rule with a plausible
detection rate nobody measured; a coverage claim that is really an effort
claim; a green test that never could have gone red; a parser reporting success
for a field it discarded. All four are indistinguishable from the real thing
until someone checks — which is the argument for building a pipeline whose
every number names the command that produced it.
