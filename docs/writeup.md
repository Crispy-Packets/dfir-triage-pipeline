# A disk-image triage pipeline: architecture, method and measured limits

Thesis-chapter framing. Every figure below carries the command or document that
produced it; where a thing was not measured, it says so instead of estimating.
The four principles this work settled are stated in full in
`docs/principles.md` and summarised here in the position where they did their
work.

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
`run.json` (`run_json_version` 1.2.0):

| collection | top entity | score | severity |
|---|---|---|---|
| clean_a | `entity.user=youssef` | 97 | high |
| clean_b | `entity.user=youssef` | 97 | high |
| clean_c | `entity.user=vboxuser` | 92 | high |
| **s1_v2** | `entity.exe_name=invoice_scan.exe` | **99** | **critical** |
| **s1_v3** | `entity.exe_name=invoice_scan.exe` | **99** | **critical** |

The headline "99 vs 86" compares the scenario payload against the highest
*executable* entity on a clean host. The 97 rows above are **user** entities,
which rank high on both clean and scenario hosts because ordinary users
accumulate autorun and account findings. Both figures are real and they answer
different questions; quoting the first without the second overstates the gap.

Class 2 findings appear in `findings.csv` and the context panel and contribute
zero to every score above.

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
outlier in either scenario collection. No family places the attack entity in
its own top decile — `bam` 33%, `prefetch` 41%, `amcache` 89%. The
1-of-894 headline is the *rules* layer placing the entity first with the
anomaly ranking appended behind it.

Ablation, quoted with its pipeline version because a rank figure without one is
itself a defect:

    2026-09-13   7 declared, 7 parsed     host 2:  40 of 525   (top 7.6%)
    2026-09-18   7 declared, 38 parsed    host 2:  81 of 443   (top 18.3%)
                                          host 1: 298 of 1189  (top 25.1%)

The percentile worsened as the event pool grew, because the entity denominator
grew while the model stayed fitted on seven families — dilution, not damage,
and evidence that *coverage was not the limiting factor*. Extending features to
the 31 remaining families would enlarge the denominator further without
touching the families the attack entity actually appears in.

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
intrusions is unestablished, and unfalsifiable from inside this corpus.
`docs/scenario-2-design.md` specifies the collection that would test it —
designed, not collected.

**No accuracy, no lift, no ROC.** One ground-truth entity (§5.4).

**Base rates come from five collections on two hosts.** That is enough to
reject a rule that fires on clean data; it is not a base-rate study.

**Operator contamination is present and measured, not eliminated.** The
operator's own shell history and the collection media appear in the evidence;
both are documented as constraints rather than filtered, because filtering them
would be unmeasurable.

**Two defects remain open by choice**, both parser-side, both with the reason
recorded rather than the work hidden.

## 8. Future work

1. **Scenario 2** — the only item that raises the ceiling.
   `docs/scenario-2-design.md`. Would convert five Class 2 rules to Class 1 and
   test generalisation directly.
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
