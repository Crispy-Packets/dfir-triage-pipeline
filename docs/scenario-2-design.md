# Scenario 2 — design specification

**Status: DESIGN ONLY. NEVER COLLECTED. NO COLLECTION IS PLANNED.** The corpus
is final at five collections (`clean_a`, `clean_b`, `clean_c`, `s1_v2`,
`s1_v3`). Nothing in this document is a measurement; it is retained as the
record of what a second scenario would have required, not as pending work.
Everywhere below that reads "if it is taken" or "when collected" describes an
experiment that was not run and will not be.

---

## 1. Why a second scenario, and why not a fourth collection of the first

The corpus contains five collections, and `s1_v3` already re-ran scenario 1 on
a second host. That settled reproducibility: the same four steps on different
hardware, users and hostname produce the same detection.

It did not settle the question underneath. **Every rule in the set was written
against one scenario's four steps** — HTTP delivery, execute, Run-key persist,
log clear. The 99-vs-86 separation is a real result about that chain. Whether
it is a result about *intrusions* is not established, and no further collection
of the same scenario can establish it, because each one re-tests the same
hypothesis against the same shape.

This is the corpus-fit risk the phase-span evaluation stated about its own
four-stage map, generalised: the stages were the scenario's steps rather than a
taxonomy. The same is true of the rule set.

**The single-scenario ceiling is the project's largest limitation.** It is not
a rules limitation, an ML limitation, or a parser limitation — those are
bounded and their bounds are measured. This one is structural and unfalsifiable
from inside the corpus.

## 2. What scenario 2 must do differently

Not "a different attack." A *deliberately disjoint* one: each step chosen so it
exercises a family or technique scenario 1 left untouched, and so that at least
one existing rule is forced to prove it generalises.

| step | scenario 1 | scenario 2 | what it tests |
|---|---|---|---|
| **delivery** | browser HTTP download | **BITS background transfer** | `evtx.bits` has been parsed, rich and joinable since D-065 and has **never had a positive class** (C-05). T1071.001 is `measured-no-discriminator` only because every transfer in the corpus is Windows servicing. |
| **execute** | double-clicked `.exe` from Downloads | **`.lnk` with arguments, or script host** | R-ATOMIC-0012 is Class 2 with `expected: unmeasured`. This is the step that would measure it. |
| **persist** | `Run` key (machine hive) | **scheduled task** | `scheduled_task` parses 1,057 rows, and T1053.005 is `measured-no-discriminator` (2026-09-18) -- present in clean and scenario alike, with nothing separating them, because the only tasks are Windows' own. A scenario-created task is the positive class that state lacks. R-ATOMIC-0017 (per-user hive autorun) is also unmeasured. |
| **destroy** | `wevtutil cl` → EID 1102 | **delete the `.evtx` file** | The case §3.8 of the grid identifies and OD-02 declines to build a rule for: 1102 cannot record its own log's deletion. This is what makes the SAM-vs-4624 discrepancy *corrective* rather than corroborating. |
| **exfil** | *(absent)* | **copy to removable media, or measurable egress** | Three rules — R-ATOMIC-0010, 0013, 0014 — are Class 2 solely because the scenario never exfiltrated. The `exfiltrate` phase exists in schema 2.1.0 and has never been exercised. |

### What each step converts

Seven rules currently carry `expected: unmeasured` on at least one collection.
Scenario 2 as specified would give five of them a positive class:

    R-ATOMIC-0012  lnk with arguments           <- execute step
    R-ATOMIC-0013  jumplist removable target    <- exfil step
    R-ATOMIC-0014  SRUM egress                  <- exfil step
    R-ATOMIC-0015  recyclebin executable        <- if the chain deletes its payload
    R-ATOMIC-0017  per-user hive autorun        <- persist step, if user-scoped
    R-ATOMIC-0016  browser executable download  -- stays unmeasured, delivery is BITS
    R-ATOMIC-0018  amcache unsigned binary      -- stays unmeasured unless the
                                                   payload is unsigned and inventoried

Five of the seven gain a positive class; two do not, and saying which is the
point of writing this before collecting rather than after. That is the
measurable deliverable: **Class 2 rules becoming Class 1**, which is the only
mechanism by which the rule set's coverage claim grows without growing the
rule count.

## 3. Constraints this collection must satisfy

The five existing constraints all apply, and three of them bite harder here.

**C-01 — evidence must not leave the host by a route the pipeline parses.** The
exfil step makes this acute: writing the scenario's own exfil to the same
removable volume the collections are carried on would make the rule fire on the
evidence-handling procedure. That is exactly what the existing removable-media
rows already are (grid T1052.001: `E:\collection_clean_a`, `E:\handoff`).
**Use a different volume, and record its serial in the manifest.**

**C-04 — lab provisioning is indistinguishable from the technique it
resembles.** A scheduled task created by the operator to *set up* the scenario
and one created *by* the scenario are the same artifact. Create the persistence
from inside the scenario's own execution chain, under the scenario user,
never from the provisioning session.

**C-05 — produce the indicator the rule reads.** The whole point. Before
collecting, walk each of the five steps against the rule that should fire and
confirm the specific field: does the BITS transfer carry an attacker-controlled
`url`? Does the `.lnk` carry arguments? Is the deleted `.evtx` the Security log
or a channel nothing reads? A step that produces the right *technique* but the
wrong *field* buys nothing.

**C-06 — the clean baseline's collection timestamp must precede the scenario
run.** Scenario 2 needs its own clean baseline on the same host, collected
before the scenario executes.

## 4. What scenario 2 would and would not settle

**Would settle:**

* Whether the rule set detects an intrusion whose shape it was not written
  against — the generalisation question, which is currently unanswerable.
* Whether `entity_score`'s separation survives a chain with different weights
  and a different number of contributing rules.
* Five Class 2 rules' real base rates on an exercising corpus.
* Whether the `exfiltrate` phase is a real stage or an unused enum value.

**Would not settle:**

* The ML question. Two scenarios is two labelled entities, and lift still
  cannot be computed (OD-01). This is worth stating because "more data" sounds
  like it should help and does not, at this scale.
* Anything `requires-telemetry`, `requires-domain` or `requires-memory`. A
  second disk-image collection changes the scenario, not the evidence class.
* False-positive rates at scale. Two hosts and a handful of collections do not
  make a base-rate study, whatever the row counts look like.

## 5. Honest statement of status

This specification is the deliverable, not the collection. The collection
requires a lab, a scenario run and a KAPE acquisition that have not happened,
and no part of this document may be cited as a result.

If scenario 2 is never collected, the correct statement of the project's
finding is the one it can support: **the rule set detects the chain it was
built against, on two hosts, with a measured separation — and its
generalisation to other intrusion shapes is specified but untested.** That is
a smaller claim than "the pipeline detects intrusions," and it is the true one.
