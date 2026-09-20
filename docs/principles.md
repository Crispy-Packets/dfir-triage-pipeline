# Principles

Four things this project settled that are not specific to it. Each is stated
as a rule someone else could adopt, followed by a short note on where it came
from here.

The subject throughout is a triage pipeline that reads a disk-image evidence
collection, matches detection rules against it, and ranks entities by
suspicion. The principles are about what such a tool is allowed to claim.

---

## 1. Separate the rules that earned a verdict from the rules that did not

A detection rule can be sound and still have no evidence behind it. It
expresses a real intrusion behaviour, its logic is defensible, and the corpus
you validated against simply never did that thing. Deleting the rule loses
real coverage. Keeping it as an equal removes the meaning from every number
the tool reports.

**The rule: split the rule set into two classes and let only one of them move
the ranking.**

- **Class 1 — corpus-validated.** Fires on the intrusion, does not fire on the
  clean baseline, and carries measured base rates per collection. These
  produce the verdict and the score.
- **Class 2 — known-behavior.** Expresses a real behaviour the corpus never
  exercised. It ships a documented false-positive profile instead of a
  detection rate, because a detection rate would be a fabrication. These
  produce context, never rank.

Three consequences follow, and all three are load-bearing:

**Enforce the split where the number is computed, not where the file is
read.** A load-time check only covers rules that arrive through the loader. An
object built by hand in a test, or any path that reaches the engine without
passing the checker, slips past it. Enforcing at the point of aggregation
covers every path by construction, because there is only one.

**Choose the failure direction deliberately.** If a rule's class is missing or
misspelled, treat it as unscoreable rather than scoreable. A typo then costs a
contribution instead of inventing one. Catch the typo separately with a
closed-set test over the files on disk.

**The split has to survive into the output, not just the arithmetic.** This is
where it is easiest to get half right: the score can be perfectly filtered
while the report still lists every finding under a heading that says "verdict."
A reader does not see your aggregation function. They see the page.

> **Here.** Nine of twenty-four rules are Class 2. The score filter lives in
> `entity_score.aggregate`; the headline 99-vs-86 entity separation is Class 1
> only. The output half was missing until D-072: the score was filtered and the
> rendered findings list was not, so Class 2 findings appeared under a heading
> that said "verdict". Now `rule_class` reaches `run.json` and `findings.csv`,
> and they render in a separate context panel.

---

## 2. Say what the evidence *cannot* contain, structurally

The tempting way to report coverage is a list of what you detect. It is
uninformative, because a reader cannot tell a technique you chose not to
implement from one that is impossible given your inputs. Those are different
claims and only one of them is a limitation of the tool.

**The rule: classify every candidate technique by the kind of evidence it
requires, before asking whether you implemented it.** Four classes, and the
boundary is the collection method, not the parser:

| Class | Meaning |
|---|---|
| `disk-resident` | The observable survives on disk. In scope. |
| `requires-telemetry` | Exists only in live or agent telemetry — Sysmon, EDR hooks, packet capture. A disk image never held it. |
| `requires-domain` | Written on a domain controller, not this endpoint. |
| `requires-memory` | Exists only in volatile memory. |

The last three eliminate candidates **structurally**. No amount of parser work
reaches them, because the bytes were never collected. That is a fact about the
evidence, and it stays true if someone rewrites the whole pipeline.

This distinction is the entire point:

- *"Not observable in this evidence class"* is a statement about the world.
  It is honest, it is stable, and a reader can act on it — by changing the
  collection, which is the only thing that would help.
- *"We didn't implement it"* is a statement about your effort. Reporting the
  second as the first inflates apparent coverage and misleads about what
  collecting differently would buy.

The discipline this imposes is worth more than the taxonomy: you must decide
which one is true for each gap, and you cannot decide by preference.

> **Here.** Twelve techniques are `not-observable` and six more
> `structurally-out-of-scope`. Each row names the specific missing observable —
> a packet capture, EID 4769, `NTDS.dit` — rather than saying "out of scope."

---

## 3. Coverage is not binary, and "not written yet" is not a rejection

A two-state grid — covered or not — forces every honest answer into the wrong
box. A technique you measured and found unexercised gets filed next to one you
have never looked at. Over a project's life that erases most of what you
learned.

**The rule: give the grid enough states that no row has to lie, and make sure
one of them means "measured, still to write."** The states that carry weight:

- **`covered`** — a validated rule exists, with measured base rates.
- **`covered-known-behavior`** — a rule exists, the corpus never exercised it
  (Class 2 above).
- **`observable-unwritten`** — the evidence is present and carries the fields a
  rule would need. Nothing is written yet. **This is a to-write state, not a
  rejection.**
- **`measured, not exercised`** — the family parses, the base rate was
  measured, and the behaviour is absent from this corpus. Genuinely different
  from the state above: someone did the work and the answer was zero.
- **`measured-no-discriminator`** — the observable is present in both clean and
  intrusion data and nothing separates them. A rule here would be a
  coin-flip. This is the most valuable state in the grid and the one a binary
  grid destroys, because it is a *measured negative*.
- **`not-observable`** / **`structurally-out-of-scope`** — principle 2.
- **`blocked`** — a specific, named obstacle, which is a task rather than a
  verdict.

The point of separating `observable-unwritten` from `measured-no-discriminator`
is that they look identical in a binary grid and imply opposite next actions.
The first is a backlog item. The second is a closed question, and re-opening it
wastes the measurement that closed it.

**A grid state must be reachable only by measurement.** If a row can be set to
`measured-no-discriminator` by someone's impression that a rule "probably
wouldn't work," the state means nothing.

> **Here.** Eight states. Re-verifying three closed rows found a wrong figure
> in each while leaving all three verdicts intact — which is the argument for
> recording the figure and not just the verdict.

---

## 4. Two defect patterns worth naming

Both are failures of *verification* rather than of code. Both pass every test
you have, because in each case the test is not looking at the thing.

### 4.1 Verification that cannot fail on the thing it checks

A check that passes tells you nothing until you know it *could* have failed.
Five ways it cannot, each seen more than once:

| Pattern | The check examines | Symptom |
|---|---|---|
| **vacuous** | nothing at all | Iterates an empty collection; passes instantly |
| **partial** | some of the population, silently | The population looks complete because you never counted it |
| **wrong target** | something adjacent to the claim | Calls the function under the gate, bypassing the gate |
| **out of scope** | correctly, but cannot see the claim | An audit for *absent* entries cannot find a *wrong* one |
| **in prose** | nothing — the claim is asserted in a document | Reads as established; never ran |

The countermeasures are cheap and specific:

1. **Assert the population size, not just the result.** A loop over zero items
   passes. `assert len(items) == 58` fails.
2. **Route the check through the same code path as the claim.** If the claim is
   about a gate, call through the gate.
3. **Confirm the check can fail.** Break the thing on purpose once and watch it
   go red. A green test never observed failing is an untested test.
4. **Treat a document's assertion as unverified until a command produced it.**
   Prose is where unmeasured claims accumulate, because nothing runs prose.

### 4.2 The parser drops the meaning-bearing field

A parser reports success. Rows appear, counts look plausible, the family is
"supported." But the one field a rule would actually need was never extracted —
so every rule written against that family is unwritable, and the reason is
invisible from the row count.

This is worse than a parser that fails, which is loud. Silent partial
extraction is mistaken for coverage for as long as nobody writes the rule.

**The rule: measure parse depth, not parse success.** For each family, record
three things and keep them together: rows produced; distinct detail keys
carried; and whether those keys include the fields a rule would need. Only the
third answers the question that matters.

> **Here.** Three instances were known — a family taken for a field it never
> extracts (D-055); one recording a complete download and keeping only the
> timestamp (D-065); one typed with four event IDs and zero detail keys
> (D-069). The audit was then run across all 38 families and five collections,
> and found **two more** (D-073): a firewall channel emitting
> `firewall_rules_deleted` on 983 rows with nothing saying which rules, and a
> winlogon channel with 2,229 rows and no keys. It also found no family
> declaring a key it never populates, and confirmed the thin families are thin
> because the artifact is thin. Five instances, bounded — which is what running
> the audit bought over estimating it.

---

## What these have in common

Each principle converts a judgement into a measurement, then makes the
measurement hard to skip.

Class is enforced at the point of aggregation rather than trusted. Evidence
class is decided by what the collection physically contains. Grid states are
reachable only by measurement. Verification is checked for its ability to fail.

The recurring failure is the same one each time: something that looks like
evidence but was never produced by running anything. A rule with a plausible
detection rate nobody measured; a coverage claim that is really an effort
claim; a green test that never could have gone red; a parser that reports
success for a field it discarded. The work is noticing that a claim has no
command behind it — and the cost of not noticing is that all four look exactly
like the real thing until someone checks.
