# The seven schema gaps, and what closing them is worth

**Written 2026-09-14, after implementing all seven.** Each was found by trying
to write a rule the 1.x grammar could not express. This document records what
each gap was, what closing it buys on a real estate, and — critically — **which
of them this corpus cannot exercise**.

---

## 1. Why this is stated up front

Three of the seven are demonstrated against real evidence. **Four are tested
only against synthetic events**, because the corpus contains nothing that would
exercise them: there is no failed-logon burst, no multi-user chain, no repeated
step, and no execution lacking an arrival record that is not simply a Windows
binary.

That is not a reason to leave them unbuilt. The criterion applied here is **what
a real incident would need**, not what this lab happens to contain — a triage
tool whose grammar cannot express password spraying is not ready for a real
estate, whatever its scores on one scenario.

But it is a reason to say so plainly. A capability tested only against a fixture
the author wrote is a capability that has never met reality, and presenting the
seven as uniformly validated would overstate them.

| gap | exercised by real evidence? |
|---|---|
| 3 — cross-field comparison | **yes** (via `is_user_writable`, its narrow form) |
| 4 — rarity conditions | **yes** (`invoice_scan.exe` is in one collection, OneDrive in five) |
| 9 — entity aggregation | **yes** (`invoice_scan.exe` scores 94 from two rules) |
| 1 — aggregation / bursts | no — one EID 4625 in `s1_v2`, zero in `s1_v3` |
| 2 — negative correlation | no — would fire on every Windows binary here |
| 6 — multi-entity chains | no — one account performs the whole scenario |
| 7 — step repetition | no — the scenario writes one Run key |

---

## 2. The gaps

### Gap 1 — aggregation (`count` / `within` / `group_by`)

**Was:** the grammar evaluates one event at a time. "N events in T seconds" was
inexpressible.

**Cost on a real estate:** password spraying, brute force and credential
stuffing are all bursts. `R-CORR-0002` currently fires on *every* failed-then-
successful logon; on a domain controller that is hundreds of findings a day with
the one genuine spray buried among them.

**Person A had already documented this** (schema §11) and — correctly — refused
to fake it:

> `R-CORR-0002` is therefore written as *one* failure followed by a success,
> which is a weaker claim than the plan asked for, and its description says so
> rather than implying otherwise. It is not faked with a threshold the engine
> cannot enforce.

**Now:** an `aggregate:` block on an atomic rule. A sliding window per group;
the first window reaching `count` emits one finding and the group is then
skipped — fifty failures in a minute is one spray observed once, not forty-six
overlapping findings.

`group_by` must be an entity key. A burst against one *account* is a spray; a
burst across every account at 09:00 is Monday morning. `count: 1` is rejected
rather than accepted as a no-op, because it implies a threshold it does not
enforce.

### Gap 2 — negative correlation (`absent: true`)

**Was:** every step had to match. "Executed with no arrival record" —
inexpressible.

**Cost on a real estate:** a binary that ran with no download, no installer and
no package-manager record is how living-off-the-land tooling and laterally
copied binaries surface. On a curated baseline it is a genuine detector.

**Now:** `absent: true` on a step drops every entity for which that step *did*
match. Two combinations are rejected at load time rather than silently ignored:
`absent` with `in_window` (there is no event to measure an interval to) and
`absent` with `optional` (an optional absence is satisfied by everything).

**Honest limit here:** on this corpus such a rule would fire on hundreds of
Windows binaries that legitimately have no download record. It needs a baseline
of known-good software to be useful, which this project does not have.

### Gap 3 — cross-field comparison (`value_field`)

**Was:** a condition compared a field to a literal or a regex. Nothing else.

**Cost:** every comparison needing two fields required an engine change.
`is_user_writable` was exactly that — a hardcoded special case of a general
capability.

**Now:** `value_field` names a second field as the right-hand side. `value` and
`value_field` are mutually exclusive: a condition carrying both has two
right-hand sides and no defined precedence, and either resolution would make
half of all such rules silently mean the other thing.

An absent right-hand side is false, for the same reason an absent left-hand side
is: a comparison against nothing is not a match, and treating it as one would
make a missing field into evidence.

### Gap 4 — rarity conditions (`entity_count_lte` / `entity_count_gte`)

**Was:** the rule layer could not ask how common something is. The anomaly layer
computes `executable_rarity` and `executable_is_unseen`; **the two layers could
not talk.**

**Cost on a real estate:** prevalence is *the* triage signal. "This binary
exists on 1 of 4,000 hosts" is the question an analyst asks first.

**Now:** a `RunContext` is built once per run holding per-entity counts, and
two operators read it.

**The claim is deliberately narrower than the ML layer's.** `features.build_rarity_index`
fits a profile on a *training* collection and applies it unchanged, so it can
say "unseen in the baseline". The engine receives no training set, so a rule may
only say **rare within this collection**. An event with no derivable executable
returns False rather than a count of zero — zero would read as maximally rare
and make every EVTX log-on record match.

### Gap 6 — multi-entity chains (`join_override`)

**Was:** `join.on` applied to the whole rule. Every step joined on the same keys.

**Cost on a real estate:** lateral movement is *definitionally* multi-entity —
user A's credentials, host B's execution, one binary as the constant. Any
intrusion past initial access needs it.

**Now:** a step may declare `join_override`. It must share at least one key with
`join.on`, checked at load time: without that overlap the steps have no common
ground and the "chain" would be two unrelated events reported as one — the
fabricated join the engine exists to prevent.

### Gap 7 — step repetition (`min_count` / `max_count`)

**Was:** a step matched once. "N registry writes" needed N separate rules.

**Cost on a real estate:** ransomware, mass collection and staged exfiltration
all have the shape "one event, then many of something".

**Now:** `min_count` and `max_count` bound how many events must satisfy a step
for the joined entity. `max_count` below `min_count` is rejected — the step
could never be satisfied, and a rule that can never fire is a rule that looks
like coverage.

### Gap 9 — entity-level aggregation

**Was:** findings were independent. Three rules firing on one binary produced
three rows, not one entity.

**Cost on a real estate:** an analyst triages entities. A real host produces
hundreds of findings; without aggregation there is nothing to rank.

**Now:** `core/entity_score.py` groups findings by entity key and scores each.

**The scoring decision, and the mistake that produced it.** The first
implementation summed distinct rule weights and capped at 100. Measured on
`s1_v3`, both `invoice_scan.exe` and `onedrive.exe` matched `R-CORR-0003` (85)
and `R-ATOMIC-0006` (60), summed to 145, and **both clamped to 100** —
indistinguishable, with the ordering destroyed at exactly the top of the list
where it matters.

The replacement treats each weight as a fraction of remaining headroom:

    combined = 100 * (1 - product over distinct rules of (1 - weight/100))

85 and 60 give 94. It is monotonic, and it stays below 100 unless a rule is
itself 100 — so accumulated partial evidence never becomes indistinguishable
from a single definite finding. Ten rules at 90 round to 100 under plain
rounding, so the result is floored at 99 when no rule asserts certainty.

**Distinct rules, not distinct findings.** A rule firing five times contributes
once, or the score would measure how many registry values a program registered.

---

## 3. What this changed on the real corpus

`s1_v3`, unchanged in findings, now also reports entities:

     94 (from 145 across 2 rules)  [critical] entity.exe_name=invoice_scan.exe
     94 (from 145 across 2 rules)  [critical] entity.exe_name=onedrive.exe
     88 (from 130 across 2 rules)  [high]     entity.user=vboxuser
     75                            [high]     entity.exe_name=npp...installer.exe
     70                            [high]     entity.host=winvm

`invoice_scan.exe` and `onedrive.exe` tie at 94, which is the honest output:
both genuinely match the same two rules with the same weights. The rules cannot
separate them, and the score does not pretend otherwise. Separating them is what
the `is_user_writable` condition already did at the rule level, and what the
anomaly layer's percentile does at the ranking level.

No existing rule uses any of the seven new capabilities. They are available;
adopting them is a rule-authoring decision, and `rules/**` is Person A's.

---

## 4. What is NOT claimed

- **Four capabilities have never run against real evidence.** They are pinned by
  synthetic fixtures; §1 says which.
- **No new rule was written to use them.** Writing rules that fire on nothing in
  this corpus would produce `expected: 0` across five collections, which is
  coverage in appearance only.
- **The negative-step capability is not useful here** and is documented as such
  in §2 gap 2.
- **`search_truncated` still applies.** Repetition and join overrides widen the
  candidate space, and the existing `SEARCH_BUDGET` reporting is what surfaces a
  truncated search rather than hiding it. On a 50,000-event estate that warning
  matters more than it does here.
