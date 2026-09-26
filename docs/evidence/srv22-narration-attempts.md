# AI briefing on collection_srv22 -- four drafts, the fourth shown (2026-09-26)

**Outcome: the fourth draft (prompt v12, per-finding) passed the pipeline's
validator AND the viewer's own gate, was read clause by clause against
`srv22-analysis.md`, and is in the srv22 viewer sample.** The history below is
the case for "the AI drafts, deterministic code checks": four drafts, and
each error found became a named check before the next draft.

| Draft | Style | Pipeline check | What was actually wrong |
|---|---|---|---|
| v9  | one answer | rejected | wrong rule for the group addition; admin's findings omitted |
| v10 | one answer | rejected | same wrong rule; a required finding omitted; worded date |
| v11 | one call per finding | **accepted** | host and account roles swapped; "a program" for logons -- caught by a human read, now checks |
| v12 | one call per finding, names with kinds | accepted | nothing found in a clause-by-clause read; viewer gate passes |

The budget agreed beforehand was two live runs, then stop. After v10 the user
decided the narration must show, and overrode the budget. The checks were
not loosened: every change after that point made them stricter.

Setup: `qwen2.5:7b` on Ollama, localhost, CPU only (Ryzen 5 5500U). Temperature
0, seed 20260830, one bounded repair attempt per run, about 3.5 to 4 minutes per
run. Narration-only call on `outputs/srv22/run.json` (rules-only run, 22
findings).

## Run 1 -- prompt v9 (briefing, not verdict)

> On February 5, 2024, at 10:55 UTC, a password was guessed for the
> administrator account, resulting in failed logons followed by a successful one
> from the address 36.133.110.87 (R-CORR-0007). At the same time, another
> password guess attempt was made from the address 185.229.66.183, also
> resulting in failed logons followed by a successful one at 22:55 UTC
> (R-CORR-0007). On the same day, at 23:24 UTC, an account was added to a
> privileged group (R-ATOMIC-0022).

Rejected for:

- the group addition cited to R-ATOMIC-0022. That rule is "Burst of failed
  logons against one account"; the addition is R-ATOMIC-0019. Caught by the
  claim check: "added" is not in the cited rule's title.
- both findings on `admin`, the top-priority entity, left out (R-ATOMIC-0009,
  R-CORR-0005).
- "at the same time" joining 10:55 and 22:55. Not caught in run 1 (the gap was
  found here); caught since.

## Run 2 -- prompt v10 (`must_cite`, shape tied to one entry)

> On February 5, 2024, at 10:45 UTC, a password was guessed, resulting in
> failed logons followed by a successful one from an unknown address
> (R-CORR-0007). At 23:02 UTC on the same day, a local user account named
> "admin" was created (R-ATOMIC-0009). Also at 23:02 UTC on February 5, 2024, an
> account named "admin" was added to a privileged group (R-ATOMIC-0022), with
> additional records at 23:24 UTC on the same day.

Rejected for:

- the same wrong rule for the group addition (R-ATOMIC-0022). Caught by the
  claim check and the time-pairing check.
- R-CORR-0005 omitted, although the facts listed it in `must_cite`.
- "February 5, 2024": a worded date, which the viewer's number check cannot
  verify.

Not caught: "from an unknown address". The facts withheld the address, so the
model called it unknown. That is an open-semantics claim with no field to
check it against. This is the documented boundary, and it is why narration is
never a verdict.

## What was changed between the runs, and kept

All covered by `tests/test_narration.py` (`TestBriefing`, `TestBriefingFindings`):

- **Claim check.** An action a sentence claims (cleared, executed, created,
  added, deleted, downloaded, guessed, registered, installed) must be named in
  the title of a rule cited in that same sentence. It catches the v8 draft's
  fabricated "Security event log ... was cleared" and account "registered to
  run at logon", and both runs' wrong rule for the group addition.
- **Pipeline and viewer agree on numbers.** The pipeline now tokenises numbers
  exactly as the viewer's `contract.NUM_RE`. It had accepted prose that the
  viewer then withheld: IP addresses, a SID, and `nmap-7.93-setup.exe`.
- **Times are first records.** The viewer verifies only
  `first_timestamp_utc`, and every "last" time was withheld (measured).
  Merged duplicates keep their own first times (`also_at_utc`), so the Domain
  Admins addition at 23:24 is not lost.
- **Simultaneity is refused**, while a paraphrase of one chain's own order is
  allowed.
- **The FQDN host is accepted.** v8 was rejected only because of a regex bug
  that cut the host name at its first dot. By luck, that bug hid the real
  errors.

## Run 3 -- prompt v11 (per finding; the model never sees a rule id)

Two single-answer drafts made the same pairing error, and the model is
deterministic, so more wording would not fix it. Now the model writes ONE
sentence per finding and sees only that finding's title, subjects and time.
Code appends that finding's own rule id, so a wrong pairing cannot be
written. The same checks run on each sentence (one repair each) and then on
the whole text. Selection is code: every `must_cite` finding, then one per
remaining rule in severity order, up to 12, printed in time order.

The pipeline accepted it: 12 sentences, no repair needed. A clause-by-clause
read found three errors the checks did not catch:

> At 23:02 UTC on 2024-02-05, an account named
> win-ni9fbk23slo.branchoffice.example.com was added to a privileged group with
> the name cn=a admin,dc=branchoffice,dc=example,dc=com (R-ATOMIC-0019).

The roles are swapped: that is the server, and that is the account.

> At 08:52 UTC on 2024-02-05, a program attempted to log into an account from
> an external network address (R-ATOMIC-0005).

These were successful remote logons. There was no program and no attempt. The
only name, an IP address, had been withheld, so the model guessed a subject.
R-ATOMIC-0008 got "a program connected" the same way.

Cause: the model saw bare names with no kind. Fix (v12): each subject is
listed as "name (kind)", and a withheld name as its kind alone. Two new
fatal checks:
- `role:` rejects a computer written as an account or group, and an account
  written as a computer or group;
- `claim:program` and `claim:attempted` require the cited title to support
  the word.

All four v11 errors are now caught, and the correct versions pass
(`TestSubjectKinds`).

## Run 4 -- prompt v12 (subjects with kinds) -- shown

Accepted by the pipeline, 12 sentences, no repairs. The viewer's
`contract.narration_gate` passes (`show: True`). Clause-by-clause read against
`srv22-analysis.md`: every sentence is true to its record. The one fix was
cosmetic: the model copied the "(a file)" and "(not named)" labels, and code
now strips them before the checks run. Text as shipped:

> At 15:25 UTC on 2023-11-04, sysinternalssuite.zip was downloaded to a
> user-writable location (R-ATOMIC-0016). At 23:37 UTC on 2024-02-04, there was
> a burst of failed login attempts against the administrator account
> (R-ATOMIC-0022). At 08:52 UTC on 2024-02-05, a network address logged into
> the system interactively (R-ATOMIC-0005). At 10:45 UTC on 2024-02-05, an
> attempt to log in as the administrator account failed from one network
> address, followed by a successful login (R-CORR-0007). At 22:47 UTC on
> 2024-02-05, an attempt to log in as the administrator account failed from one
> network address, followed by a successful login (R-CORR-0007). At 23:02 UTC
> on 2024-02-05, a computer named win-ni9fbk23slo.branchoffice.example.com had
> an account named admin created locally (R-ATOMIC-0009). At 23:02 UTC on
> 2024-02-05, the admin account was created and then authenticated within the
> hour (R-CORR-0005). At 23:02 UTC on 2024-02-05, the account cn=a
> admin,dc=branchoffice,dc=example,dc=com was added to the privileged group on
> the computer win-ni9fbk23slo.branchoffice.example.com (R-ATOMIC-0019). At
> 23:14 UTC on 2024-02-05, sysinternalssuite.zip was moved to the Recycle Bin
> from a user-writable location by one account (R-ATOMIC-0015). At 11:27 UTC on
> 2024-02-08, a terminal services session was opened from a remote network
> address (R-ATOMIC-0008). The program msmpeng.exe was registered, and its
> binary file is stored in a location that can be written to by users
> (R-ATOMIC-0011). The program dir.exe was found in a user-writable directory
> and has no publisher information (R-ATOMIC-0018).

What it does NOT say, and what to say aloud:
- The 2023-11-04 download is a real browser record from before the incident.
  The attacker's own download is 5 Feb 23:13.
- "An attempt ... failed" understates tens of thousands of failures. Every
  time is the finding's FIRST record, the one the viewer can verify, so
  10:45 is when the failures begin; the success came at 10:55:56.
- The 08:52 and 11:27 logons are the legitimate administrator's (195.21.1.97).
  The briefing describes; it does not judge.
- rename.exe (Petya.A), PsExec and share.zip are not in the 12 sentences
  (one per rule, rule-severity order). They are in the analyst brief below.

## The analyst-written brief (for a slide, beside the AI's)

Written by hand from `srv22-analysis.md`. Every line is checked there. Times
are UTC.

> On 5 February a password for the built-in administrator account was guessed
> from one external address after tens of thousands of failed attempts; the
> successful logon came 0.6 seconds after the last failure (10:55). That
> evening a remote desktop session was opened from a second address, and at
> 23:02 a new account, `admin`, was created, added to Administrators, and at
> 23:24 to Domain Admins. Over the next hour it downloaded Sysinternals and
> nmap. On 6 February PsExec was used and, 30 seconds later, a 694 MB archive,
> share.zip, was sent to the Recycle Bin. On 7 February two programs, rename.exe and dir.exe, were placed on
> the server; on 9 February PsExec was used again and rename.exe ran. Its hash
> matches Petya.A.

Image: CC-BY-NC-SA 4.0, Benjamin Donnachie, The Open University. All names and
addresses in it are synthetic.
