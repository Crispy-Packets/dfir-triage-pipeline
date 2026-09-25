# AI briefing on collection_srv22 -- two drafts, both rejected (2026-09-26)

**Outcome: narration stays OFF for the demo.** The budget agreed beforehand
was two live runs; if the second was rejected, stop. It was.

This is the mechanism working, not failing. The model drafts. Deterministic
code checks every clause it can against the record. A draft with one wrong
pairing is withheld, and the reasons are named. That is the slide.

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

## The analyst-written brief (for the slide, instead of the AI's)

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
