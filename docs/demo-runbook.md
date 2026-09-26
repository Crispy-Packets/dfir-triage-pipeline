# Demo runbook

**Rule for the day: nothing runs live.** Every output below is produced the day
before and opened from disk. A pipeline run takes minutes and a live failure
costs the room; a pre-computed, hash-verified run costs nothing.

## The story — five beats, one real compromise

The case is `collection_srv22`: a public research image of a Windows Server 2022
domain controller hit by "Red Petya" ransomware (Donnachie, Open University,
CC-BY-NC-SA 4.0). All names and IPs in it are synthetic. Full analysis:
`docs/evidence/srv22-analysis.md`.

| Beat | Say | Show |
|---|---|---|
| **1. How they got in** | 100,003 failed logons from one address, then the password was guessed at **5 Feb 10:55:56** — 0.6 s after the last failure. | R-CORR-0007 finding (Verdict/Context panel): `[administrator, 36.133.110.87]` |
| **2. What they did** | Created `admin`, made it **Domain Admin** within 23 minutes; browsed the file share; downloaded Sysinternals and nmap; ran PsExec; staged a 695 MB `share.zip`. | R-ATOMIC-0009, R-CORR-0005, **R-ATOMIC-0019** (Domain Admins), 0016, 0015 |
| **3. The payload** | An unsigned `rename.exe` on the attacker's Desktop ran one minute before the server stopped. Its SHA-1 matches **Petya.A — Red Petya** in public sandboxes. | R-ATOMIC-0018 finding; the hash; `srv22-analysis.md` §5 |
| **4. What we missed** | PsExec has no rule; the ransomware itself acts at boot, outside Windows' logs; exfiltration of `share.zip` cannot be shown (no network usage recorded on this server). | `srv22-analysis.md` §6 |
| **5. What we fixed** | "How did they get in" was missing: the old chain gave up on 100k failures, and joined on the account alone it would have blamed the real admin's home logon. New join key on the **source address** fixed both. RDP findings went from 807 to 3 — one per address, one of them the attacker's Kali machine. | Before/after counts (below) |

## Numbers to have ready

| | Before | After |
|---|---|---|
| "How did they get in" | nothing (R-CORR-0002 search truncated) | **R-CORR-0007: 10:55:56 from 36.133.110.87** |
| External RDP findings (R-ATOMIC-0005) | 807, one per logon | **3, one per source address** |
| RDP session findings (R-ATOMIC-0008) | 262 | **2** |
| Payload | "probable" | **confirmed by hash (Petya.A)** |

Pipeline on srv22: 2,072,843 events, 29+ rules. Integrity: 7/7 image segment
MD5s match the publisher; all 509 collected files match KAPE's source SHA-1s.

On the lab corpus (s1_v3): the rules place the payload `invoice_scan.exe` at
triage score 99 (critical); the anomaly layer ranks it **14 of 443** under
MODA*-G. **The anomaly layer ranks; it does not detect.**

## Questions to pre-empt

- **"Why is Notepad++ flagged high?"** (s1_v3) — The number is a triage score:
  the weight of the rules that matched, not a verdict. R-CORR-0001 fires on any
  downloaded file that is executed, which is what an installer does; measured
  firing on clean hosts too. The score queues it; the drill-down resolves it.
- **"Why does the anomaly ranking lead with ordinary Windows programs?"** —
  Unusual is not malicious. It ranks rows by how rare they are among their own
  kind. The rules found the attack.
- **"Why is the ML panel empty for the server?"** — Windows Server writes no
  Prefetch by default, the Amcache family is below its row floor, and there is
  no clean collection of that same machine to compare against. Scoring it
  against a different machine is the documented failure the pipeline warns
  about. The rules found the payload without it.
- **"Is the AI summary a verdict?"** — No. It is off by default, validated
  against the record, and withheld when wrong; the viewer re-checks it too.

## Commands (run the day before)

```powershell
cd %USERPROFILE%\dfir-triage-pipeline

# gate
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe rules\validate_rules.py

# the server case (rules only: no same-host baseline exists)
.\.venv\Scripts\python.exe -m dfir_triage_pipeline %USERPROFILE%\dfir-evidence\collection_srv22 `
    --output outputs\srv22\timeline.csv --run-json outputs\srv22\run.json --report

# ...or run AND open it in one step: --view launches the viewer on this run,
#    in its own window, once the run is written
.\.venv\Scripts\python.exe -m dfir_triage_pipeline %USERPROFILE%\dfir-evidence\collection_srv22 `
    --output outputs\srv22\timeline.csv --run-json outputs\srv22\run.json --report --view
```

**One click:** double-click `viewer\Start-Viewer.bat`. It opens the viewer on
the runs in `viewer\samples\` (srv22 included). Drag a `run.json` onto it to
open that run instead. On first use it builds the viewer's own environment
with Python 3.11 (~100 MB, needs internet) -- do that on the presenting
machine, on good Wi-Fi, before the day. Close its console window to stop the
viewer.

## Narration (the AI briefing -- OFF by default, ON in the srv22 sample)

The AI briefing runs on this laptop (Ollama, `qwen2.5:7b`, localhost, CPU
only). **The srv22 viewer sample carries an accepted briefing** (prompt v12,
per finding): open the sample and it shows under the AI-summary label, with
the code-written ranking lines beside it. The page to have ready for
questions is `docs/evidence/srv22-narration-attempts.md`. It holds four
drafts, the errors each check caught, and what to say aloud about what the
briefing leaves out.

What to say: **"The AI drafts one sentence per finding. It never sees a rule
id; code attaches it. Deterministic code checks every time, name, number, role
and action against the record, and the viewer checks again. If any check
fails, nothing is shown."**

A live run adds about 3.5 minutes (12 model calls). To switch it on for ONE
PowerShell window:

```powershell
$env:DFIR_NARRATION = "ollama:qwen2.5:7b"
$env:DFIR_NARRATION_ENDPOINT = "http://localhost:11434"
# ...then run the pipeline as usual. To switch it off again:
Remove-Item Env:DFIR_NARRATION, Env:DFIR_NARRATION_ENDPOINT
```

Or in one step -- sets both, checks the model is up BEFORE the long run, and
clears them afterwards:

```powershell
.\tools\run_with_narration.ps1 -Check
.\tools\run_with_narration.ps1 -Collection %USERPROFILE%\dfir-evidence\collection_srv22 `
    -Baseline %USERPROFILE%\dfir-evidence\collection_clean_c
```

**Do not set these as permanent Windows environment variables.** Every pipeline
run -- and the test suite -- would then call the model.

## Screens, in order

1. Viewer → sample `srv22` → **Priority** and **This run**: manifest verified.
2. **Verdict / Context** → R-CORR-0007 → expand source events: the failure and
   the success, same address, 0.6 s apart.
3. R-ATOMIC-0019 → Domain Admins, `TargetSid …-512`.
4. R-ATOMIC-0018 → `rename.exe` → then the hash on screen (`srv22-analysis.md`).
5. Terminal: the before/after counts above.
6. s1_v3 sample → the 99 vs 14-of-443 slide: rules detect, ML ranks.
7. srv22 sample → the AI briefing: drafted by the model, every clause checked
   by code, labelled not-a-verdict. Then the attempts page: what the checks
   caught in the drafts that were NOT shown.
