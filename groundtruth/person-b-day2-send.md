# Copy-paste for Person B (Day 2)

Day 2 metadata only. **No evtx/pf attachments.** Evidence trees stay off git until Day 3 hashes.

**KAPE:** `KapeTriage`, no `--vhdx`, dest `collection_clean_a`, `collection_clean_b`, `collection_s1`. Copied off VM `Z:` by USB (no shared folder).

**Actors:** Clean A = `youssef`. Clean B collect = `admin_local`. Scenario 1 = `janed`; log-clear/KAPE = `admin_local`.

**Scenario 1:** notepad as `invoice_scan.exe` via **USB**, execute, HKCU Run `SecurityUpdate`, `wevtutil cl Security` (destroys 4688).

**Sanity passed:** both evtx in all three; s1 Security ~69 KB; Prefetch `collection_s1\C\Windows\prefetch\INVOICE_SCAN.EXE-A345C2FE.pf`.

**Path shape:** `collection_*\C\Windows\...` (no hostname folder). Full packet: `groundtruth/person-b-day2-metadata.md`. UTC log: `groundtruth/scenario1.md`.

**Caveat:** `collection_clean_a` has two KAPE log timestamps (19 Aug and 20 Aug) in one dest.

**GitHub (Person A):** commit `groundtruth/*.md` only. `.gitignore` already excludes `collection_*` and `invoice_scan.exe`.
