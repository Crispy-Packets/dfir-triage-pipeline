# collection_srv22 — analysis of a real Windows Server 2022 compromise

Analysed 2026-09-25. Every claim below names the artifact it rests on.
**Fact** = read directly from a record. **Inference** = a reading of facts that
the records do not state; marked as such, with what would confirm it.

## 1. Source and integrity

- **Image:** `20240212-decrypted-Windows_Server_2022.E01`..`.E07`, a public
  research dataset by Benjamin Donnachie (Open University), CC-BY-NC-SA 4.0.
  Its README: simulated UK small-office network, Sept 2023 – Feb 2024; the
  administrator opened RDP for home working; on 12 Feb 2024 the server showed
  "Red Petya"; the disk was decrypted, then imaged. All names and IPs are
  synthetic. Ground truth is available from the author on request.
- **Download integrity:** all seven segments match the README's MD5s (7/7).
- **Collection:** mounted read-only with Arsenal Image Mounter (KAPE refuses
  FTK Imager mounts), KAPE 1.3.0.2 `KapeTriage`. 509 files, all seven locked
  NTFS files copied ($MFT, $LogFile, $J, $Max, $SDS, $Boot, $T). **All 509
  copies match the SHA-1 KAPE recorded from the source** (0 mismatches).
- **Pipeline:** 512 files seen, 430 handled, 0 failed; **2,072,843 events**;
  29 rules; **1,084 findings**. Run with no `--baseline`: there is no clean
  collection of this host, and a baseline from another machine would make the
  anomaly ranking meaningless (CLAUDE.md, "train and score within one host").

## 2. The host

- **Fact:** `WIN-NI9FBK23SLO.branchoffice.example.com` (Security.evtx). It holds
  Domain Admins membership changes and serves a handful of named staff each
  working day (roughly 5–25 network logons each) from
  `10.44.24.1`–`.9` (DESKTOP-001..005): **a domain controller and file server**.
- **Fact:** Windows Server does not write Prefetch by default — **0 .pf files**.
  Every Prefetch-based rule and the anomaly layer's Prefetch family cannot
  contribute. Execution evidence here comes from BAM, Amcache, Shimcache, SRUM.
- **Fact:** SRUM on this host holds application resource usage only; there is
  **no network-usage table**, so bytes sent per program cannot be measured.

## 3. Timeline

All times UTC.

| When | What | Source | |
|---|---|---|---|
| 4 Feb 23:37:28 | Password guessing starts from **36.133.110.87** (workstation name `kali`) | Security 4625 | Fact |
| 4 Feb 23:37 → 5 Feb 20:58 | **100,003 failed logons** from that address, 99,999 against `Administrator`, all network (type 3) | Security 4625 | Fact |
| **5 Feb 10:55:56** | **One successful network logon as `Administrator` from 36.133.110.87** — the password is guessed | Security 4624, EventRecordID 2379067 | Fact |
| 5 Feb 22:43 → 23:00 | 14 failures from **185.229.66.183** (also `kali`); success at 22:55:18 | Security 4625/4624 | Fact |
| **5 Feb 23:00:28** | **RDP session as `Administrator` from 185.229.66.183** | Security 4624 type 10 | Fact |
| **5 Feb 23:02:00** | **Account `admin` created** by `Administrator` | Security 4720, ERID 2441460 | Fact |
| **5 Feb 23:02:22** | `admin` added to **Administrators** (S-1-5-32-544) | Security 4732, ERID 2441473 | Fact |
| 5 Feb 23:04:48 | The `Administrator` profile has browsed `share\<user>` folders for 17+ staff | ShellBags (key write time) | Fact; that it was the attacker session is inference from timing |
| 5 Feb 23:05 → 23:24 | RDP sessions as `admin` from 185.229.66.183 | Security 4624 type 10 | Fact |
| 5 Feb 23:13:32 | `admin` downloads **SysinternalsSuite.zip** (Microsoft) | Edge History | Fact |
| **5 Feb 23:24:35** | `admin` added to **Domain Admins** (RID 512) — **the attacker controls the domain** | Security 4728, ERID 2441859 | Fact |
| 5 Feb 23:41:28 | `admin` downloads **nmap-7.93-setup.exe** from softonic | Edge History | Fact |
| 5 Feb 23:42:42 | **Npcap** packet driver installed (nmap dependency) | System 7045 | Fact |
| 6 Feb 00:06 → 8 Feb 20:00 | **nmap active hourly for ~3 days** | SRUM resource usage | Fact (active); that it was scanning is inference |
| **6 Feb 19:52 → 9 Feb 22:52** | A **third address, 31.220.85.162**, logs in as `Administrator` then as `admin` — 22 RDP sessions over three days | Security 4624, RDP LSM | Fact |
| **6 Feb 22:14:12 / 22:15:14** | **PsExec64 and PsExec executed** by `admin` | BAM | Fact |
| **6 Feb 22:14:44** | **`share.zip` (694,728,396 bytes) on `admin`'s Desktop sent to the Recycle Bin**, 30 s after PsExec64 | Recycle Bin $I | Fact |
| 7 Feb 21:00:10 | **`rename.exe` and `dir.exe` on `admin`'s Desktop**, no publisher | Amcache | Fact |
| **9 Feb 22:55:44** | **PsExec executed again** | BAM | Fact |
| **9 Feb 22:56** | **`rename.exe` running** (13.3 billion CPU cycles in that interval) | SRUM | Fact |
| **9 Feb 22:56:32** | **Last write anywhere on the system** (SYSTEM hive) | Shimcache / hive | Fact |
| 12 Feb | "Red Petya" found on screen | README | Reported, not in the image |

## 4. Indicators

| Indicator | Value | Source |
|---|---|---|
| Brute-force source | 36.133.110.87 (`kali`) | Security 4625/4624 |
| Attacker RDP sources | 185.229.66.183 (`kali`), 31.220.85.162 | Security 4624 type 10 |
| Planted account | `admin`, SID …-2611, member of Administrators and **Domain Admins** | Security 4720/4732/4728 |
| `rename.exe` | SHA-1 `39b6d40906c7f7f080e6befa93324dddadcbd9fa`, 230,912 bytes, no publisher, `C:\Users\admin\Desktop` | Amcache |
| `dir.exe` | SHA-1 `d1c62ac62e68875085b62fa651fb17d4d7313887`, 806,912 bytes, no publisher, same folder | Amcache |
| Staged archive | `C:\Users\admin\Desktop\share.zip`, 694,728,396 bytes, deleted 6 Feb 22:14:44 | Recycle Bin |
| Tools | PsExec / PsExec64 (Sysinternals), nmap 7.93 + Npcap 1.71 | BAM, Amcache, 7045 |

## 5. Readings (inference — each needs confirmation)

1. **`rename.exe` is the most likely payload.** It is unsigned, planted on the
   attacker account's Desktop, and the last program running before the system
   stops. Its $MFT record carries **24 March 2016** (`dir.exe`: 1 April 2016);
   extracted files keep their original dates, and Petya was first reported in
   late March 2016. *Confirm:* the hash against a malware database, or the
   author's ground truth.
2. **No file-by-file encryption is expected in these logs.** There is no mass
   rename or creation burst in the USN journal before the end, and the system
   stops at 22:56:32. That fits Petya, which forces a reboot and encrypts the
   disk's master records during a fake CHKDSK at boot — outside Windows, so
   outside Windows' logs.
3. **`share.zip` is the company file share, staged for theft.** The attacker
   browsed staff share folders on 5 Feb, and a 695 MB archive on the attacker's
   Desktop was deleted 30 s after PsExec64 ran. *Not shown:* that it left the
   server — this host's SRUM records no network usage. **Staged; exfiltration
   not evidenced.**
4. **PsExec was used to reach other machines.** It ran from this server on
   6 Feb and again one minute before the end. *Not provable from this image
   alone:* PsExec leaves its service (`PSEXESVC`) on the **target**, not here.
   The desktops' own images would show it.

## 6. What the pipeline caught, missed, and got wrong

**Caught** (rule findings): the brute-force burst (R-ATOMIC-0022, new), the
account creation (0009) and its use within the hour (R-CORR-0005), both
privileged-group additions including **Domain Admins** (R-ATOMIC-0019, new),
the tool downloads (0016), both Recycle Bin deletions including `share.zip`
(0015), and the unsigned `rename.exe` / `dir.exe` (0018).

**Missed:**
- **The successful brute force.** R-CORR-0002 (failed → success) reported
  `SEARCH TRUNCATED` on 100,023 failures and emitted nothing — the step that
  answers "how did they get in" is absent from the findings.
- **PsExec** — no rule covers it.
- **The ransomware itself** — no rule could: it acts at boot, outside Windows.
- **nmap's three-day run** — no rule on sustained execution of scanning tools.

**Noise:**
- **R-ATOMIC-0005 fired 807 times** — every external RDP logon, including 778
  by the legitimate administrator from 195.21.1.97. It is corpus-validated, so
  it also inflates `administrator`'s triage score.
- R-ATOMIC-0011 on Windows Defender's own `MsMpEng.exe` — a known false
  positive of that known-behavior rule.
- 1,142 firewall events are Windows' own font-driver rule churn.

## 7. A correction made during this analysis

A first reading, from rule hits alone, placed the attacker's entry at
**5 Feb 08:52** — the first `Administrator` RDP logon after the burst. **That
was wrong.** 778 of the 781 `Administrator` RDP logons come from
**195.21.1.97**, not the brute-forcing address (the other 3 are the attacker's), in working hours, over five days: the real
administrator working from home, as the README describes. The actual entry is
**5 Feb 10:55:56 from 36.133.110.87**. Found by grouping logons by source
address instead of by account. It is the same failure the rule layer has:
**temporal order read as causation**, and exactly why R-CORR-0002's truncation
matters.

## 8. Open questions

- The author's ground truth: payload identity, whether `share.zip` was
  exfiltrated, and which hosts PsExec reached.
- The failed console logons as `admin` on 9 Feb (21:46, 22:54) from `::1`.
- Morning `Administrator` network logons from each desktop on 6 Feb
  (09:29–10:00): consistent with legitimate administration; unresolved.
