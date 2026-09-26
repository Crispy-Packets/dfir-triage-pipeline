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
| `rename.exe` | SHA-1 `39b6d40906c7f7f080e6befa93324dddadcbd9fa`, 230,912 bytes, no publisher, `C:\Users\admin\Desktop` — **Petya.A (Red Petya)**, confirmed by public sandbox hash match | Amcache |
| `dir.exe` | SHA-1 `d1c62ac62e68875085b62fa651fb17d4d7313887`, 806,912 bytes, no publisher, same folder — **Petya 2 / GoldenEye variant**, confirmed by public sandbox hash match; no execution record | Amcache |
| Staged archive | `C:\Users\admin\Desktop\share.zip`, 694,728,396 bytes, deleted 6 Feb 22:14:44 | Recycle Bin |
| Tools | PsExec / PsExec64 (Sysinternals), nmap 7.93 + Npcap 1.71 | BAM, Amcache, 7045 |

## 5. Readings (inference — each needs confirmation)

1. **`rename.exe` IS the payload — confirmed 2026-09-26 by hash, not by the
   author's ground truth.** Its Amcache SHA-1 `39b6d40906c7f7f080e6befa93324dddadcbd9fa`
   appears verbatim on tria.ge (https://tria.ge/210227-bsc63lx48j: 225 KB,
   tagged *bootkit*; ours is 230,912 bytes = 225.5 KiB), whose SHA-256
   `26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739` is the
   ANY.RUN report for **Petya.A** — the original 2016 "Red Petya" the README
   names. SRUM shows it running at 22:56, the last minute before the system
   stops. `dir.exe`'s SHA-1 `d1c62ac62e68875085b62fa651fb17d4d7313887` appears
   verbatim on ANY.RUN as **"Petya 2.exe"** (a Petya 2 / GoldenEye variant):
   a second Petya build dropped beside it, with **no execution record** in
   this image (Amcache and Shimcache attest presence only). The $MFT dates
   (24 March / 1 April 2016) fit Petya's first appearance. The pipeline
   surfaced both through R-ATOMIC-0018.
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

**Caught since 2026-09-26 — how they got in.** R-CORR-0007 (new): failures
then a success **from the same source address**, joined on the account and
the new join-only key `entity.src_ip`. It fires twice on srv22 and 0 on all
five corpus collections: `[administrator, 36.133.110.87]` — success
EventRecordID 2379067 at **5 Feb 10:55:56**, 0.603 s after the last of 52,426
failures — and `[administrator, 185.229.66.183]`. Search not truncated.

**Missed (as first run):**
- **The successful brute force.** R-CORR-0002 (failed → success) reported
  `SEARCH TRUNCATED` on 100,023 failures and emitted nothing — the step that
  answers "how did they get in" is absent from the findings. **Now caught
  by R-CORR-0007 (above).** R-CORR-0002 is deliberately unchanged: made to
  finish its search, and joined on the account alone, its first valid chain
  would pair the attacker's failures with the real administrator's logon from
  195.21.1.97 — the same misread section 7 records.
- **PsExec** — no rule covers it.
- **The ransomware itself** — no rule could: it acts at boot, outside Windows.
- **nmap's three-day run** — no rule on sustained execution of scanning tools.

**Noise:**
- **R-ATOMIC-0005 fired 807 times** — every external RDP logon, including 778
  by the legitimate administrator from 195.21.1.97. It is corpus-validated, so
  it also inflated `administrator`'s triage score. **Fixed 2026-09-26:**
  grouped by `entity.src_ip`, one finding per address — **807 → 3**
  (185.229.66.183, 195.21.1.97, 31.220.85.162), and R-ATOMIC-0008 **262 → 2**.
  The findings key on the address, not the account, so they no longer inflate
  `administrator`. Trade-off, stated in the rule: an address with a single RDP
  logon no longer fires; R-CORR-0007 and R-ATOMIC-0022 cover a lone logon that
  followed guessing.
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

- The author's ground truth: whether `share.zip` was exfiltrated, which
  hosts PsExec reached, and whether `dir.exe` ever ran. (Payload identity is
  now settled by hash — section 5.)
- The failed console logons as `admin` on 9 Feb (21:46, 22:54) from `::1`.
- Morning `Administrator` network logons from each desktop on 6 Feb
  (09:29–10:00): consistent with legitimate administration; unresolved.

## 9. Correlations across artifacts

What connects, what the engine can join, and why it cannot join the rest.

| Chain (fact) | Joinable today? |
|---|---|
| Source address → 100,003 failures → success from that address | **Yes** — R-CORR-0007, on `[entity.user, entity.src_ip]` |
| Source address → RDP sessions (Security 4624 type 10, RDP LSM 21/25) | **Yes** — grouped per address by R-ATOMIC-0005/0008 |
| `admin` created (4720) → added to Administrators (4732) → Domain Admins (4728) | **No** — identity fragmentation, below |
| `admin` ran PsExec (BAM) → `share.zip` deleted 30 s later (Recycle Bin) | Joinable on the SID (both record S-1-5-21-…-2611); no rule written — one instance is not a base rate |
| `rename.exe` inventoried (Amcache) → running (SRUM) | Joinable on `entity.exe_name`; the atomic R-ATOMIC-0018 already surfaces it |

**Identity fragmentation — the largest correlation gap.** The attacker's one
account reaches the engine as three different `entity.user` values:

| Artifact | Recorded as |
|---|---|
| Account creation, 4720 | `admin` |
| Group membership, 4728 / 4732 | `cn=a admin,dc=branchoffice,dc=example,dc=com` (MemberName, a directory DN) |
| BAM, Recycle Bin, SRUM | `s-1-5-21-1057484085-1795310446-2370380301-2611` |

So no rule can join "created" → "made Domain Admin" → "ran PsExec" →
"deleted share.zip", though an analyst reads them as one actor. The fix is a
name ↔ SID ↔ DN map for the run: 4720 carries `TargetSid` (not yet kept in
`details`), 4728/4732 carry `MemberSid`, and the SOFTWARE hive's ProfileList
maps SID → profile path (`C:\Users\admin`). With `entity.user` resolved to the
SID wherever one exists, all four steps share a key. Not made before the
presentation: it changes `entity.user` for every Security-log family and needs
the five-collection measurement behind it. Recorded here as the next
correlation change.

## 10. One ML experiment — cross-host scoring, indicative only

The anomaly layer needs a baseline, and srv22 has no clean collection of the
same machine. As the one experiment possible with existing code, srv22 was
scored against `collection_clean_c` — **a different machine**, which
CLAUDE.md's "train and score within one host" rule says cannot be trusted.
MODA*-G; only `amcache` passed the family gates; **106 entities ranked**:

| Rank | Entity | |
|---|---|---|
| 1–3 | microsoftedgeupdate.exe, vboxtray.exe, msmpeng.exe | benign |
| **4** | **psexec64.exe** | attacker tool |
| **5** | **dir.exe** | Petya 2 / GoldenEye |
| **6** | **rename.exe** | **Petya.A — the payload** |
| 8, 11 | ncat.exe, zenmap.exe | from nmap |

Both Petya samples and PsExec64 rank in the top six of 106. **Indicative, not
validated:** against another machine, part of the signal is "software the
baseline never had" — which is also why Edge Update and VirtualBox's tray tool
lead. The mismatch guard (`baseline_warning`) was computed against the
baseline's own threshold and did not fire, which means at most 15 % of these
180 rows fell below it (it warns above three times the 5 % contamination
setting; the exact rate was not recorded). So the ranking is not
rejected, but it rests on one family and a cross-host comparison. The honest
claim: the anomaly layer, pointed even at the wrong baseline, placed the
payload in the top 6 % — and the rules had already put it on screen.

**MODA\*-G vs Isolation Forest on the same run (measured 2026-09-26).** Same
collection, same baseline (clean_c), same code; only `DFIR_ANOMALY_SCORER`
differs. Both ranked 106 entities from `amcache`, and neither raised
`baseline_warning`.

| Entity | MODA\*-G | Isolation Forest |
|---|---|---|
| rename.exe (Petya.A) | **6** (5.7 %) | 14 (13.2 %) |
| dir.exe (Petya 2) | **5** (4.7 %) | 13 (12.3 %) |
| psexec64.exe | **4** (3.8 %) | 6 (5.7 %) |
| psexec.exe | **16** | 23 |
| ncat.exe | **8** | 9 |
| zenmap.exe | **11** | 12 |
| nmap-7.93-setup.exe | **12** | 16 |
| nmap.exe | **23** | 78 |

MODA\*-G ranks every attack tool higher, and ranks both Petya samples more
than twice as high. That matches s1_v3 (same-host baseline): 14/443 vs 40/443.
Same caveats as above: one family, cross-host, and eight known entities are
not a labelled test set. **This is a rank comparison, not an accuracy figure;
none can be computed.** IF's top 5 is all benign (svchost, msmpeng, vboxtray,
Edge Update, msedge). MODA's is Edge Update, vboxtray, msmpeng, then
psexec64 and dir.exe.

**Ranking accuracy, the same two runs.** Labels were fixed from this document
before any score was read. Broad set: the Petya pair, PsExec/PsExec64, and the
nmap installer and suite; 9 of the 10 were ranked (Npcap was not). Strict set:
the Petya pair and PsExec only. Everything else counts as not-attack, which
means unlabelled, not proven benign.

| Labels | Scorer | ROC AUC | Avg precision (chance) | Attack in top 10 |
|---|---|---|---|---|
| broad (9) | MODA\*-G | **0.943** | **0.463** (0.085) | **5 of 9** |
| broad (9) | IF | 0.843 | 0.301 (0.085) | 2 of 9 |
| strict (4) | MODA\*-G | **0.949** | **0.350** (0.038) | **3 of 4** |
| strict (4) | IF | 0.887 | 0.177 (0.038) | 1 of 4 |

s1_v3 has one labelled entity, so its AUC is only a restatement of its rank:
MODA\*-G 0.971 (14/443), IF 0.912 (40/443).

With 4 to 9 positives, one host pair and one family, these figures are
**indicative and not significance-tested**. They are ranking accuracy (how
high the attack sits), not detection accuracy: no threshold, no confusion
matrix. The anomaly layer ranks; the rules detect. Script:
`rank_accuracy.py`, computed from the rank order in the two run.json files.
