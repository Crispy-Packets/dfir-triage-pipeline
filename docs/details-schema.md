# details key schema

**Rule: a key must be declared in this table before any parser emits it.** CD-012.

`details` is a free-form dict on `Event`, excluded from the `event_id` hash and
from equality (CD-005, CD-008). That freedom is what makes an undeclared key
dangerous: it costs nothing to add, participates in no test, and a downstream
rule that reads it will silently find nothing when a parser stops emitting it.
Declaring the key here is the only thing that makes it part of the contract.

All values are serialised as strings. A key whose value is not available is
**omitted**, never emitted as an empty string, `"None"`, or `0` -- an absent key
means the artifact did not record it, whereas a present key asserts a value the
artifact did record.

## Prefetch

| key | type | emitted by | meaning |
|---|---|---|---|
| `executable` | str | `prefetch` | Executable name exactly as recorded in the Prefetch record's `executableName`, uppercase as the artifact stores it. Not a path, not case-folded. The case-folded form of this value is CD-010's primary join key. |
| `run_count` | str(int) | `prefetch` | Number of times the binary has been executed, read from offset `0xC8` of the version-30 file information block. **Not** the library's `runCount`, which is read at the wrong offset (CD-018, D-023). Omitted entirely when it cannot be read. Always `>=` the number of Events from the same file. |
| `volume_serial` | str | `prefetch` | Volume serial in hex, from the record's `volSerialNumber` attribute (**not** `volumeSerialNumber`, which does not exist on this library and returns `None` silently). Input to the volume-serial to drive-letter map in Week 3's `core/entity.py`. |
| `path_source` | str | `prefetch` | Provenance of the `path` field. Currently always `prefetch_executable_name`, recording that `path` holds a bare executable name rather than a full path -- so a consumer never mistakes it for one. |

## EVTX

Seeded from the six declared EIDs. Person A owns these rows; keys are declared
here before emission, same rule.

| key | type | emitted by | meaning |
|---|---|---|---|
| `LogonType` | str(int) | `evtx.security` | Numeric logon type from 4624/4625. 2 interactive, 3 network, 10 RemoteInteractive. |
| `IpAddress` | str | `evtx.security` | Source address from 4624/4625. May be `-` or `::1` as recorded; emitted as recorded. |
| `WorkstationName` | str | `evtx.security` | Originating workstation as recorded in 4624/4625. |
| `LogonProcessName` | str | `evtx.security` | Logon process from 4624/4625, e.g. `NtLmSsp`, `Advapi`. |
| `SubStatus` | str | `evtx.security` | Failure sub-status from 4625; distinguishes bad password from disabled account. |
| `CommandLine` | str | `evtx.security` | Process command line from 4688, present only when command-line auditing is enabled. |
| `ParentProcessName` | str | `evtx.security` | Creator process image path from 4688. |
| `NewProcessId` | str | `evtx.security` | New process id from 4688, as recorded (hex in the XML). |
| `SubjectDomainName` | str | `evtx.security` | Domain of the subject account. |
| `SubjectLogonId` | str | `evtx.security` | Logon id linking a process-creation record to its session. |
| `TargetUserName` | str | `evtx.security` | Account **created** by a 4720, as recorded. Distinct from `SubjectUserName`, which is the account that performed the creation. Without this an account-creation base rate can be counted but its members cannot be told apart, which is what A-4 requires (D-029). |
| `TargetDomainName` | str | `evtx.security` | Domain or machine scope of the created account from 4720. Local accounts carry the machine name. |
| `SubjectUserName` | str | `evtx.security` | Account that performed the recorded action, from 4688, 4720 and 1102. For 4720 this is the creator, never the created account. |
| `ServiceName` | str | `evtx.system` | Service name from 7045. |
| `ImagePath` | str | `evtx.system` | Service binary path from 7045, as recorded, including any arguments and quoting. |
| `ServiceType` | str | `evtx.system` | Service type from 7045, e.g. `user mode service`. |
| `StartType` | str | `evtx.system` | Start type from 7045, e.g. `auto start`, `demand start`. |
| `AccountName` | str | `evtx.system` | Account the service runs as, from 7045. |
| `ScriptBlockId` | str | `evtx.powershell` | GUID shared by every fragment of one script block from 4104. The join key for reassembly. |
| `MessageNumber` | str(int) | `evtx.powershell` | 1-based index of this fragment within its script block. |
| `MessageTotal` | str(int) | `evtx.powershell` | Total fragment count for this script block. With MessageNumber, tells a whole script from one third of one. |
| `Path` | str | `evtx.powershell` | Source file of the script block when it came from a file. Absent for interactive or in-memory blocks, which is meaningful and is why it is omitted rather than emitted empty. |
| `script_block_text` | str | `evtx.powershell` | Script text from 4104, **capped at 4096 UTF-8 bytes** (`SCRIPT_BLOCK_TEXT_CAP`). Truncated on a character boundary. Because it may be partial, a rule may read it with POSITIVE operators only -- `not_contains` against a capped field asserts absence the evidence does not support. See D-031. |
| `script_block_text_bytes` | str(int) | `evtx.powershell` | Full byte length of the ORIGINAL script text, always the untruncated figure. Lets a consumer measure how much was not recorded instead of inferring it. |
| `script_block_truncated` | str | `evtx.powershell` | Literal `true`, present only when the cap was hit. Absent means the text is complete. |

### WMI-Activity 5861 (`evtx.wmi`), added 2026-09-15

A permanent event subscription: a filter bound to a consumer, which fires
whenever the filter's query matches. This is what fileless WMI persistence
leaves behind (T1546.003) -- it survives a reboot and touches no file on disk.

| key | type | families | meaning |
|---|---|---|---|
| `Namespace` | str | `evtx.wmi` | WMI namespace the binding was registered in, e.g. `//./root/subscription`. |
| `ESS` | str | `evtx.wmi` | Name of the event filter half of the binding. |
| `CONSUMER` | str | `evtx.wmi` | The consumer half, including its class -- `CommandLineEventConsumer` is the one that runs a command, `NTEventLogEventConsumer` writes a log entry. |
| `PossibleCause` | str | `evtx.wmi` | The channel's own diagnostic text, which carries the full `__EventFilter` instance **including its WQL Query**. The query is the discriminating field: `Namespace` and `ESS` name the subscription, the query says what triggers it. Carried verbatim and uncapped -- unlike `script_block_text` it is not truncated, so negative operators are permitted against it. |

### TerminalServices-LocalSessionManager 21/25 (`evtx.rdp`), added 2026-09-15

| key | type | families | meaning |
|---|---|---|---|
| `User` | str | `evtx.rdp` | `DOMAIN\\user` as the channel recorded it. Not split -- CD-010's principle is that a parser records what the artifact wrote, and principal normalisation happens in `core/entity.py` where it is visible. Also emitted as `Event.user`. |
| `SessionID` | str(int) | `evtx.rdp` | Terminal Services session number. Session 1 is typically the console. |
| `Address` | str | `evtx.rdp` | **The discriminating field.** Literal `LOCAL` for a console logon, an IP address for a remote desktop session. Without it a rule cannot tell the two apart and every console logon reads as remote access. |


### SYSTEM hive: Shimcache (`shimcache`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `shimcache_position` | str(int) | `shimcache` | 0-based index in the cache. **The only stable identifier the artefact offers** -- there is no id, and order is meaningful: entry 0 was inserted most recently. It is also the `source_locator`. |
| `file_modified` | str | `shimcache` | The FILETIME the entry carries, which is the file's MODIFICATION time -- a property of the file, not of when it was seen. Omitted when the artefact recorded zero, which means "not recorded" rather than 1601. |

### SYSTEM hive: BAM (`bam`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `sid` | str | `bam` | The security identifier the entry sits under. **This is the artefact's reason for existing**: Prefetch records that a binary ran and carries no principal at all, so BAM is what re-attributes an execution after a 4688 is destroyed. Also emitted as `Event.user`. |
| `bam_service` | str | `bam` | `bam` or `dam`. DAM is the Desktop Activity Moderator and is absent on most desktop builds; the key says which service recorded the entry rather than merging two sources. |

### SYSTEM hive: Services (`services`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `service_name` | str | `services` | Registry key name, which is the service's short name. |
| `image_path` | str | `services` | `ImagePath` exactly as recorded. Frequently a command line rather than a path, so `paths.derive` declines it by design (CD-021, D-032). |
| `start_type` | str | `services` | `boot`, `system`, `auto`, `manual` or `disabled`, decoded from the numeric value. The raw number is kept when it is outside the documented set rather than guessed at. |
| `service_type` | str | `services` | `kernel_driver`, `fs_driver`, `own_process` or `shared_process`, decoded the same way. |
| `account` | str | `services` | `ObjectName` -- the principal the service runs as. Omitted when absent, which is meaningful: a driver has none. Also emitted as `Event.user`. |

### SAM hive (`sam`), added 2026-09-17

The Security log records account events; SAM records accounts. After
`wevtutil cl security` the log holds neither, and SAM holds both.

| key | type | families | meaning |
|---|---|---|---|
| `rid` | str(int) | `sam` | Relative identifier, the account's last SID component. Unique within the hive and stable across renames, which a name is not, so it is also the `source_locator` (as the hex key name). |
| `logon_count` | str(int) | `sam` | Interactive logons counted by SAM itself, not by the log. **The value the artefact exists for**: a non-zero count with no 4624 is authentication the log no longer holds. Measured 0 on every built-in account and 1-29 on used ones across the five collections. |
| `account_flags` | str | `sam` | Comma-separated, sorted, decoded from the flags WORD: `disabled`, `normal_account`, `password_never_expires`, `password_not_required`, `account_auto_locked`, `workstation_trust`, `server_trust`, `home_directory_required`, `temporary_duplicate`. Omitted when no known bit is set. Undecoded bits are dropped rather than guessed at. |
| `well_known` | str | `sam` | `administrator`, `guest`, `default_account` or `wdag_utility` for RIDs 500/501/503/504. Named rather than suppressed: a rule may want to know an account is built-in, and hiding built-ins would remove evidence that one was enabled or used. Absent for RIDs >= 1000. |
| `last_logon` | str | `sam` | ISO-8601 Z, or the literal `never`. `never` is written explicitly rather than omitting the key, because SAM's zero means the logon never happened -- which a missing key could not distinguish from a field this parser failed to read. |
| `password_last_set` | str | `sam` | Same encoding, same `never` convention. Creation-adjacent: Windows sets it when the account is created, so on an untouched account it approximates the creation time that 4720 would have carried. |
| `password_last_failed` | str | `sam` | Same encoding. A failed-authentication time SAM keeps independently of 4625. |

**Why `last_run` and not a new `last_logon` timestamp type.** CD-019's
vocabulary is defined by shape -- "the artifact records only the most recent
occurrence" -- and SAM's single overwritten slot behind a count of 13 logons is
exactly that shape. A separate term would split one concept in two and break
every rule that reasons over recency. An account that never logged on has no
such time at all; it carries the key's last-write and `presence` instead.

**Why the event timestamp is NOT the key's last-write time.** Measured across
all five collections: the user key's last-write is EXACTLY the last-logon
FILETIME on every account with a non-zero logon count, because Windows rewrites
the key on logon. Timestamping by the key write would restate one fact twice
and label it `presence`, understating what the artefact knows.

**What this parser does not read.** No password hash and no decryption. The `V`
value holds the NT hash and `SupplementalCredentials` holds more; neither is
touched. A triage pipeline that extracted credential material would be a
different tool with different handling requirements.

### SRUM (`srum`), added 2026-09-17

Two providers of one ESE database, sharing a clock, an id map and a flush
cycle. `Event.path` carries the application identity **as SRUM recorded it**
(CD-010) — a device path, a bare service name, or an AppX package identity.
Which of the three shapes appears is itself information about how the program
was launched, so they are not normalised into a common form.

| key | type | families | meaning |
|---|---|---|---|
| `srum_provider` | str | `srum` | `network_data_usage` or `application_resource_usage`. The provider GUID the row came from, so a consumer can tell the two tables apart after they are merged into one family. |
| `bytes_sent` | str(int) | `srum` | `network_usage` rows only. Bytes the application sent during the interval. **The value this artefact exists for** — no other family in the pipeline attests to transfer volume. |
| `bytes_received` | str(int) | `srum` | `network_usage` rows only. |
| `bytes_read` | str(int) | `srum` | `resource_usage` rows only. Foreground plus background disk reads, summed: the split is a scheduling detail, not a forensic distinction. |
| `bytes_written` | str(int) | `srum` | `resource_usage` rows only, summed the same way. |
| `cpu_cycles` | str(int) | `srum` | `resource_usage` rows only. Foreground plus background cycle time. A raw cycle count, not seconds — the conversion needs a clock rate SRUM does not record. |

**`<unattributed>` is a real value in `path`.** `AppId=1` resolves under no
IdType; it is SRUM's own sentinel for traffic it could not attribute. Measured
41/41/54/26/31 rows across the five collections. Those rows are emitted with
the sentinel rather than dropped — the bytes were still moved — and rather than
given a fabricated `<id 1>` name, which would put an invented identifier into a
field a rule may join on. **An unresolvable id other than 1 yields no event.**

**Timestamps are OLE automation dates arriving as ints.** `dissect` declares
the column `JET_coltyp.DateTime` and returns `4676592689485971456`. That is the
raw float64 *bits*, not a scaled tick count: they must be reinterpreted
(46274.1875 days from 1899-12-30 = 2026-09-09T04:30Z). Scaling instead places
the event roughly 148 million years out, and nothing raises. Values outside
1995–2100 are rejected as decode failures rather than emitted.

**`IdType=3` is the SID; 0, 1 and 2 are all application identities.** This is
the opposite of the numbering in most format write-ups, and taking it on faith
attributes every row to the wrong party. Established by reading the blobs:
`IdType=3` holds `\x01\x01\x00\x00\x00\x00\x00\x05\x14\x00\x00\x00` (`S-1-5-20`),
`IdType=0` holds `!!WmiPrvSE.exe!2019/10/16:23:45:21!860a3!`.

**`timestamp_type` is `recorded`** for both providers. The row is an observation
of an interval that the provider flushed, not a presence claim about the program
— but note the interval's *start* is not recorded, only the flush time.

### Scheduled tasks (`scheduled_task`), added 2026-09-17

One file is one task; one task may yield several events, one per declared
action. `Event.path` carries the command **as recorded** (CD-010), environment
variables unexpanded — `%windir%\system32\rundll32.exe` is what the file says,
and expanding it would assert a resolution this parser did not verify.

| key | type | families | meaning |
|---|---|---|---|
| `task_uri` | str | `scheduled_task` | The task's identity, normalised to a single leading backslash. `<URI>` is inconsistent about that separator even within one collection, so the raw value would split one task into two entities. Falls back to the path under `Tasks\` when the element is absent — the directory tree mirrors the task folder. |
| `action_type` | str | `scheduled_task` | `exec` or `com_handler`. **Measured 106 exec against 115 com_handler on `s1_v3`**: most tasks run a COM object, not a command line, and a parser reading only `<Exec>` drops over half of them. |
| `command` | str | `scheduled_task` | `exec` actions only. Also emitted as `Event.path`. |
| `arguments` | str | `scheduled_task` | `exec` actions only, when present. Frequently carries the real payload: `rundll32.exe` is the command and the DLL plus entry point are here. |
| `working_directory` | str | `scheduled_task` | `exec` actions only, when present. |
| `com_class_id` | str | `scheduled_task` | `com_handler` actions only. The CLSID that would be instantiated. **No command line exists for these** — resolving the CLSID to a DLL needs the SOFTWARE hive, which this parser does not read, so the id is reported as the artefact recorded it. |
| `com_data` | str | `scheduled_task` | `com_handler` actions only, when present. Opaque data passed to the handler. |
| `task_author` | str | `scheduled_task` | `<Author>`, when present. Self-declared and trivially forged; it is evidence of what the file claims, not of who wrote it. |
| `run_level` | str | `scheduled_task` | `HighestAvailable` or `LeastPrivilege`. Measured 82 `HighestAvailable` on `s1_v3`. |
| `triggers` | str | `scheduled_task` | Comma-separated trigger element names in document order — `LogonTrigger`, `BootTrigger`, `TimeTrigger`, `EventTrigger`, `WnfStateChangeTrigger`, and others. A task with no `<Triggers>` block omits the key rather than claiming none. |
| `task_enabled` | str | `scheduled_task` | `true`/`false`, **only when the XML states it**. Absent means the element was missing, which is not the same as `true` — writing the default would assert a value the file does not carry. |
| `task_hidden` | str | `scheduled_task` | Same convention. Measured 57 hidden tasks on `s1_v3`; hidden is normal for OS tasks and is not on its own suspicious. |
| `registered_at` | str | `scheduled_task` | ISO-8601 Z, when `<Date>` is present. **Measured 26 of 222 on `s1_v3`** — most tasks carry no registration date at all, which is why it is a detail rather than the event timestamp. |

**Timestamps: two shapes, handled differently on purpose.** Measured across four
collections: **86 naive, 4 offset-bearing, none with `Z`**.

- Naive (`2010-09-30T14:53:37.9516706`) → UTC is **attached**, not converted.
  D-013's decision: the value is the subject machine's wall clock, and
  converting applies the *analyst's* zone to the *subject's* clock.
- Offset-bearing (`2005-06-23T13:48:00-08:00`) → **converted** to UTC, which
  preserves the instant. Attaching UTC would move the event eight hours.

`Event` validation rejects a non-zero offset (CD-019), so the four
offset-bearing tasks raised until this branch existed — see D-045.

**`timestamp_type` is `presence`.** The definition says a task EXISTS and what
it would run. It does **not** say the task ever ran: `LastRunTime` lives in the
Task Scheduler's own log and in `SOFTWARE\...\Schedule\TaskCache`, neither of
which is read here. Tasks with no `<Date>` carry the 1601 sentinel, as the other
presence-typed families do.

### NTUSER Explorer keys, added 2026-09-17

Four families out of one hive, all **per-user by construction**: the keys sit
inside one profile, so the principal is the hive's owner and needs no inference.
`Event.user` is the account name taken from the hive's own path under `Users\`.

#### UserAssist (`userassist`)

| key | type | families | meaning |
|---|---|---|---|
| `run_count` | str(int) | `userassist` | GUI launches, counted by Explorer itself. Offset 4 of the 72-byte record. Measured max 48 on `s1_v2`; the scenario payload shows **28**. |
| `focus_count` | str(int) | `userassist` | Times the window took focus. Offset 8. |
| `focus_seconds` | str(int) | `userassist` | Focus time, converted from the millisecond value at offset 12. Seconds because the sub-second precision is not meaningful for a focus duration. |
| `userassist_guid` | str | `userassist` | The containing GUID subkey. `{CEBFF5CD-…}` is shortcut launches, `{F4E57C4B-…}` is executables; the id is recorded rather than translated, because the translation is a convention this parser has not verified. |

**Value names are ROT13.** `HRZR_PGYFRFFVBA` is `UEME_CTLSESSION`. A parser that
skips the decode emits garbage paths that look like real data.

**The record is 72 bytes with the FILETIME at offset 60** — not at the front. A
shorter blob is rejected rather than partially decoded: the time is the last
field, so a truncated record yields a run count with a time read from the wrong
bytes. Measured on `clean_b`: 57 records of 72 bytes, 2 of 1612.

The 1612-byte `UEME_CTLSESSION` values are **session aggregates, not programs**,
and are skipped. Emitting one would invent a binary of that name with a run
count of several hundred.

`timestamp_type` is `last_run` when the record carries a real FILETIME
(measured 85 of 124 on `s1_v2`) and `presence` otherwise — a zero there means
Explorer recorded no time, not 1601.

#### RecentDocs (`recentdocs`), TypedPaths (`typedpaths`), RunMRU (`runmru`)

| key | type | families | meaning |
|---|---|---|---|
| `value_name` | str | all three | The MRU slot name (`0`, `1`, `a`). Position in the list, which is the only ordering the artefact offers. |
| `value_count_in_key` | str(int) | all three | How many sibling values share this key's last-write time. **D-027 applies exactly**: the timestamp belongs to the key, not the value. |
| `recentdocs_extension` | str | `recentdocs` | The extension subkey (`.txt`, `.pdf`, `Folder`), when the entry came from one rather than from the root. |

**RecentDocs values are UTF-16LE up to a null CODE UNIT, then a shell-link
tail.** Splitting on a single null *byte* truncates mid-character — `test_doc`
came back as `test_doc�`. The tail is a binary structure this parser does
not decode.

**`MRUList` and `MRUListEx` are ordering bookkeeping**, not entries, and are
skipped in all three families.

**RunMRU values carry a literal `\1` suffix** (`VBoxTray.exe\1`) which is the
MRU ordering marker, stripped before the command is reported.

All three are `timestamp_type=presence`: the containing key's last write, shared
by every sibling value.

**What these keys do not attest.** UserAssist counts **GUI launches only** — a
program started from a command line, a script, or a service leaves no entry, so
a zero count is not evidence of no execution. RecentDocs records that a name was
opened through the shell, not that a file exists: entry 15 on `clean_b` decodes
to a URL query string rather than a filename, which is why the recorded string
is reported without asserting it is a path.

### Shell links (`lnk`), added 2026-09-17

One event per file. `Event.path` is the target's **full local path** when the
link carries one, falling back to the relative path; a link with neither yields
no event. `Event.user` is the profile owner when the link lives under `Users\`.

| key | type | families | meaning |
|---|---|---|---|
| `lnk_location` | str | `lnk` | `recent` or `installed`. Links under `AppData\Roaming\Microsoft\Windows\Recent` were written by Explorer when a user opened something; those under Start Menu, Desktop and Quick Launch were installed by software and describe the machine's configuration rather than anyone's activity. **The distinction matters for every rule**: an installed link is not evidence of use. Measured on `s1_v2`: 38 recent, 16 installed. |
| `target_size` | str(int) | `lnk` | The target file's size in bytes, as recorded in the link header. `0` for directories and for targets that no longer existed when the link was written. |
| `volume_serial` | str | `lnk` | Eight uppercase hex digits, from the volume the **target** lived on. Measured: `A62AF538` is host 1's system disk, `5659C38D` the transfer volume, `18334A83` a removable device present in `s1_v2` alone. |
| `volume_label` | str | `lnk` | The volume's label, when the link records one. `New Volume`, `JOE`. |
| `drive_type` | str | `lnk` | `fixed`, `removable`, `remote`, `cdrom`, `ramdisk`, `no_root_directory` or `unknown`, decoded from the numeric field. **This is the CD-013 field.** |
| `relative_path` | str | `lnk` | The path relative to the link, when present — `..\..\..\Downloads\Files.zip`. |
| `working_dir` | str | `lnk` | The working directory, when present. |
| `arguments` | str | `lnk` | Command-line arguments, when present. Measured 2 of 69 on `s1_v2`; a Recent link normally has none, so their presence on one is worth an analyst's attention. |
| `target_created` | str | `lnk` | ISO-8601 Z. **A property of the target file**, copied into the link, not of the link itself. Omitted when the link recorded zero. |
| `target_accessed` | str | `lnk` | Same. |
| `target_modified` | str | `lnk` | Same, and the event's timestamp when present — the strongest claim the link makes about *when*. |

**`timestamp_type` is `presence`, not `recorded`.** The three FILETIMEs describe
the **target**, not the link: the OS logged no event at that instant, it copied
a property of a file. The honest claim is *this file existed with this timestamp
when the link was written* — which is exactly why a link survives the target's
deletion and is evidence of a file that may no longer exist.

**Parsing traps, both bounds-checked.** Every section after the 76-byte header
is length-prefixed and positioned relative to the one before it, so one
mis-sized field shifts everything after it and yields plausible strings read out
of the middle of other structures, without raising:

- **StringData counts CHARACTERS, not bytes.** All 256 links in this corpus are
  Unicode, so the byte length is `count * 2`. Read as bytes, every later section
  lands mid-string.
- **LinkInfo offsets are relative to the start of the LinkInfo structure**, not
  to the file. Treated as absolute they read from inside the header.

A section that would run past the end of the file ends the parse, and the fields
gathered so far are kept: a truncated link still attests to its header.
Measured: **256 files across five collections, 0 raised, 0 overran.**

**Files that yield no event.** Protocol links (`ms-settings:`,
`ms-gamingoverlay:`) name a URI handler rather than a file and carry no path at
all. A `.lnk` whose header is not a shell link yields nothing rather than
raising — a mislabelled file is not a parser fault, and raising would inflate
the failure count (D-024's reasoning).

### Recycle Bin (`recyclebin`), added 2026-09-17

The only family that attests to a **deletion**. One event per `$I` record.

| key | type | families | meaning |
|---|---|---|---|
| `original_path` | str | `recyclebin` | The file's full path before deletion. **The `$R` filename destroys this** -- `$RA9EQBZ.exe` says nothing about where the file lived. Also emitted as `Event.path`. |
| `deleted_size` | str(int) | `recyclebin` | Size in bytes at deletion. Measured on `s1_v2`: the same payload name at 201216, then 360448, then 4608 bytes over four days. |
| `info_version` | str(int) | `recyclebin` | `1` (Vista-8, fixed 260-character name) or `2` (8.1+, length-prefixed). **Read, not assumed**: applying the v1 layout to a v2 record yields a path assembled from the length prefix onward, which looks real and does not raise. |
| `sid` | str | `recyclebin` | The deleting account, taken from the `$Recycle.Bin\<SID>\` path segment. Per-SID by location, so the principal needs no inference. Also emitted as `Event.user`. |

**`timestamp_type` is `recorded`**, unlike `lnk` and the other file-metadata
families. Windows wrote this FILETIME at the moment it moved the file, so it is
an observation rather than a property copied from a target.

**`$R` files are not parsed.** They hold the deleted content itself and have no
structure of their own.

### Windows Timeline (`timeline`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `activity_type` | str(int) | `timeline` | `5` (application opened) or `6` (UserEngaged). Types 11 (settings sync) and 16 (clipboard) are **not parsed** -- they name no program. Measured on `s1_v3`: 41 / 102 / 2 / 37. |
| `active_seconds` | str(int) | `timeline` | **How long a person actively used the program.** Type 6 only. No other family in this pipeline carries a duration -- Prefetch counts runs, SRUM samples intervals, neither says someone sat in front of something. Measured max 68,791s on `s1_v2`. |
| `display_text` | str | `timeline` | The payload's `displayText` or `appDisplayName`, when present -- a human-readable name beside the raw application id. |
| `end_time` | str | `timeline` | ISO-8601 Z, when the row records one. Absent on type 5, which has no end. |

`Event.path` is the application, taken from the **most specific platform present**
in the `AppId` JSON array: `x_exe_path` (a full path, sometimes on another
drive), then `windows_win32`, `packageId`, `alternateId`. `data_boundary` is
deliberately excluded -- its application is the constant
`microsoft.default.default`, and taking the first array member blindly returns
it on most rows.

**Times are Unix epoch seconds**, not FILETIME and not OLE. Applying either of
the other two conventions used in this pipeline places the events decades away
without raising.

**A database with no `Activity` table yields nothing rather than raising.**
Measured on host 1's `admin_local`: an account that logged on but never used the
Activity Feed has an initialised, empty database. That is an absence of
evidence, not a parser fault (D-024's reasoning).

### PowerShell console history (`ps_history`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `command` | str | `ps_history` | The command as typed, with backtick continuations joined back into one line. Also emitted as `Event.path`. |
| `history_line` | str(int) | `ps_history` | 1-based line number of the command's FIRST line. **Order is the only sequence information the file carries** -- PSReadLine records no timestamps -- so the number is the locator and preserves it. |
| `commands_in_file` | str(int) | `ps_history` | How many commands the file holds, so a consumer can see where one sits in the whole. |

**`timestamp_type` is `presence`.** PSReadLine writes no timestamps at all. Every
event carries the FILE's modification time, shared by every command in it --
D-027's situation exactly. The file says a command is present, not when it ran.

**Why this is worth parsing beside `evtx.powershell`:** 4104 records script
blocks only when script-block logging is enabled. Measured: `clean_c`'s first
collection held **5** rows against **470** with it on. This file holds the typed
line even when the channel holds nothing.

**Multi-line commands are joined.** PSReadLine writes a backtick at the end of
each incomplete line, as typed; splitting on newlines would report fragments
like `'HKCU:\Software\...\RunOnce',` as if they were commands.

### JumpLists (`jumplist`), added 2026-09-17

Answers what `lnk` and `recentdocs` cannot: **which application opened the
file**. Details shared with `lnk` (`target_size`, `drive_type`,
`volume_serial`, `volume_label`, `arguments`, `working_dir`,
`target_created`/`accessed`/`modified`) carry the same meanings and are not
repeated here.

| key | type | families | meaning |
|---|---|---|---|
| `app_id` | str | `jumplist` | The filename stem, which is Windows' per-executable AppID hash. **The container names the program**, which is this family's reason to exist. Measured 5-9 distinct ids per collection. |
| `jumplist_type` | str | `jumplist` | `automatic` or `custom`. Recorded because the two are **different file formats**, not two flavours of one: automaticDestinations is an OLE compound file, customDestinations is not -- it begins `02 00 00 00` and concatenates shell links with no container at all. |

**`timestamp_type` is `presence`**, for the same reason as `lnk`: the times
describe the target file, copied into the embedded link.

**Embedded links are located by signature, not by walking the container.** For
`custom` files that IS the format. For OLE files it is a deliberate
simplification -- a full compound-file implementation (FAT, miniFAT, directory
tree, sector chains) is a large amount of code whose only job here is finding
streams the signature already finds, and a bug in it would produce plausible
wrong output. A link fragmented across non-contiguous sectors is not recovered;
measured, every link in these files is contiguous, and one that is not yields no
event rather than a wrong one, because `parse_lnk` bounds-checks every field.

A four-byte signature match is **not** accepted on its own: each candidate goes
to `parse_lnk`, which verifies the 16-byte link CLSID immediately after it.

**The DestList stream is not read.** It holds access counts and MRU ordering,
which would be worth having, but its entry size varies by Windows version and
inventing a version-dependent layout is how D-023 and D-045 happened.

### Browser (`browser`), amended 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `browser` | str | `browser` | `edge` or `chrome`. Edge and Chrome ship an identical `downloads` schema -- verified column by column on both collections' files -- so one parser serves both and this records which. **Chrome yields zero rows on this corpus**; the path is handled anyway, because a collection where Chrome was used would otherwise be silently unparsed. |

### Shellbags (`shellbags`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `bag_kind` | str | `shellbags` | `folder` or `file`, from the shell item type byte (0x31 / 0x32). |
| `short_name` | str | `shellbags` | The 8.3 name in ASCII, at a fixed offset. Always present -- it is what the item is keyed by. |
| `long_name` | str | `shellbags` | The full name in UTF-16, **anchored at the 0xBEEF extension signature + 40 bytes** -- measured on every item in the corpus regardless of short-name length. NOT computed from the end of the short name and NOT found by scanning; see D-049. Explorer's resource suffix (`Downloads@shell32.dll,-21798`) is stripped. |
| `bag_depth` | str(int) | `shellbags` | Depth in the BagMRU tree, which is the depth in the filesystem path. |
| `target_modified` | str | `shellbags` | ISO-8601 Z from the item's embedded DOS date/time. **A property of the target folder, not of when it was browsed.** DOS times are local with no zone and two-second resolution, so UTC is attached rather than converted (D-013). |

`Event.path` is the ancestry joined by backslash, built from the tree position
rather than from any single item -- `Users\janed\Downloads\Files.zip`.

**Only types 0x31 and 0x32 are decoded into names.** 0x1f (desktop root), 0x2e
and 0x2f (GUID and volume entries) hold CLSIDs and bare drive letters; decoding
them would put the UTF-16 misreading of a GUID into a path field. Their tree
positions are still walked, because ordinary folders sit beneath them.

**`timestamp_type` is `presence`** -- the containing key's last write, shared by
every sibling bag. D-027 exactly.

### USN change journal (`usn`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `usn_reason` | str | `usn` | The full reason bitmask as `0x%08x`. The event_type names the strongest flag; this preserves the rest, so a consumer can see that a deletion was also a close, or a creation also an extend. |
| `file_name` | str | `usn` | The name as recorded. Also emitted as `Event.path`. |

**`Event.path` is a NAME, never a path.** The journal identifies a file and its
parent by MFT reference number; resolving those to a full path requires the
`$MFT`, which is not parsed. The name is recorded as it stands (CD-010) rather
than being given a fabricated directory.

**Only four reasons are emitted**: `file_created`, `file_deleted`,
`file_renamed_from`, `file_renamed_to`. Data overwrites, attribute changes,
security changes and stream changes are skipped — they say a file was touched,
which is both extremely common and the weakest claim the journal makes. The
journal holds 169,304 records on `s1_v3` and 328,156 on `s1_v2`, mostly Windows
servicing writing `.mui` files.

**One operation is one event.** NTFS writes a record at each *stage* — create,
create+extend, create+extend+close — all with the same timestamp and name.
Measured: **43% of otherwise-emitted rows are such restatements**, and
`invoice_scan_marker.txt` alone produced three identical creations. The first
record for a (name, type, timestamp) wins: 44,854 → 29,655 rows on `s1_v3`.

**`timestamp_type` is `recorded`** — NTFS appends the record as the change
happens, which makes it among the strongest observations in the pipeline.

### Defender text logs (`defender_mplog`), added 2026-09-17

All four text logs under `Windows Defender\Support` share one line format, so
one parser reads them and `log_family` says which. The `MpWpp*.bin` files are
binary ETW traces and are not read — decoding them needs a TMF schema.

| key | type | families | meaning |
|---|---|---|---|
| `log_family` | str | `defender_mplog` | `mplog`, `mpdetection`, `mpscanskip` or `mpdevicecontrol`. They share a line format but not a subject. |
| `mplog_line` | str(int) | `defender_mplog` | 1-based line number, which is also the locator. |
| `process_name` | str | `defender_mplog` | `process_exec` rows. The image name the engine observed. |
| `pid` | str(int) | `defender_mplog` | `process_exec` and `scan_skipped` rows. |
| `scan_time_ms` | str(int) | `defender_mplog` | `process_exec` rows, when present. Accumulated engine time on that process. |
| `scan_count` | str(int) | `defender_mplog` | `process_exec` rows, when present. |
| `reported_path` | str | `defender_mplog` | `file_reported` rows. The path `ReportLowfi` named. Also `Event.path`. |

**`file_reported` is not a detection.** `ReportLowfi` is Defender's own wording
— *low fidelity* — and means the engine wanted a second opinion. Measured: zero
1116/1117 verdicts in `evtx.defender` across all five collections, while
`s1_v3`'s MPLog holds a `ReportLowfi` for the payload.

**`scan_skipped` is evidence in the D-028 sense**: the engine declining to scan
something differs from the engine scanning and finding nothing.

### LSA policy (`lsa_policy`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `sid` | str | `lsa_policy` | A SID granted a privilege beyond its group membership. Also `Event.user`. Measured 13-17 per collection. |
| `well_known` | str | `lsa_policy` | `Administrators`, `Local Service`, … for unambiguous built-ins. A domain SID is left as recorded. |
| `privilege_values` | str | `lsa_policy` | Names of the value(s) under the SID's key, when any. **The privilege LUIDs are NOT decoded to names** — the table varies by Windows version, and inventing one is how D-023 and D-045 happened. |

`\Policy\Secrets` and `PolEKList` are **not read**: LSA secrets and boot key
material, for the same reason `sam_hive.py` does not read the `V` value.

### Registry transaction logs (`registry_txlog`), added 2026-09-17

| key | type | families | meaning |
|---|---|---|---|
| `hive_name` | str | `registry_txlog` | The hive this log belongs to. |
| `log_sequence` | str(int) | `registry_txlog` | The log's primary sequence number. |
| `hive_sequence` | str(int) | `registry_txlog` | The hive's, read from its base block. |
| `log_ahead_of_hive` | str | `registry_txlog` | `true`/`false`. **The actionable field**: a log ahead of its hive holds changes the hive has never seen, so the hive alone is an incomplete answer. Measured on `clean_b`: 21 of 27 logs are ahead. |
| `pending_bytes` | str(int) | `registry_txlog` | Size of the dirty-page entry. Up to 933,376 bytes measured. |
| `entry_sequence` | str(int) | `registry_txlog` | The `HvLE` entry's own sequence, when present. |

**The logs are not replayed.** Applying dirty pages at recorded offsets and
re-parsing would produce a hive that parses cleanly and contains fabricated keys
if anything were wrong — the worst failure mode available here. A log with no
dirty pages yields no event.

### `$MFT` (`mft`), added 2026-09-17

352,768 records on `s1_v3`, streamed at a fixed 1,024 bytes each.

| key | type | families | meaning |
|---|---|---|---|
| `mft_record` | str(int) | `mft` | Record number, unique within the table and the only identifier it carries. Also the locator. Records 0-15 are NTFS metafiles and are skipped. |
| `file_name` | str | `mft` | The name from `$FILE_NAME`, preferring the long entry over the 8.3 one. Also `Event.path`. |
| `in_use` | str | `mft` | `true`/`false`. **`false` is a DELETED file whose record has not been reused** — measured 1,136 on `s1_v3`, held by no other family. |
| `is_directory` | str | `mft` | `true`/`false`. |
| `si_created`, `si_modified`, `si_mft_modified`, `si_accessed` | str | `mft` | The four `$STANDARD_INFORMATION` times, ISO-8601 Z. |
| `fn_created` | str | `mft` | The `$FILE_NAME` creation time. |

**No timestomping verdict is emitted, and the omission is deliberate.** The
textbook indicator — `$SI` earlier than `$FN` — was implemented and then
measured: **94,262 of 351,088 records on `s1_v3` and 99,955 of 287,983 on
`clean_c`**, 27% of both, led by `$Recycle.Bin`, `PerfLogs` and `Program
Files`. A file laid down from a Windows install image keeps the image's `$SI`
and gets a fresh `$FN`; that is every OS file. Both timestamps are emitted so
an analyst can compare them on a specific file; the pipeline makes no claim.
See D-051.

**`Event.path` is a NAME, never a path** — resolving a record's parent
reference needs a full-table index this parser does not build. Same limitation
as `usn`, for the same reason (CD-010).

**The fixup array is applied.** NTFS overwrites the last two bytes of each
512-byte sector with an update-sequence number; skipping the restore reads two
corrupted bytes per sector, inside filenames and timestamps, without raising. A
**torn** record — one whose sector does not carry the expected USN — is skipped
rather than repaired. Measured: zero torn in 59,992 scanned.

**Not decoded**: data runs, resident content, `$DATA` streams, attribute lists
and the directory index.

### Generic EVTX channels (`evtx.x.*`), added 2026-09-17

Every channel without a curated EID map. Family names are derived from the
filename: `Microsoft-Windows-Store%4Operational.evtx` becomes
`evtx.x.microsoft-windows-store.operational`. Measured on `s1_v3`: **88
families, 46,464 records**.

Records carry their `EventData` fields as details under the field names the
channel itself used, plus the standard EVTX keys. **No key is invented and no
EID is interpreted** -- `event_type` is always `log_record`, because this
pipeline has not studied what these EIDs mean and will not claim otherwise.

### Browser visits and searches (`browser`), added 2026-09-17

Read alongside `downloads`, which this parser read alone until now.

| key | type | families | meaning |
|---|---|---|---|
| `url` | str | `browser` | On `page_visited`, the page. Also `Event.path`. |
| `page_title` | str | `browser` | The title as recorded, when present. |
| `transition` | str | `browser` | `link`, `typed`, `form_submit`, `reload`, … from the low byte of Chromium's transition mask. **`typed` is the discriminating value**: the user wrote the address rather than following a link. |
| `transition_raw` | str(int) | `browser` | The full mask, always emitted. The name table above is deliberately incomplete, and the raw value must survive it. |
| `search_term` | str | `browser` | On `search_term`, the text typed. Also `Event.path`. Measured 65 on `s1_v3`; on `s1_v2` they include the delivery URL the operator typed by hand. |

**`keyword_search_terms` has no unique key of its own** — `keyword_id`
identifies the search *engine*, so every Bing search shares one. Using it as
the locator produced 61 duplicates and violated CD-004; the locator is
`(keyword_id, url_id)`, the table's real primary key.

A search term whose URL row carries no `last_visit_time` is `presence`-typed
rather than given an invented time.

### WebCache (`webcache`), added 2026-09-17

The WinINet history, cache and transfer index -- a different record from the
Chromium `History` database, not a duplicate.

| key | type | families | meaning |
|---|---|---|---|
| `url` | str | `webcache` | The address, with the `Visited:` marker and any date-range prefix stripped. Also `Event.path`. |
| `container` | str | `webcache` | `History`, `DOMStore`, `BackgroundTransferApi`, or `MSHist01<start><end>` for per-day history. **Read from the `Containers` index, never inferred from the table number.** |
| `container_id` | str(int) | `webcache` | The numeric id, so a finding can be traced back to `Container_<n>`. |
| `cache_directory` | str | `webcache` | The on-disk directory the container indexes, from `Containers.Directory`. |
| `access_count` | str(int) | `webcache` | How many times the entry was accessed, when non-zero. |
| `cached_bytes` | str(int) | `webcache` | `FileSize` of the cached entry, when non-zero. **The response body itself is not read.** |
| `created`, `modified`, `expires` | str | `webcache` | ISO-8601 Z, when the row records them. |

**`Event.user` comes from inside the record.** `Visited: vboxuser@https://...`
puts the account in the data, so a visit is attributed without inferring the
user from the file's path — measured on `s1_v2`, three profiles yield Youssef
62, janed 31, admin_local 18.

**`Content` containers are not emitted.** They index cache files describing what
a page loaded rather than what a person did, and on a real machine they number
in the tens of thousands.

**Timestamps are FILETIME** — a third convention beside `browser`'s WebKit
microseconds and `srum`'s OLE dates. A row with no `AccessedTime` is `presence`
rather than given an invented time, which makes this family mixed by record.

## Derived path fields (B-9)

Emitted by every parser that carries a path. These are **additions**, never
replacements: CD-010 holds, and `Event.path` always keeps exactly what the
artifact recorded alongside its derived form.

A field is **omitted rather than guessed**. A consumer that finds
`path_canonical` absent knows to fall back to `path`; a consumer handed a
wrongly-derived value has no way to detect it, and a wrong canonical path
silently joins two unrelated records.

| key | type | emitted by | meaning |
|---|---|---|---|
| `path_canonical` | str | all with a path | Case-folded comparison form, separators normalised to `\`. Lowercasing is the entire transformation, and it is safe because Windows paths are case-insensitive -- a fact about the filesystem, not a guess. **Omitted** for command lines, `\Device\HarddiskVolumeN\` paths and values holding an unexpanded `%VARIABLE%`, because a canonical form exists for those but cannot be computed without inventing the drive or the expansion. |
| `path_basename` | str | all with a path | Trailing component, in the case the artifact recorded. Omitted when the value has no separator, since there is nothing to extract -- Prefetch stores a bare name that is already its own basename. |
| `path_basename_canonical` | str | all with a path | Lowercased basename: the cross-artifact join key CD-010 names. Present for separator-less values too, because Prefetch carries no path and this is the only field by which an execution recorded there can be matched to a full path recorded elsewhere. |

Command lines receive **none** of the three. Their trailing token is an
argument, not a filename, so even a basename would be wrong. Measured, that is
95 rows of the 25,026 carrying a path -- all `service_install` and autorun
values (CD-021, D-032).

## Registry

Emitted by `registry`. The autorun value is the payload; the key's last-write
time is the only time the artifact offers, and it belongs to the **key**, not to
any single value under it.

| key | type | emitted by | meaning |
|---|---|---|---|
| `hive` | str | `registry` | Hive file the value was read from, as a collection-relative POSIX path. Distinguishes a machine-wide `SOFTWARE` entry from a per-user `NTUSER.DAT` one. |
| `hive_type` | str | `registry` | `software` or `ntuser`. The scope of the autorun: `software` runs for every user, `ntuser` for the profile owner only. |
| `key_path` | str | `registry` | Registry key path within the hive, e.g. `\Microsoft\Windows\CurrentVersion\Run`. Recorded so a finding can name the exact key without re-reading the hive. |
| `value_name` | str | `registry` | Name of the autorun value, e.g. `SecurityUpdate`. This is the attacker-chosen label and is frequently the most recognisable part of the artifact. |
| `value_data` | str | `registry` | Value data exactly as stored, including any `%APPDATA%` or quoting. CD-010: never expanded. Duplicated into `Event.path`. |
| `key_last_write` | str | `registry` | ISO-8601 UTC last-write time of the containing **key**. Emitted explicitly because `Event.timestamp` carries it while `timestamp_type` is `presence`: several values under one key share this time, and it is not the moment this value was written. |
| `value_count_in_key` | str(int) | `registry` | Number of values under the same key at collection time. A reader comparing two events with an identical timestamp needs this to understand why they match. |

## Browser

Emitted by `browser`. Edge History is SQLite; the `downloads` table records one
row per download with its own start time.

| key | type | emitted by | meaning |
|---|---|---|---|
| `url` | str | `browser` | Source URL of the download, as recorded. |
| `target_path` | str | `browser` | Filesystem path the browser wrote to, as recorded. Duplicated into `Event.path`. |
| `bytes` | str(int) | `browser` | `total_bytes` from the downloads row. Omitted when zero or absent, which the artifact uses for an incomplete download rather than for a zero-length file. |
| `mime_type` | str | `browser` | MIME type as recorded by the browser, not sniffed from content. |
| `referrer` | str | `browser` | Referring URL where recorded; omitted when empty. |
| `db_sha256` | str | `browser` | SHA-256 of the copy of the History database that was read. The file is copied out before opening (see the parser docstring); recording the hash makes the reading auditable. |

## PowerShell

Emitted by `evtx.powershell`. Script-block records are chunked: one script
arrives as N records carrying the same `ScriptBlockId`.

| key | type | emitted by | meaning |
|---|---|---|---|
| `ScriptBlockId` | str | `evtx.powershell` | GUID shared by every fragment of one script block. The join key for reassembly, which the parser does **not** perform. |
| `MessageNumber` | str(int) | `evtx.powershell` | 1-based index of this fragment. |
| `MessageTotal` | str(int) | `evtx.powershell` | Total fragments for this script block. A consumer seeing `MessageTotal > 1` must not treat one fragment as a whole script. |
| `Path` | str | `evtx.powershell` | Script path where the block came from a file; omitted for interactive or in-memory blocks, which is itself meaningful. |

## Amcache

Emitted by `amcache`. Amcache is written by a scheduled maintenance task, not at
execution time, so an entry proves the binary was **present and inventoried**,
not that it ran at the recorded moment.

| key | type | emitted by | meaning |
|---|---|---|---|
| `amcache_key` | str | `amcache` | Subkey name, of the form `<name>|<hash>`. Duplicated into `source_locator`. |
| `name` | str | `amcache` | File name as inventoried. |
| `sha1` | str | `amcache` | SHA-1 of the file, from `FileId` with its four-character field prefix stripped. Omitted when the value is not 4+40 hex characters -- a reformatted identifier is not a hash, and emitting it as one would licence a false match. |
| `size` | str(int) | `amcache` | File size in bytes as inventoried. |
| `publisher` | str | `amcache` | Publisher string from the binary's version resource, lowercased by the artifact. |
| `version` | str | `amcache` | File version as inventoried. |
| `binary_type` | str | `amcache` | e.g. `pe64_amd64`. Distinguishes architecture without reading the file. |
| `program_id` | str | `amcache` | Links the file to its `InventoryApplication` parent entry. |

### Legacy PowerShell 800 (`evtx.ps_classic`), added 2026-09-18

**Closes a gap the attestation matrix has carried as stated since it was
written** and which D-059 showed was no longer accurate: the matrix recorded
`legacy PowerShell EID 800` with the not-parsed marker, written when the whole
channel was unparsed. The channel has been parsed since 2026-09-17; EID 800
was being discarded *inside* it, because an unmapped EID in a curated channel
is dropped rather than falling through to the generic reader.

800 is pipeline execution detail. It is the **only record in this pipeline that
carries a PowerShell command line when script-block logging is off** --
`evtx.powershell` 4104 holds the script text and exists only when that logging
is enabled, and EID 600, which CD-007 cited as this channel's justification,
carries `HostApplication` but not the invoked command (D-055).

Measured 10 / 10 / 10 / 0 / 0 across the five collections. Flat on host 1 and
absent on host 2, so it **does not discriminate by volume** and no rule should
be written on its presence. It is taken for the field, not the count.

| key | type | families | meaning |
|---|---|---|---|
| `host_application` | str | `evtx.ps_classic` | **The command line of the process that started PowerShell**, e.g. `powershell.exe -ExecutionPolicy Bypass -NonInteractive -File C:\...\ps-script-….ps1`. The field D-055 records as present in the evidence and unextracted. Carries the execution-policy bypass and the script path when either is present. |
| `ps_command_line` | str | `evtx.ps_classic` | The `CommandLine` the pipeline invoked, from the record's detail block. What ran, as opposed to what launched PowerShell. Capped at `SCRIPT_BLOCK_TEXT_CAP` bytes on the same reasoning as `script_block_text`, and **positive operators only** when truncated. |
| `ps_script_name` | str | `evtx.ps_classic` | `ScriptName` -- the `.ps1` or module file the pipeline was executing, when the record names one. Often a shipped module rather than a user script. |
| `ps_user_id` | str | `evtx.ps_classic` | `UserId` as the channel wrote it, `DOMAIN\user`. Also emitted as `Event.user`, which is why this channel can be joined on `entity.user` while 811/812 cannot (D-057). |
| `ps_sequence_number` | str(int) | `evtx.ps_classic` | `SequenceNumber` within the host session. Orders records inside one PowerShell host; not a time. |
| `ps_command_line_truncated` | str | `evtx.ps_classic` | Present and `"true"` only when `ps_command_line` was cut at the cap. Absent otherwise, so truncation is measurable rather than silent. |
| `ps_command_line_bytes` | str(int) | `evtx.ps_classic` | Full UTF-8 byte length of `CommandLine` **before** truncation, always the real length. |
