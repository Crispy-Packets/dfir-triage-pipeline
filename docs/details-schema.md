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
