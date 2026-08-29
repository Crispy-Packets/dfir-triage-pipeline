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
