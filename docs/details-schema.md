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
| `ServiceName` | str | `evtx.system` | Service name from 7045. |
| `ImagePath` | str | `evtx.system` | Service binary path from 7045, as recorded, including any arguments and quoting. |
| `ServiceType` | str | `evtx.system` | Service type from 7045, e.g. `user mode service`. |
| `StartType` | str | `evtx.system` | Start type from 7045, e.g. `auto start`, `demand start`. |
| `AccountName` | str | `evtx.system` | Account the service runs as, from 7045. |
