"""Scheduled Tasks: persistence that the Security log does not record.

4698 (task created) belongs to the *Object Access* audit subcategory, which is
**off by default**. Measured across all five collections: **zero** 4698 events.
The task definitions under `Windows\\System32\\Tasks` are therefore the only
record that a scheduled task exists at all -- the same argument that makes the
registry `Services` key worth parsing beside System 7045, and for a task it is
stronger, because there is no enabled-by-default event to fall back on.

**Each file is one task**, stored as UTF-16LE XML with a BOM, in a directory
tree that mirrors the task's folder path. All 220 files in `s1_v3` parse.

**`ComHandler` outnumbers `Exec`, 116 to 106.** A task action is either a
command line (`<Exec><Command>`) or a **COM class id** (`<ComHandler><ClassId>`)
with no command line anywhere in the file. A parser reading only `<Exec>` drops
more than half the tasks on this evidence, silently -- and drops precisely the
fileless shape, where persistence is a CLSID pointing at a registered object
rather than a path on disk. Both are emitted, distinguished by `action_type`.

**The task's identity is its URI, normalised.** `<RegistrationInfo><URI>` is
inconsistent about its leading backslash even within one collection (three of
the first four carry it, one does not), so it is normalised to a single leading
separator. Without that the same task reached by two spellings becomes two
entities, and a rule joining on identity would see neither.

**What this parser does not claim.** A task definition says a task EXISTS and
what it would run. It does not say the task ever ran: that is `<LastRunTime>` in
the Task Scheduler's own log and in `SOFTWARE\\Microsoft\\Windows NT\\
CurrentVersion\\Schedule\\TaskCache`, neither of which is read here. The event
carries `timestamp_type=presence` and the file's own registration date, for the
same reason the registry Run keys do (D-027).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from ..model import Event
from . import register

_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"

#: Everything under this directory is a task definition. KAPE preserves the
#: tree, and the path below it IS the task's folder path.
_TASKS_ROOT = "windows/system32/tasks/"

#: Files Windows keeps beside the definitions that are not definitions, and
#: the legacy binary `.job` format this parser does not read.
#:
#: Matching by NAME rather than by "has no extension", which was the first
#: attempt and was wrong: 5 of the 220 task names on `s1_v3` contain a dot --
#: `GoogleUpdaterTaskSystem152.0.7933.0{...}` and four `.NET Framework NGEN
#: v4.0.30319` variants, whose names BEGIN with one. An extension test drops
#: real tasks silently, which is the failure this pipeline keeps finding.
_NOT_A_TASK = frozenset({"sa.dat", "desktop.ini", "thumbs.db"})
_NOT_A_TASK_SUFFIX = (".job", ".log", ".tmp")


def _q(tag: str) -> str:
    return _NS + tag


def _text(node: ET.Element | None, tag: str) -> str | None:
    if node is None:
        return None
    found = node.find(_q(tag))
    if found is None or found.text is None:
        return None
    value = found.text.strip()
    return value or None


def normalise_uri(uri: str | None, relative_path: str) -> str:
    r"""The task's identity, as a single-leading-backslash path.

    `<URI>` is inconsistent about the leading separator even within one
    collection, so the same task reached two ways would otherwise become two
    entities and a rule joining on identity would match neither.

    Falls back to the path under `Tasks\` when the element is missing: the
    directory tree mirrors the task folder, so the identity is recoverable
    without the XML claiming it.
    """
    if uri:
        return "\\" + uri.strip().replace("/", "\\").lstrip("\\")

    lowered = relative_path.lower().replace("\\", "/")
    marker = _TASKS_ROOT
    index = lowered.find(marker)
    tail = relative_path.replace("/", "\\")
    if index != -1:
        tail = relative_path[index + len(marker) :].replace("/", "\\")
    return "\\" + tail.lstrip("\\")


def parse_registration_date(raw: str | None) -> datetime | None:
    """`<Date>` to aware UTC, or None.

    Two shapes appear, and they are handled DIFFERENTLY on purpose. Measured
    across four collections: 86 naive, 4 carrying an offset, none with `Z`.

    * **Naive** (`2010-09-30T14:53:37.9516706`) -- the file states no zone, so
      UTC is ATTACHED rather than converted. This is D-013's decision: a naive
      value is the subject machine's wall clock, and converting it would apply
      the ANALYST's zone to the SUBJECT's clock.
    * **Offset-bearing** (`2005-06-23T13:48:00-08:00`) -- here the file DOES
      state its zone, so the value is converted to UTC, which preserves the
      instant. Attaching UTC instead would silently move the event by eight
      hours.

    The conversion is also required rather than merely correct: CD-019's
    `Event` validation rejects a non-zero offset outright, and the four
    offset-bearing tasks raised `ValueError: timestamp must be UTC` until this
    branch existed. The contract caught it; see D-045.
    """
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _actions(root: ET.Element) -> list[dict[str, str]]:
    """Every action the task would take, in document order.

    A task may declare several. Each becomes its own event, because two actions
    are two things that would run and collapsing them would hide one.
    """
    found: list[dict[str, str]] = []
    container = root.find(_q("Actions"))
    if container is None:
        return found

    for child in container:
        kind = child.tag.split("}")[-1]
        if kind == "Exec":
            command = _text(child, "Command")
            if not command:
                continue
            action = {"action_type": "exec", "command": command}
            arguments = _text(child, "Arguments")
            if arguments:
                action["arguments"] = arguments
            working = _text(child, "WorkingDirectory")
            if working:
                action["working_directory"] = working
            found.append(action)
        elif kind == "ComHandler":
            class_id = _text(child, "ClassId")
            if not class_id:
                continue
            # No command line exists for a COM action. The CLSID is the whole
            # of what would run, and resolving it to a DLL needs the SOFTWARE
            # hive, which this parser does not read.
            action = {"action_type": "com_handler", "com_class_id": class_id}
            data = _text(child, "Data")
            if data:
                action["com_data"] = data
            found.append(action)
        # Other action kinds exist in the schema (SendEmail, ShowMessage) and
        # were removed in Windows 8. None appear in this corpus; an unknown
        # kind yields no event rather than an event with no action.

    return found


def _principal(root: ET.Element) -> tuple[str | None, str | None]:
    """(principal, run_level). The account the task would run as."""
    container = root.find(_q("Principals"))
    if container is None:
        return None, None
    for node in container.iter(_q("Principal")):
        who = _text(node, "UserId") or _text(node, "GroupId")
        return who, _text(node, "RunLevel")
    return None, None


def _trigger_kinds(root: ET.Element) -> list[str]:
    container = root.find(_q("Triggers"))
    if container is None:
        return []
    return [child.tag.split("}")[-1] for child in container]


def _task_events(root: ET.Element, relative_path: str) -> Iterator[Event]:
    registration = root.find(_q("RegistrationInfo"))
    uri = normalise_uri(_text(registration, "URI"), relative_path)
    registered = parse_registration_date(_text(registration, "Date"))
    author = _text(registration, "Author")
    principal, run_level = _principal(root)
    triggers = _trigger_kinds(root)

    settings = root.find(_q("Settings"))
    enabled = _text(settings, "Enabled")
    hidden = _text(settings, "Hidden")

    for index, action in enumerate(_actions(root)):
        details: dict[str, str] = {"task_uri": uri, **action}
        if author:
            details["task_author"] = author
        if run_level:
            details["run_level"] = run_level
        if triggers:
            details["triggers"] = ",".join(triggers)
        # Recorded only when the XML says so. Both default to true when the
        # element is absent, and writing the default would assert a value the
        # file does not carry.
        if enabled is not None:
            details["task_enabled"] = enabled.lower()
        if hidden is not None:
            details["task_hidden"] = hidden.lower()
        if registered:
            details["registered_at"] = registered.isoformat().replace("+00:00", "Z")

        yield Event(
            # The registration date when the task declares one, else the epoch
            # sentinel the other presence-typed parsers use. Either way the
            # claim is presence: the definition says the task EXISTS, not that
            # it ever ran.
            timestamp=registered or datetime(1601, 1, 1, tzinfo=UTC),
            source_artifact="scheduled_task",
            event_type="task_registered",
            action="scheduled task defined on disk",
            source_file=relative_path,
            # The URI plus the action index: a task with two actions yields two
            # events, and CD-004 requires them to be distinguishable.
            source_locator=f"{uri}#{index}",
            timestamp_type="presence",
            path=action.get("command"),
            user=principal,
            details=details,
        )


class ScheduledTasksParser:
    name = "scheduled_tasks"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower().replace("\\", "/")
        if _TASKS_ROOT not in lowered:
            return False
        name = lowered.rsplit("/", 1)[-1]
        if not name or name in _NOT_A_TASK:
            return False
        return not name.endswith(_NOT_A_TASK_SUFFIX)

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        # ElementTree honours the XML declaration's encoding, which these files
        # carry, so the UTF-16 BOM is handled without decoding by hand.
        root = ET.parse(abs_path).getroot()
        # A file under Tasks\ that is well-formed XML but not a task definition
        # yields nothing rather than an event with no action. can_handle works
        # on names, so it cannot know this.
        if root.tag != _q("Task"):
            return
        yield from _task_events(root, relative_path)


register(ScheduledTasksParser)
