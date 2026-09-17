"""PSReadLine's `ConsoleHost_history.txt`: what was typed at a PowerShell prompt.

Every command a user types into an interactive PowerShell session is appended
here by PSReadLine, in plaintext, **regardless of whether script-block logging
is enabled**. That is the whole point of parsing it:

* `evtx.powershell` 4104 records script blocks, and only when logging is on --
  measured, `clean_c`'s first collection held 5 rows against 470 with it on;
* this file holds the typed line even when the channel holds nothing at all.

**It is not a log and carries no timestamps.** PSReadLine appends lines; it
records no time, no session boundary and no exit status. So every event is
`presence` and carries the file's own modification time -- the one thing that
can be said is that the command is in the file, not when it ran.

**Order is the only sequence information available**, and it is preserved: the
line number is the locator, so a consumer can reconstruct what was typed after
what, within a file.

**A multi-line command spans several lines.** PSReadLine writes a backtick
continuation at the end of each incomplete line, exactly as typed. Those lines
are joined back into one command, because splitting them would report fragments
like `'HKCU:\\Software\\...\\RunOnce',` as if they were commands.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from ..model import Event
from . import register

_BASENAME = "consolehost_history.txt"

#: PSReadLine's line continuation, as typed at the prompt.
_CONTINUATION = "`"

#: A defence against a pathological file rather than a judgement about what a
#: real command looks like: a single logical command is capped so a file full
#: of continuations cannot build one unbounded string.
_MAX_CONTINUATION_LINES = 200


def join_continuations(lines: list[str]) -> list[tuple[int, str]]:
    """(1-based line number, command), joining backtick continuations.

    The number is the FIRST line of a multi-line command, so the locator points
    at where the command starts in the file.
    """
    commands: list[tuple[int, str]] = []
    buffer: list[str] = []
    start = 0

    for index, raw in enumerate(lines, start=1):
        line = raw.rstrip("\r\n")
        if not buffer:
            start = index
        if line.rstrip().endswith(_CONTINUATION) and len(buffer) < _MAX_CONTINUATION_LINES:
            buffer.append(line.rstrip()[: -len(_CONTINUATION)])
            continue
        buffer.append(line)
        command = "\n".join(buffer).strip()
        buffer = []
        if command:
            commands.append((start, command))

    if buffer:
        command = "\n".join(buffer).strip()
        if command:
            commands.append((start, command))

    return commands


def _hive_user(relative_path: str) -> str | None:
    parts = relative_path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return None


class PsHistoryParser:
    name = "ps_history"

    def can_handle(self, relative_path: str) -> bool:
        return relative_path.replace("\\", "/").lower().endswith(_BASENAME)

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        # PSReadLine writes UTF-8; errors="replace" rather than raising, so a
        # single bad byte does not discard 256 commands.
        text = abs_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        commands = join_continuations(lines)
        user = _hive_user(relative_path)

        # The file's mtime is the only time available, and it belongs to the
        # FILE rather than to any one command -- every event shares it, which
        # is D-027's situation exactly.
        try:
            modified = datetime.fromtimestamp(abs_path.stat().st_mtime, tz=UTC)
        except (OSError, OverflowError, ValueError):
            modified = datetime(1601, 1, 1, tzinfo=UTC)

        for number, command in commands:
            yield Event(
                timestamp=modified,
                source_artifact="ps_history",
                event_type="command_typed",
                action="command typed at a PowerShell prompt",
                source_file=relative_path,
                source_locator=f"line/{number}",
                # Not `recorded`: the file says the command is present, not
                # when it was run. PSReadLine writes no timestamps at all.
                timestamp_type="presence",
                path=command,
                user=user,
                details={
                    "command": command,
                    "history_line": str(number),
                    "commands_in_file": str(len(commands)),
                },
            )


register(PsHistoryParser)
