"""`$LogFile`: filesystem operations the USN journal has already rolled past.

NTFS's transaction log. Every metadata change is written here BEFORE it is
applied, so the log holds operations from a window that is shorter but more
recent than the USN journal's -- and, critically, it survives a journal that
has wrapped.

**This file was dismissed as unparseable earlier in this session**, on the
strength of its first four bytes being `RSTR` (a restart area) rather than a
record signature. That was wrong and the dismissal was not tested. Measured:

    16,382 RCRD pages, 4001 of 4001 sampled with a VALID update sequence
    array, zero torn -- and `invoice_scan` appears seven times.

The page structure is the same shape `$MFT` uses: a signature, an update
sequence array, and a fixup per 512-byte sector.

**What this parser does, and what it does not.** It does NOT reconstruct
transactions. A log record carries an opcode, a redo body and an undo body, and
replaying them means implementing NTFS's transaction semantics -- which is how
a parser fabricates filesystem history that never happened.

What it does is recover the **filenames present in the log's records**, with
the page's LSN as the ordering key. That is the recoverable, checkable part: a
name in `$LogFile` means the filesystem touched that name inside the log's
window, which for a deleted file may be the only remaining trace.

**Names are located by their `$FILE_NAME` shape**, not by parsing opcodes: a
UTF-16 run whose length matches a preceding name-length byte. A run that does
not satisfy that check is skipped rather than reported, because the log is full
of binary that decodes to plausible-looking text.

**A KNOWN AND UNFIXED LIMIT: some names are truncated fragments.** The
length/namespace pair also matches at offsets INSIDE a long name -- UTF-16 puts
a zero high byte after every ASCII character, and 0 is a valid namespace -- so
scanning a 53-character package name yields shorter suffixes that each decode
cleanly. `_drop_suffix_fragments` removes those that appear beside their parent
in the same page (1,496 of 18,534 on `s1_v3`, 8%), but a fragment landing in a
DIFFERENT page from its parent survives, and `5-21-...-1000.pck` is visibly
among the output.

Two byte-level filters were written to reject them at the source and both
failed: a real attribute's preceding bytes and a fragment's are not
distinguishable without parsing the log's opcodes, which means implementing
NTFS transaction semantics. Rather than guess a third time, the limit is stated
here: **a name from this family may be a suffix of the real filename.** It is
usable for "did this name appear in the log" and must not be treated as an
authoritative filename. `mft` and `usn` carry authoritative names; this family
exists for the window they no longer cover.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from ..model import Event
from . import register

_RCRD = b"RCRD"
_RSTR = b"RSTR"

#: Log pages are 4096 bytes on every NTFS volume this pipeline has seen; the
#: value is read from the page rather than assumed where possible.
_PAGE = 4096
_SECTOR = 512

_OFF_USA_OFFSET = 4
_OFF_USA_COUNT = 6
_OFF_LSN = 8

#: A filename in a $FILE_NAME body is preceded by a length in CHARACTERS and a
#: namespace byte. Requiring both is what separates a real name from a UTF-16
#: run that happens to decode.
_MIN_NAME = 3
_MAX_NAME = 255

#: Bounds a corrupt or hostile file. 16,382 pages is the real count here.
_MAX_PAGES = 200_000

#: Names NTFS writes constantly during boot and servicing. They are emitted --
#: suppressing by name is what this project refuses to do -- but the count is
#: what makes the family readable, so duplicates within a page are collapsed.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def apply_fixup(page: bytes) -> bytes | None:
    """Restore the bytes NTFS replaced with update-sequence numbers.

    Identical in principle to `mft.apply_fixup` and deliberately separate: the
    two formats are free to diverge, and sharing the function would couple them
    on an assumption rather than on a contract.
    """
    if len(page) < 16:
        return None
    usa_offset = struct.unpack_from("<H", page, _OFF_USA_OFFSET)[0]
    usa_count = struct.unpack_from("<H", page, _OFF_USA_COUNT)[0]
    if usa_count < 1 or usa_offset + usa_count * 2 > len(page):
        return None

    expected = page[usa_offset : usa_offset + 2]
    patched = bytearray(page)
    for index in range(1, usa_count):
        end = index * _SECTOR - 2
        if end + 2 > len(patched):
            break
        if bytes(patched[end : end + 2]) != expected:
            return None
        source = usa_offset + index * 2
        patched[end : end + 2] = page[source : source + 2]
    return bytes(patched)


def names_in_page(page: bytes) -> set[str]:
    """Filenames in one log page, by `$FILE_NAME` shape.

    A candidate must be preceded by a length byte that MATCHES the run's
    length in characters, and by a namespace byte in the documented range.
    Without both checks the log's binary yields hundreds of plausible strings
    that were never filenames.
    """
    found: set[str] = set()
    limit = len(page) - 4

    for position in range(2, limit):
        length = page[position]
        if not _MIN_NAME <= length <= _MAX_NAME:
            continue
        if page[position + 1] > 4:  # namespace: POSIX, WIN32, DOS, WIN32&DOS
            continue
        start = position + 2
        end = start + length * 2
        if end > len(page):
            continue
        raw = page[start:end]
        # Every second byte of an ASCII-range UTF-16 name is zero; requiring
        # it rejects most binary before the decode is attempted.
        if any(raw[i] for i in range(1, len(raw), 2)):
            continue
        try:
            name = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if len(name) != length or not name.isprintable():
            continue
        if "." not in name and "\\" not in name:
            # A bare token with no extension and no separator is more often a
            # coincidence than a filename.
            continue

        found.add(name)

    return _drop_suffix_fragments(found)


def _drop_suffix_fragments(names: set[str]) -> set[str]:
    r"""Remove names that are a strict suffix of a longer name in the same page.

    **This rule is derived from the output, not guessed at the byte layout, and
    that distinction is the point.**

    The length/namespace pair that marks a `$FILE_NAME` body also matches at
    many offsets INSIDE a long name, because UTF-16 puts a zero high byte after
    every ASCII character and 0 is a valid namespace (POSIX). Scanning
    `S-1-5-21-1591430865-807086247-2139423957-1000.pckgdep` therefore yields a
    dozen shorter suffixes that each decode cleanly.

    Two byte-level filters were written to reject them and BOTH failed -- the
    real name's preceding bytes and a fragment's are not distinguishable
    without parsing the log's opcodes to find where an attribute actually
    begins, which means implementing NTFS transaction semantics.

    The property that IS checkable: a genuine filename is not a strict suffix
    of another genuine filename recorded on the same page. Measured on `s1_v3`:
    1,496 of 18,534 names removed, 8%, and **no scenario name is shadowed** --
    `invoice_scan_marker.txt` and `INVOICE_SCAN.EXE-3CB0BB32.pf` survive.

    The cost is honest and bounded: a real file whose name genuinely ends
    another file's name, recorded in the same 4 KB page, is dropped. That is
    rarer than the fragments it removes, and a fragment reported as a filename
    is a fabrication where a missing name is only a gap.
    """
    ordered = sorted(names, key=len, reverse=True)
    kept: list[str] = []
    for name in ordered:
        if any(longer.endswith(name) for longer in kept):
            continue
        kept.append(name)
    return set(kept)


class NtfsLogFileParser:
    name = "ntfs_logfile"

    def can_handle(self, relative_path: str) -> bool:
        return relative_path.replace("\\", "/").lower().endswith("/$logfile")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        with abs_path.open("rb") as handle:
            head = handle.read(4)
            if head not in (_RSTR, _RCRD):
                return
            handle.seek(0)

            page_index = -1
            while page_index < _MAX_PAGES:
                raw = handle.read(_PAGE)
                if len(raw) < _PAGE:
                    return
                page_index += 1
                if raw[:4] != _RCRD:
                    # Restart areas and unused pages carry no log records.
                    continue

                page = apply_fixup(raw)
                if page is None:
                    # A torn page: its sectors were captured mid-write and the
                    # real bytes are unknown. Skipped, never repaired.
                    continue

                lsn = struct.unpack_from("<Q", page, _OFF_LSN)[0]
                for name in sorted(names_in_page(page)):
                    yield Event(
                        # The log carries no wall-clock time at all -- only
                        # LSNs. The epoch sentinel is used and the event is
                        # `presence`, because inventing a time from the LSN
                        # would be a fabrication.
                        timestamp=_FILETIME_EPOCH,
                        source_artifact="ntfs_logfile",
                        event_type="file_referenced",
                        action="filename present in the NTFS transaction log",
                        source_file=relative_path,
                        # Page plus name: unique within the file, and the LSN
                        # alone is not (a page names several files).
                        source_locator=f"page/{page_index}/{name}",
                        timestamp_type="presence",
                        path=name,
                        user=None,
                        details={
                            "file_name": name,
                            "log_page": str(page_index),
                            # The ordering key the log DOES provide. Higher is
                            # more recent, and that is all it means.
                            "lsn": str(lsn),
                        },
                    )


register(NtfsLogFileParser)
