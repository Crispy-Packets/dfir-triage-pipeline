r"""`$Extend\$RmMetadata\$TxfLog\$T`: servicing operations left in flight.

**Dismissed earlier in this session as "TxF metadata, no per-file records".**
That was wrong and untested -- the file holds 147,668 printable characters of
Component Based Servicing XML naming Windows Update packages whose installation
had not completed when the machine was imaged.

Measured on `s1_v3`: **one pending transaction (KB5033052), 47 component
version changes, and 2 deployment installs.** Zero on `clean_b` and `clean_c`,
so the family discriminates rather than firing everywhere.

**It is XML fragments inside a transaction log, not an XML document**, and the
difference is what defeated three attempts to parse it properly:

* the declaration starts at byte 3, not 0 or 2;
* TxF interleaves its own framing into the character stream -- measured, **290
  pairs of `\x01\x00` injected mid-attribute**, splitting `ProcessorArchitecture`
  into `Proces` + `rArchitecture`;
* removing those still leaves a structurally unbalanced document, because the
  framing consumed characters the markup needed. `ET.fromstring` fails at line
  13 with everything on that line well-formed.

So **the document is never parsed as a tree.** Complete elements are recovered
by pattern instead: a `Transaction` with a full quoted `TransactionId`, a
`Change` with `Family`/`Old`/`New`, an `Install` or `Uninstall` with an
`Application`. An element whose quoting was damaged simply does not match and
is not reported -- which is the same bargain `ntfs_logfile` makes, and for the
same reason: a recovered fragment presented as a parsed record is a
fabrication, whereas a missing one is only a gap.

**Why a triage pipeline wants it.** A pending servicing transaction means the
machine was mid-update at collection, which bears on whether an inconsistent
file version is tampering or an interrupted patch, and on whether a reboot was
pending. The `Change` elements additionally give the **old and new version of
every component** the update touches -- version provenance no other family
here carries.

**No timestamps exist in the document.** Every event is `presence` with the
epoch sentinel: the transaction is pending now, and the file does not say when
it was begun.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from ..model import Event
from . import register

_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: A guard against a pathological file. The real one is 1 MB.
_MAX_BYTES = 64 * 1024 * 1024

#: Complete elements only -- each requires its closing quote, so a fragment
#: damaged by the interleaved framing does not match.
_TRANSACTION = re.compile(r'<Transaction\s+TransactionId="([^"]{4,400})"')
_CHANGE = re.compile(
    r'<Change\s+Family="([^"]{4,400})"[^>]*?Old="([^"]*)"[^>]*?New="([^"]*)"'
)
_DEPLOYMENT = re.compile(
    r'<(Install|Uninstall)\s+Application="([^"]{4,400})"'
)


def recoverable_text(blob: bytes) -> str:
    """The character stream with TxF's framing bytes removed.

    Control bytes other than tab, newline and carriage return are not legal in
    XML 1.0 and are not part of the document: measured, 290 `\\x01` and 290
    `\\x00` injected mid-attribute on `s1_v3`.
    """
    start = blob.find(b"<?xml")
    if start == -1:
        start = blob.find(b"<PendingTransaction")
        if start == -1:
            return ""
    stripped = bytes(b for b in blob[start:] if b >= 0x20 or b in (9, 10, 13))
    return stripped.decode("utf-8", errors="replace")


def _first_component(value: str) -> str:
    """The readable half of a CBS identity, before the assembly attributes."""
    return value.split(",", 1)[0].strip()


class TxfPendingParser:
    name = "txf_pending"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.replace("\\", "/").lower()
        return lowered.endswith("/$txflog/$t")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        try:
            if abs_path.stat().st_size > _MAX_BYTES:
                return
            blob = abs_path.read_bytes()
        except OSError:
            return

        text = recoverable_text(blob)
        if not text:
            return

        for index, match in enumerate(_TRANSACTION.finditer(text)):
            transaction_id = match.group(1)
            yield Event(
                timestamp=_EPOCH,
                source_artifact="txf_pending",
                event_type="servicing_pending",
                action="servicing transaction pending at collection time",
                source_file=relative_path,
                source_locator=f"transaction/{index}",
                # The id embeds the package name, which is the readable
                # identity. Recorded as written (CD-010).
                timestamp_type="presence",
                path=transaction_id,
                user=None,
                details={
                    "transaction_id": transaction_id,
                    "package": _first_component(transaction_id.split("/")[-1]),
                },
            )

        for index, match in enumerate(_DEPLOYMENT.finditer(text)):
            operation, application = match.group(1), match.group(2)
            yield Event(
                timestamp=_EPOCH,
                source_artifact="txf_pending",
                event_type="servicing_pending",
                action=f"deployment {operation.lower()} pending",
                source_file=relative_path,
                source_locator=f"deployment/{index}",
                timestamp_type="presence",
                path=_first_component(application),
                user=None,
                details={
                    "operation": operation.lower(),
                    "application": application,
                },
            )

        for index, match in enumerate(_CHANGE.finditer(text)):
            family, old, new = match.group(1), match.group(2), match.group(3)
            if not old or not new:
                continue
            yield Event(
                timestamp=_EPOCH,
                source_artifact="txf_pending",
                # A component's version moving from one value to another is a
                # different claim from a transaction being pending, so it gets
                # its own event_type rather than being folded in.
                event_type="component_version_change",
                action="component version change pending",
                source_file=relative_path,
                source_locator=f"change/{index}",
                timestamp_type="presence",
                path=_first_component(family),
                user=None,
                details={
                    "component": _first_component(family),
                    "version_old": old,
                    "version_new": new,
                },
            )


register(TxfPendingParser)
