from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..model import Event


@runtime_checkable
class ArtifactParser(Protocol):
    """Contract every artifact parser implements."""

    name: str

    def can_handle(self, relative_path: str) -> bool:
        """Decide from the collection-relative POSIX path alone. Must not open the file."""
        ...

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        """Yield events. Iterator, not list: Week 2's MFT will not fit in memory."""
        ...
