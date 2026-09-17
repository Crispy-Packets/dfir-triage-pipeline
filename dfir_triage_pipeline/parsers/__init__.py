from __future__ import annotations

from .base import ArtifactParser

_REGISTRY: list[ArtifactParser] = []


def register(cls):
    """Class decorator: instantiate once and add to the registry."""
    _REGISTRY.append(cls())
    return cls


def registered_parsers() -> tuple[ArtifactParser, ...]:
    return tuple(_REGISTRY)


def find_parser(relative_path: str) -> ArtifactParser | None:
    for parser in _REGISTRY:
        if parser.can_handle(relative_path):
            return parser
    return None


__all__ = ["ArtifactParser", "register", "registered_parsers", "find_parser"]

# Parser modules are imported at the bottom so their @register decorators run
# without a circular import. Both parsers register here; ruff's I001 sees two
# consecutive bottom-of-file imports as an unsorted block, so the first carries
# ,I001 in addition to E402/F401 (D-014).
from . import evtx_windows  # noqa: E402,F401,I001
from . import prefetch  # noqa: E402,F401
from . import registry  # noqa: E402,F401
from . import browser  # noqa: E402,F401
from . import amcache  # noqa: E402,F401
from . import system_hive  # noqa: E402,F401
from . import sam_hive  # noqa: E402,F401
from . import srum  # noqa: E402,F401
from . import scheduled_tasks  # noqa: E402,F401
from . import lnk  # noqa: E402,F401
from . import recycle_bin  # noqa: E402,F401
from . import timeline  # noqa: E402,F401
from . import ps_history  # noqa: E402,F401
from . import jumplist  # noqa: E402,F401
from . import shellbags  # noqa: E402,F401
from . import usn_journal  # noqa: E402,F401
