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
