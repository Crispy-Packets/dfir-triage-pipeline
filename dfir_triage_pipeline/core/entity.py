"""Entity resolution: the derived keys a correlation rule may join on.

CD-010 settles the principle -- entity identity is DERIVED, never stored. `path`
stays exactly what the artifact recorded, and every key computed here goes into
a Finding, never back onto an Event.

Version 1.3.0 of `rules/schema.md` defines exactly two joinable keys:

    entity.exe_name   case-folded basename of the executable image
    entity.user       normalised principal, system contexts excluded

`entity.host` is defined but deliberately not joinable: `clean_b` carries both
`WIN-BQVKLIBL3LA` and `windows10` for one machine, before and after a rename, so
a join on host would split one collection in two.

Most of the work is already done by `paths.derive` (B-9), which puts
`path_basename_canonical` into `details` for every value it can canonicalise.
This module adds the one case that function deliberately declines: a command
line, where the executable has to be extracted before a basename means anything.
That is the extraction CD-021 assigns here.
"""

from __future__ import annotations

import re
from typing import Any

from .. import paths

# Extensions that end an image token. Matches paths.py's set so the two modules
# cannot drift on what counts as an executable.
_IMAGE_EXTENSIONS = ("exe", "com", "sys", "dll", "bat", "cmd", "ps1", "scr", "msi", "vbs", "js")

# The FIRST extension at a token boundary, not the last. See _image_token.
_UNQUOTED_IMAGE = re.compile(
    r"(?i)^(.*?\.(?:" + "|".join(_IMAGE_EXTENSIONS) + r"))(?=\s|$)"
)

# "-" is a value the log wrote; "" is a field the parser found missing (CD-022).
# Neither is a principal, and they are not the same thing.
ABSENT_USER_FORMS = frozenset({"", "-"})

# Well-known non-principals. A correlation joined on `system` correlates the
# whole machine to itself, which is not a finding.
SYSTEM_CONTEXTS = frozenset(
    {
        "system",
        "localsystem",
        "local service",
        "network service",
        "nt authority\\system",
        "nt authority\\localservice",
        "nt authority\\local service",
        "nt authority\\networkservice",
        "nt authority\\network service",
        "iusr",
        "anonymous logon",
    }
)

# Domain-qualified and bare spellings of one well-known principal fold together.
_USER_FOLD = {
    "nt authority\\system": "system",
    "nt authority\\localservice": "local service",
    "nt authority\\local service": "local service",
    "nt authority\\networkservice": "network service",
    "nt authority\\network service": "network service",
    "localsystem": "system",
}

_MACHINE_ACCOUNT = re.compile(r"(?i)^(dwm|umfd)-\d+$")


def _image_token(text: str) -> str | None:
    """The executable portion of a command line, or None when it is ambiguous.

    Two shapes, and nothing else is guessed:

    1. Quoted -- the image is the text between the opening quote and the next
       one. This covers 27 of the 55 measured `service_install` rows.
    2. Unquoted -- the image is the SHORTEST leading prefix ending in an
       executable extension at a token boundary.

    Shortest, not longest, and the difference is not academic::

        C:\\Program Files\\App\\run.exe -config C:\\other\\thing.exe

    The longest such prefix runs to `thing.exe`, which is an argument. The
    shortest is `run.exe`, which is the image. An earlier draft of the schema
    said longest; that was wrong and 1.3.0 corrects it.

    Genuinely ambiguous unquoted paths with spaces -- the Windows
    unquoted-service-path class -- resolve to whichever candidate ends first,
    which is what the Service Control Manager itself would try first.
    """
    text = text.strip()
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 1:
            return text[1:end]
        return None
    match = _UNQUOTED_IMAGE.match(text)
    if match:
        return match.group(1)
    return None


_HAS_IMAGE_EXTENSION = re.compile(r"(?i)\.(?:" + "|".join(_IMAGE_EXTENSIONS) + r")$")


def _basename(text: str) -> str | None:
    """Trailing component, or None when the result is not a file name.

    The guard is not cosmetic. A registry autorun value is free text and a
    service ImagePath is a command line; either can hold something that is not
    a path at all. Without this, `run this thing please` becomes an
    `entity.exe_name` of `run this thing please`, and two unrelated events
    carrying the same prose would join on it. A name may contain spaces only if
    it ends in an image extension -- `"My App.exe"` is a filename, a sentence is
    not. Found by a negative test, not by reading.
    """
    cut = max(text.rfind("\\"), text.rfind("/"))
    tail = text[cut + 1 :] if cut >= 0 else text
    tail = tail.strip().strip('"')
    if not tail:
        return None
    if any(ch.isspace() for ch in tail) and not _HAS_IMAGE_EXTENSION.search(tail):
        return None
    return tail


def exe_name(event: Any) -> str | None:
    """`entity.exe_name`, or None when it cannot be derived without guessing.

    Order matters. The parser-derived key is preferred because it is declared,
    tested and emitted by every artifact that carries a plain path; the command
    line branch exists only for the values `paths.derive` refuses.
    """
    details = getattr(event, "details", None) or {}

    derived = details.get("path_basename_canonical")
    if isinstance(derived, str) and derived.strip():
        return derived.strip().lower()

    raw = getattr(event, "path", None)
    if not isinstance(raw, str) or not raw.strip():
        return None

    if paths.looks_like_command_line(raw):
        token = _image_token(raw)
        if token is None:
            # CD-021: emitting no key is a NOT-PARSED outcome Day 5 can count.
            # Emitting a wrong one is a fabricated join Day 5 cannot see.
            return None
        base = _basename(token)
        return base.lower() if base else None

    base = _basename(raw.strip())
    return base.lower() if base else None


def user_key(event: Any) -> str | None:
    """`entity.user`, or None when the value is not a joinable principal.

    None is returned for an absent form, for a system context and for a machine
    pseudo-account. CD-022 keeps `Event.user` exactly as recorded; this is the
    Week 3 normalisation that clause defers to, and it never writes back.
    """
    raw = getattr(event, "user", None)
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if text.lower() in ABSENT_USER_FORMS:
        return None
    folded = _USER_FOLD.get(text.lower(), text.lower())
    if folded in SYSTEM_CONTEXTS:
        return None
    if _MACHINE_ACCOUNT.match(folded):
        return None
    if folded.endswith("$"):
        # A computer account, not a person.
        return None
    return folded


def host_key(event: Any) -> str | None:
    """`entity.host`. Defined for reporting; not joinable (schema 4.5)."""
    raw = getattr(event, "host", None)
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip().lower()


#: Addresses that name no remote source: the log's own "not recorded" marker,
#: loopback, the unspecified address, and the RDP channel's console marker. A
#: console logon has no source address, and an absent key never joins.
_NO_SOURCE = frozenset({"", "-", "::1", "127.0.0.1", "0.0.0.0", "local", "::"})


def src_ip_key(event: Any) -> str | None:
    """`entity.src_ip`: the network address a logon came FROM.

    Read from `details.IpAddress` on Security 4624/4625 and `details.Address` on
    the RDP session channel (EID 21/25). None for a local or console logon.

    **Join-only.** It is resolvable by name for `join.on` and `aggregate.group_by`
    but is deliberately absent from `_RESOLVERS`, so `keys_for()` never adds it
    to an atomic finding's entity keys and it never becomes a ranked entity
    (entity_score scores only SCORED_ENTITY_KINDS). It exists because a
    brute-force chain joined on the account alone pairs the attacker's failures
    with the legitimate owner's success from elsewhere -- measured on
    collection_srv22, where 100,003 failures from 36.133.110.87 overlap the real
    administrator's logons from 195.21.1.97.
    """
    details = getattr(event, "details", None) or {}
    raw = details.get("IpAddress") or details.get("Address")
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    if value in _NO_SOURCE:
        return None
    return value


_RESOLVERS = {
    "entity.exe_name": exe_name,
    "entity.user": user_key,
    "entity.host": host_key,
}

#: Resolvable by name for joins and grouping, never emitted by keys_for().
_JOIN_ONLY_RESOLVERS = {
    "entity.src_ip": src_ip_key,
}

JOINABLE = frozenset({"entity.exe_name", "entity.user", "entity.src_ip"})


def resolve(event: Any, key: str) -> str | None:
    """One entity key by name. Unknown names raise rather than return None."""
    resolver = _RESOLVERS.get(key) or _JOIN_ONLY_RESOLVERS.get(key)
    if resolver is None:
        defined = sorted(_RESOLVERS) + sorted(_JOIN_ONLY_RESOLVERS)
        raise KeyError(f"unknown entity key {key!r}; defined: {defined}")
    return resolver(event)


def keys_for(event: Any) -> dict[str, str]:
    """Every derivable entity key for one event. Absent keys are omitted.

    Omitted, not empty-stringed: an absent key never joins, not to another
    absent key and not to "" (CONTRACT-RULES section 3).
    """
    out: dict[str, str] = {}
    for name, resolver in _RESOLVERS.items():
        value = resolver(event)
        if value:
            out[name] = value
    return out
