"""Derived path fields for cross-artifact comparison (B-9).

CD-010 says `Event.path` is what the artifact recorded and is never rewritten.
Nothing here changes that. These are *additional* values placed in `details`, so
the original always remains alongside its derived form.

The problem this solves is measured, not assumed: 86 paths in the corpus differ
from another path **only by case**, because Amcache lowercases what it stores
while the EVTX channels preserve the case the OS used. Without a canonical form,
`C:\\Program Files\\7-Zip\\7z.exe` from a 4688 record and
`c:\\program files\\7-zip\\7z.exe` from Amcache are two different strings
describing one file, and no join between the two artifacts can succeed.

What is deliberately NOT done here:

* No environment variable is expanded to a guessed value. `%SystemRoot%` is
  almost always `C:\\Windows`, but "almost always" is not a fact the evidence
  records, and CD-010 forbids inventing one.
* No `\\Device\\HarddiskVolumeN` is resolved to a drive letter. That mapping
  needs the volume serial, and the artifacts that carry a device path do not
  carry the serial. Week 3's entity resolver owns that.
* No executable is extracted from a command line. See `looks_like_command_line`.
"""

from __future__ import annotations

import re

# A command line is a path followed by arguments. Distinguishing one from a path
# that merely contains spaces is the whole difficulty: "C:\Program Files\..." has
# spaces and is a path, while "cmd.exe /q /c del" has spaces and is not.
#
# Measured across the corpus, only two artifacts carry command lines at all --
# evtx.system (55 rows) and registry (40) -- and every one of them is either
# quoted or has an argument after an executable extension. The other 24,931
# rows with a path carry a bare path with no arguments, including all 2,542
# Amcache rows and all 19,020 evtx.security rows.
_ARG_AFTER_EXTENSION = re.compile(r"(?i)\.(?:exe|dll|sys|com|bat|cmd|ps1|scr|msi|vbs|js)\s+\S")

# %SystemRoot%, %windir%, %APPDATA% and so on.
_ENV_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_()]*%")

# \Device\HarddiskVolume2\... -- a kernel path with no drive letter.
_DEVICE_PATH = re.compile(r"(?i)^\\device\\harddiskvolume\d+\\")

# A path naming only a root: a drive letter with optional separators, or
# separators alone. Matched explicitly because trailing-character stripping
# cannot express it -- "C:\\".rstrip("\\\\/") is "C:", and stripping the
# colon then leaves "C", which is truthy and would pass.
_IS_ROOT_ONLY = re.compile(r"(?i)^(?:[a-z]:)?[\\\\/]*$")


def looks_like_command_line(value: str) -> bool:
    """True when the value carries arguments as well as a path.

    A command line cannot be canonicalised without first extracting the
    executable, and extraction is not solid enough to do here: an unquoted
    ``C:\\Program Files\\x\\y.exe -flag`` is genuinely ambiguous to a parser that
    cannot check the filesystem, which is exactly the ambiguity that makes
    unquoted service paths a known Windows privilege-escalation class.

    Emitting a wrong canonical path is worse than emitting none, because a wrong
    one silently joins two unrelated records. So these get no derived fields at
    all -- see CD-021 and D-032.
    """
    text = value.strip()
    if not text:
        return False
    if text.startswith('"'):
        return True
    return bool(_ARG_AFTER_EXTENSION.search(text))


def path_basename(value: str) -> str | None:
    """Trailing component of a path, preserving the case the artifact recorded.

    Returns None when the value has no separator at all: Prefetch stores a bare
    executable name, which IS its own basename, and emitting a derived field
    identical to `path` would imply a normalisation step that did not happen.
    """
    text = value.strip().rstrip("\\/")
    if not text:
        return None
    # Both separators appear: registry values are written by hand and are not
    # guaranteed to use the Windows one.
    cut = max(text.rfind("\\"), text.rfind("/"))
    if cut < 0:
        return None
    tail = text[cut + 1 :]
    return tail or None


def path_canonical(value: str) -> str | None:
    """Case-folded comparison form of a path, or None when one cannot be made.

    Lowercasing is the entire transformation. It is safe because Windows paths
    are case-insensitive, so two paths differing only by case denote the same
    object -- which is a fact about the filesystem, not a guess about intent.

    None is returned rather than a partial answer when the value is a command
    line, a device path, or carries an unexpanded environment variable. In each
    case a canonical form exists but this function cannot compute it without
    inventing something: the drive a device path refers to, or the directory a
    variable expands to. A consumer that gets None knows to fall back to
    `path`; a consumer given a wrong value has no way to know.
    """
    text = value.strip()
    if not text:
        return None
    if looks_like_command_line(text):
        return None
    if _DEVICE_PATH.match(text):
        return None
    if _ENV_VAR.search(text):
        return None
    # Separators are normalised to backslash so a hand-written registry value
    # using forward slashes compares equal to the same path from an EVTX record.
    return text.replace("/", "\\").lower()


def derive(value: str | None) -> dict[str, str]:
    """Derived fields for one path value, ready to merge into `details`.

    Returns an empty dict when nothing can be derived, so a caller can always
    `details.update(derive(path))` without a conditional.
    """
    if not value:
        return {}
    text = value.strip()
    if not text or looks_like_command_line(text):
        # A command line gets nothing at all. Its trailing token is an argument,
        # not a filename, so even a basename would be wrong (CD-021, D-032).
        return {}

    # A value naming only a root -- "C:\\", "\\\\", "\\" -- is a directory, not a file.
    # Every consumer of these fields is asking about a binary, so a root
    # entering the pipeline as a canonical path with no join key would be a
    # silent oddity rather than a useful value. Not present in this corpus
    # (checked: zero occurrences); a Startup folder entry or a directory
    # ImagePath would produce one.
    if _IS_ROOT_ONLY.match(text):
        return {}

    out: dict[str, str] = {}

    canonical = path_canonical(text)
    if canonical:
        out["path_canonical"] = canonical

    basename = path_basename(text)
    if basename:
        out["path_basename"] = basename

    # The cross-artifact join key CD-010 names. A value with no separator is
    # already a bare name -- Prefetch stores INVOICE_SCAN.EXE -- and is its own
    # comparison key, which is why this is not gated on path_basename. Without
    # it the one artifact that carries no path could never join to one that
    # does, and that join is the whole point of B-9.
    leaf = basename or (text if "\\" not in text and "/" not in text else None)
    if leaf:
        out["path_basename_canonical"] = leaf.lower()

    return out
