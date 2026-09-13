"""Behavioural features for the anomaly model (B-10, B-11).

The governing constraint is that this corpus makes leakage very easy. Three
collections were produced by one operator on one machine over about nine days,
so almost every raw field encodes *which collection a row came from* rather than
what happened in it. A model given such a field separates the collections
perfectly, validates beautifully, and detects nothing.

Everything excluded here was excluded because it was measured, not because it
looked risky. The measurements are recorded against each exclusion in
`EXCLUDED_FIELDS`, and `docs/feature-decisions.md` carries them in full.

The features that remain describe *behaviour that would still make sense on a
different machine*: how often a binary has run, how rare it is, how much is
happening around it. None of them can be computed from the collection label.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .model import Event

# Fields that must never be fed to the model as values, with the measurement
# that disqualified each. Percentages are share-of-rows in clean_b vs s1_v2.
#
# "Single-field accuracy" below is the accuracy of the best possible rule that
# looks at that field alone, against a 79.8% baseline from always guessing the
# majority class. Anything meaningfully above 79.8% is separating collections.
EXCLUDED_FIELDS: dict[str, str] = {
    "path": (
        "139 canonical paths appear only in s1_v2, most of them the VirtualBox "
        "Guest Additions install absent from both baselines (D-026). A model "
        "given raw path learns 'Guest Additions present, therefore malicious'. "
        "Single-field accuracy 81.3%."
    ),
    "source_file": (
        "Names the collection layout directly: 335 distinct files in clean_b "
        "against 209 in s1_v2. Single-field accuracy 83.0%, the highest of the "
        "raw string fields."
    ),
    "source_artifact": (
        "The artifact mix differs enormously between collections -- "
        "evtx.security is 77.0% of clean_b and 10.5% of s1_v2, while "
        "evtx.powershell is 7.4% against 37.0%. That is a property of what was "
        "collected, not of what happened. Single-field accuracy 81.8%."
    ),
    "event_type": (
        "Moves with source_artifact for the same reason and to the same degree "
        "-- process_exec is 79.3% of clean_b against 34.0% of s1_v2. "
        "Single-field accuracy 81.8%. Not in the plan's original exclusion "
        "list; added after measurement."
    ),
    "user": (
        "88.9% of s1_v2 rows carry no user against 22.8% of clean_b, because "
        "Prefetch and Amcache record no user and s1_v2 is proportionally far "
        "more of both. The emptiness is an artifact-mix effect, not a "
        "behavioural one."
    ),
    "timestamp_type": (
        "A restatement of the artifact mix: 49% of s1_v2 rows are presence or "
        "last_run against 18% of clean_b. Added after measurement."
    ),
    "hour_of_day": (
        "The worst leaker measured, at 86.0% single-field accuracy. Hours "
        "21-23 hold 33% of s1_v2 rows and about 1% of baseline rows -- not "
        "because intrusions happen at night, but because the operator ran the "
        "scenario in the evening. This is session identity. The plan proposed "
        "it as a feature; it is excluded on evidence."
    ),
    "is_weekend": (
        "84.2% single-field accuracy, and the corpus spans only 9-10 distinct "
        "dates per collection, so weekday-ness reflects which days the lab was "
        "run rather than any behavioural rhythm."
    ),
}

# Order is fixed and part of the contract: a stored model scores incoming rows
# by position, so inserting a column in the middle silently reinterprets every
# feature after it.
FEATURE_NAMES: tuple[str, ...] = (
    "run_count",
    "run_count_is_known",
    "executable_rarity",
    "executable_is_unseen",
    "events_in_same_hour",
    "distinct_executables_in_same_hour",
    "seconds_since_previous_run_of_same_executable",
    "previous_run_is_known",
    "path_depth",
    "path_is_user_writable",
    # Appended 2026-09-13, not inserted. Order is contractual: a stored model
    # scores by column position, so inserting mid-list silently reinterprets
    # every feature after it.
    "download_size_log10",
    "download_size_is_known",
    "mime_type_is_executable",
    # Appended 2026-09-13 alongside the per-family split. Both describe the
    # filename's shape rather than its text, so neither carries a corpus-specific
    # string; both measured 58.1% single-field accuracy against a 58.1%
    # baseline separating clean_c from s1_v3.
    "filename_length",
    "filename_entropy",
)


#: Which features each artifact family can actually populate.
#:
#: Derived from what each artifact records, argued in full in
#: `docs/per-family-features.md` and committed there BEFORE this code, because
#: the 2026-09-13 ablation happens to favour the same change and the ordering
#: is what shows the ablation was not the reason.
#:
#: The principle: a browser download has never run, so `run_count` and the
#: interval features are *undefined* for it rather than missing, and every
#: download lands in `Downloads\` so `path_depth` is constant. A Prefetch
#: record carries no byte count or MIME type. A column that is identical across
#: every row in a family cannot separate anything, and Isolation Forest picks
#: features uniformly at random -- so each such column spends split attempts
#: that partition nothing and dilutes the ones that carry signal.
#:
#: This is the second half of the argument that produced `PerFamilyModel`:
#: separate forests stopped families being compared against each other, but
#: each forest was still handed columns its family cannot populate.
_SHARED = (
    "executable_rarity",
    "executable_is_unseen",
    "events_in_same_hour",
    "distinct_executables_in_same_hour",
)

#: Families that record repeated observations of a path: intervals and path
#: shape are defined, byte counts and MIME types are not.
_PATH_AND_INTERVAL = (
    "seconds_since_previous_run_of_same_executable",
    "previous_run_is_known",
    "path_depth",
    "path_is_user_writable",
)

FAMILY_FEATURES: dict[str, tuple[str, ...]] = {
    # The only family with a run count, and the only one for which the
    # download columns are undefined.
    "prefetch": _SHARED + ("run_count", "run_count_is_known") + _PATH_AND_INTERVAL,
    # Downloads: size and content type are defined; execution is not, and
    # path_depth is constant because everything lands in Downloads\.
    "browser": _SHARED
    + (
        "download_size_log10",
        "download_size_is_known",
        "mime_type_is_executable",
        "filename_length",
        "filename_entropy",
    ),
    # Inventory and log records: a path and a time, no run count, no bytes.
    "amcache": _SHARED + _PATH_AND_INTERVAL,
    "registry": _SHARED + _PATH_AND_INTERVAL,
    "evtx.security": _SHARED + _PATH_AND_INTERVAL,
    "evtx.system": _SHARED + _PATH_AND_INTERVAL,
    "evtx.powershell": _SHARED + _PATH_AND_INTERVAL,
}


def features_for(family: str | None) -> tuple[str, ...]:
    """Feature names for `family`; the full set when it is unknown.

    An unrecognised family falls back to every feature rather than to a guess.
    A new parser then scores with redundant columns -- measurably worse, per
    `docs/per-family-features.md` -- rather than silently dropping a column its
    artifact does populate, which would be wrong rather than merely diluted.
    """
    if family is None:
        return FEATURE_NAMES
    return FAMILY_FEATURES.get(family, FEATURE_NAMES)


@dataclass(frozen=True, slots=True)
class FeatureTable:
    """Feature vectors and the events they were computed from, in step.

    `events[i]` produced `rows[i]`. Keeping them together is what lets a score
    be traced back to the evidence that caused it, which CD-003 and CD-004
    require of anything this pipeline reports.
    """

    names: tuple[str, ...]
    rows: list[tuple[float, ...]]
    events: list[Event]

    def __len__(self) -> int:
        return len(self.rows)


# Directories an unprivileged user can write to. Used as a *shape* feature --
# "this ran from somewhere writable" -- never as the path itself, so it carries
# no collection-specific string.
_USER_WRITABLE = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\public\\",
)


def _is_user_writable(canonical: str | None) -> bool:
    """True when the path sits under a user-writable directory.

    Compared against path_canonical, which is already lowercased, so no
    case handling is needed. This is a shape feature: it carries no
    collection-specific string, only the fact that the location is
    writable by an unprivileged user.
    """
    if not canonical:
        return False
    return any(marker in canonical for marker in _USER_WRITABLE)


#: MIME types a Windows executable is served as. A closed set, matched against
#: the recorded value -- never the raw string as a feature, which would be a
#: category tied to this corpus in the way `path` and `source_file` are.
_EXECUTABLE_MIME = frozenset(
    {
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
        "application/x-ms-installer",
        "application/x-msi",
    }
)


def _download_size(event: Event) -> tuple[float, float]:
    """Log-scaled download size, and whether it was recorded at all.

    Returns (log10(bytes + 1), is_known). Log-scaled because the measured range
    on this corpus spans 153 bytes to 1.07 GB -- seven orders of magnitude. On a
    linear scale one 1 GB download dominates every split the forest can make and
    the difference between 4 KB and 400 KB disappears.

    A missing size is flagged rather than imputed, matching `run_count_is_known`:
    substituting a mean would invent a measurement the artifact never recorded,
    and the model cannot tell an imputed value from a real one.
    """
    raw = event.details.get("bytes")
    if raw is None:
        return 0.0, 0.0
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0.0, 0.0
    if value < 0:
        return 0.0, 0.0
    return math.log10(value + 1), 1.0


def _mime_is_executable(event: Event) -> float:
    """Whether the download was served as a Windows executable.

    A shape feature, like `path_is_user_writable`: it carries no
    collection-specific string, only the fact that the server declared an
    executable content type. Measured at 58.1% single-field accuracy separating
    clean_c from s1_v3, against a 58.1% baseline -- it carries no collection
    identity at all.
    """
    mime = (event.details.get("mime_type") or "").lower().strip()
    return 1.0 if mime in _EXECUTABLE_MIME else 0.0


def _filename_shape(event: Event) -> tuple[float, float]:
    """Length and Shannon entropy of the recorded basename.

    Shape, not text. The characters themselves never enter the model -- only how
    many there are and how evenly distributed they are -- so neither value
    carries a string tied to this corpus, in the way `path` and `source_file` do.

    Entropy separates a readable name from a machine-generated one: `setup.exe`
    scores low, a 32-character hash scores high. Length separates a short binary
    name from a book title carrying author and edition metadata.

    Both measured 58.1% single-field accuracy separating clean_c from s1_v3,
    against a 58.1% majority-class baseline -- no collection identity at all.
    """
    name = (event.details.get("path_basename") or "").lower()
    if not name:
        return 0.0, 0.0
    counts = Counter(name)
    n = len(name)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return float(n), entropy


def _executable(event: Event) -> str | None:
    """The binary this row is about, as a comparison key.

    Uses the derived join key from B-9 rather than the raw path, so a binary
    recorded by Amcache in lowercase matches the same binary recorded by a 4688
    in the OS casing.
    """
    return event.details.get("path_basename_canonical")


def build_rarity_index(events: Iterable[Event]) -> dict[str, int]:
    """Count how often each executable appears. This is the training profile.

    Rarity must be computed on the *training* collection and then applied
    unchanged to whatever is scored. Recomputing it per collection would make
    every binary averagely-rare within its own collection, which is precisely
    the property that would hide a binary that appears nowhere else.
    """
    counts: Counter[str] = Counter()
    for event in events:
        name = _executable(event)
        if name:
            counts[name] += 1
    return dict(counts)


def build(
    events: Sequence[Event],
    rarity: dict[str, int] | None = None,
    family: str | None = None,
) -> FeatureTable:
    """Compute the feature table for `events`.

    `rarity` is the training profile from `build_rarity_index`. When omitted,
    it is built from `events` themselves -- correct for fitting the model on a
    baseline, wrong for scoring, which is why scoring code must pass it
    explicitly.

    `family` restricts the columns to those its artifact can populate, per
    `FAMILY_FEATURES`. Omitting it returns all thirteen, which is what the
    ablation tool and the older tests expect; `PerFamilyModel` passes it.
    Every value is still computed -- the selection happens at the end -- so a
    column's presence changes nothing about how the others are calculated.
    """
    ordered = sorted(events, key=lambda e: e.timestamp)
    if rarity is None:
        rarity = build_rarity_index(ordered)
    total_training = sum(rarity.values()) or 1

    # Per-hour aggregates. The hour bucket is used only to group nearby events;
    # the hour itself is never a feature, because it leaks (see EXCLUDED_FIELDS).
    per_hour: Counter = Counter()
    execs_per_hour: defaultdict[object, set[str]] = defaultdict(set)
    for event in ordered:
        bucket = event.timestamp.replace(minute=0, second=0, microsecond=0)
        per_hour[bucket] += 1
        name = _executable(event)
        if name:
            execs_per_hour[bucket].add(name)

    last_seen: dict[str, object] = {}
    rows: list[tuple[float, ...]] = []

    for event in ordered:
        bucket = event.timestamp.replace(minute=0, second=0, microsecond=0)
        name = _executable(event)
        canonical = event.details.get("path_canonical")

        size_log10, size_known = _download_size(event)
        name_len, name_entropy = _filename_shape(event)

        raw_count = event.details.get("run_count")
        run_count = float(raw_count) if raw_count is not None else 0.0
        # A missing run count is flagged rather than imputed. Substituting a
        # mean would invent an execution history the artifact never recorded,
        # and the model cannot tell an imputed value from a measured one.
        run_count_known = 1.0 if raw_count is not None else 0.0

        seen = rarity.get(name, 0) if name else 0
        # Frequency, not the name. A name is a string tied to this corpus; a
        # frequency is a property that transfers to another estate.
        rarity_score = seen / total_training
        unseen = 1.0 if (name and seen == 0) else 0.0

        if name and name in last_seen:
            gap = (event.timestamp - last_seen[name]).total_seconds()
            gap_known = 1.0
        else:
            gap, gap_known = 0.0, 0.0
        if name:
            last_seen[name] = event.timestamp

        rows.append(
            (
                run_count,
                run_count_known,
                rarity_score,
                unseen,
                float(per_hour[bucket]),
                float(len(execs_per_hour[bucket])),
                gap,
                gap_known,
                float(canonical.count("\\")) if canonical else 0.0,
                1.0 if _is_user_writable(canonical) else 0.0,
                size_log10,
                size_known,
                _mime_is_executable(event),
                name_len,
                name_entropy,
            )
        )

    names = features_for(family)
    if names != FEATURE_NAMES:
        # Select by name rather than by index. Indexing would silently produce
        # the wrong columns the moment FEATURE_NAMES gains an entry, and the
        # forest scores by position -- every column after the insertion would
        # be reinterpreted as its neighbour without anything failing.
        keep = [FEATURE_NAMES.index(n) for n in names]
        rows = [tuple(row[i] for i in keep) for row in rows]

    return FeatureTable(names=names, rows=rows, events=ordered)
