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
)


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


def build(events: Sequence[Event], rarity: dict[str, int] | None = None) -> FeatureTable:
    """Compute the feature table for `events`.

    `rarity` is the training profile from `build_rarity_index`. When omitted,
    it is built from `events` themselves -- correct for fitting the model on a
    baseline, wrong for scoring, which is why scoring code must pass it
    explicitly.
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
            )
        )

    return FeatureTable(names=FEATURE_NAMES, rows=rows, events=ordered)
