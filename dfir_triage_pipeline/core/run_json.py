"""`run.json` -- the canonical run artifact, and the exports derived from it.

Everything a consumer needs is here: the run's provenance, the findings with
their evidence, the scored entities, the anomaly percentiles, and a windowed
slice of the timeline around each finding. `findings.csv` and `anomalies.csv`
are generated FROM this file rather than written independently, so the CSVs and
the report cannot disagree about what a run produced.

Four properties the format has to hold, each for a stated reason.

**Deterministic bytes.** Keys are sorted, floats are formatted to a fixed
precision, and no timestamp of the run itself appears in the document. Two runs
over one collection must produce byte-identical output or the SHA-256 manifest
that covers it means nothing.

**The anomaly percentile travels as `anomaly_context`, never as a verdict.**
The acceptance gate requires the ML layer be labelled as anomaly prioritisation
rather than a malicious verdict, so the field is named for what it is, carries
`is_verdict: false` explicitly, and sits beside a finding rather than inside its
severity. `is_outlier` is deliberately NOT exported: it is a threshold artifact
that reads as a judgement, and the percentile is the reportable form.

**Timeline slices, not the whole timeline.** A finding carries the events within
a window around it. Shipping all 2,304 rows into every report would make a
self-contained HTML artifact unusable, and the question an analyst actually asks
is "what else happened around this?".

**Nothing here decides anything.** This module serialises what the rule engine
and the anomaly layer already produced. It applies no threshold, drops no
finding and reorders nothing on its own judgement.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left, bisect_right
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

from .entity_score import ScoredEntity
from .findings import Finding

#: Version of the run.json structure itself, independent of the rule schema.
#: A consumer that reads this file needs to know when its shape changes.
RUN_JSON_VERSION = "1.0.0"

#: Events either side of a finding's first timestamp. Five minutes because the
#: scenario's own tightest interval is 2m32s, so a window that narrow would cut
#: a chain in half; wide enough to carry context, narrow enough that a busy
#: minute does not dominate the file.
DEFAULT_WINDOW = timedelta(minutes=5)

#: Hard cap per finding. One busy window on a real estate could otherwise carry
#: thousands of rows into the report. When it bites, the slice says so rather
#: than silently truncating -- a shortened list that does not announce itself is
#: indistinguishable from a quiet period.
MAX_SLICE_EVENTS = 40


def _iso(dt: Any) -> str:
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _event_json(event: Any) -> dict[str, Any]:
    """One timeline row, with the provenance that makes it checkable."""
    return {
        "event_id": event.event_id,
        "timestamp_utc": _iso(event.timestamp),
        "timestamp_type": event.timestamp_type,
        "source_artifact": event.source_artifact,
        "event_type": event.event_type,
        "action": event.action,
        "user": event.user or "",
        "path": event.path or "",
        "source_file": event.source_file,
        "source_locator": event.source_locator,
    }


def _slice_around(
    events: Sequence[Any],
    timestamps: Sequence[Any],
    centre: Any,
    window: timedelta,
) -> dict[str, Any]:
    """Events within `window` of `centre`, from a time-sorted list.

    `timestamps` is the parallel list of `events`' timestamps, built once by the
    caller: bisect needs a sortable sequence and rebuilding it per finding would
    make this quadratic in the number of findings.
    """
    lo = bisect_left(timestamps, centre - window)
    hi = bisect_right(timestamps, centre + window)
    total = hi - lo
    window_events = events[lo:hi]

    truncated = total > MAX_SLICE_EVENTS
    if truncated:
        # Keep the events NEAREST the centre rather than the first N. The first
        # N would be the oldest, which is the half least likely to explain the
        # finding.
        window_events = sorted(
            window_events, key=lambda e: abs(e.timestamp - centre)
        )[:MAX_SLICE_EVENTS]
        window_events = sorted(window_events, key=lambda e: e.timestamp)

    return {
        "window_seconds": int(window.total_seconds()),
        "events_in_window": total,
        "truncated": truncated,
        "events": [_event_json(e) for e in window_events],
    }


def _anomaly_index(scores: Sequence[Any]) -> dict[str, dict[str, Any]]:
    """Best percentile per entity, keyed by `path_basename_canonical`.

    Best rather than mean: an entity is as unusual as its most unusual row, and
    averaging would let a run of ordinary rows bury one anomalous one.
    """
    from .. import evaluation

    index: dict[str, dict[str, Any]] = {}
    for scored in scores:
        entity = evaluation.entity_of(scored)
        pct = scored.percentile_in_family
        if entity is None or pct is None:
            continue
        current = index.get(entity)
        if current is None or pct < current["percentile_in_family"]:
            index[entity] = {
                "entity": entity,
                "family": scored.family,
                "percentile_in_family": round(pct, 4),
            }
    return index


def _finding_json(
    finding: Finding,
    anomalies: dict[str, dict[str, Any]],
    timeline: Sequence[Any],
    timestamps: Sequence[Any],
    window: timedelta,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "title": finding.title,
        "severity": finding.severity,
        "weight": finding.weight,
        "attack_technique": finding.attack_technique,
        "first_timestamp_utc": _iso(finding.first_timestamp),
        "time_claim": finding.time_claim,
        "window_observed_seconds": (
            None
            if finding.window_observed_seconds is None
            else round(finding.window_observed_seconds, 6)
        ),
        "entity_keys": [{"key": k, "value": v} for k, v in sorted(finding.entity_keys)],
        "reason": finding.reason,
        "notes": list(finding.notes),
        # Every matched event names its source file and locator. `Finding`
        # cannot be constructed without them, and this is where that guarantee
        # becomes visible to a consumer.
        "matched": [
            {
                "event_id": m.event_id,
                "timestamp_utc": _iso(m.timestamp),
                "timestamp_type": m.timestamp_type,
                "source_artifact": m.source_artifact,
                "event_type": m.event_type,
                "source_file": m.source_file,
                "source_locator": m.source_locator,
                "step": m.step,
            }
            for m in finding.matched
        ],
        "timeline_slice": _slice_around(
            timeline, timestamps, finding.first_timestamp, window
        ),
    }

    # The ML layer's contribution, attached only when the anomaly layer scored
    # this finding's entity. Absent rather than null when it did not, so a
    # consumer cannot mistake "not scored" for "scored as ordinary".
    contexts = []
    for key, value in sorted(finding.entity_keys):
        if key == "entity.exe_name" and value in anomalies:
            contexts.append(dict(anomalies[value], joined_on=key))
    if contexts:
        out["anomaly_context"] = {
            "is_verdict": False,
            "meaning": (
                "Rank within this artifact family, 0 most unusual. A statement "
                "about how a row compares with others of its kind, not about "
                "whether it is malicious."
            ),
            "entities": contexts,
        }
    return out


def build(
    *,
    collection: Path,
    events: Sequence[Any],
    findings: Sequence[Finding],
    entities: Sequence[ScoredEntity],
    scores: Sequence[Any] = (),
    ingest_stats: Any = None,
    engine_stats: Any = None,
    unscored_families: Any = None,
    window: timedelta = DEFAULT_WINDOW,
) -> dict[str, Any]:
    """Assemble the canonical run document.

    `scores` is optional: a run with `--no-rules`, or one where the anomaly
    layer was not used, produces a valid document without it.
    """
    timeline = list(events)
    timestamps = [e.timestamp for e in timeline]
    anomalies = _anomaly_index(scores)

    doc: dict[str, Any] = {
        "run_json_version": RUN_JSON_VERSION,
        "collection": {
            "path": str(collection),
            "name": collection.name,
        },
        "events": {
            "total": len(timeline),
            "first_timestamp_utc": _iso(timeline[0].timestamp) if timeline else None,
            "last_timestamp_utc": _iso(timeline[-1].timestamp) if timeline else None,
        },
        "findings": [
            _finding_json(f, anomalies, timeline, timestamps, window) for f in findings
        ],
        "entities": [
            {
                "key": e.key,
                "value": e.value,
                "score": e.score,
                "raw_sum": e.raw_sum,
                "severity": e.severity,
                "rule_ids": list(e.rule_ids),
                "techniques": list(e.techniques),
                "finding_count": e.finding_count,
                "finding_ids": [f.finding_id for f in e.findings],
            }
            for e in entities
        ],
        # The prioritisation panel's data, kept SEPARATE from findings. The
        # report shows them in different panels for the same reason: a ranking
        # and a verdict are different claims and must not share a column.
        "anomalies": {
            "is_verdict": False,
            "meaning": (
                "Anomaly prioritisation, not a malicious verdict. A percentile "
                "is a rank within one artifact family: 0 is the most unusual "
                "row of its kind in this collection."
            ),
            "scored_entities": sorted(
                anomalies.values(), key=lambda a: (a["percentile_in_family"], a["entity"])
            ),
        },
    }

    if ingest_stats is not None:
        doc["ingest"] = {
            "files_seen": ingest_stats.files_seen,
            "files_handled": ingest_stats.files_handled,
            "files_skipped": ingest_stats.files_skipped,
            "files_failed": ingest_stats.files_failed,
            "events_by_artifact": dict(sorted(ingest_stats.events_by_artifact.items())),
        }

    if engine_stats is not None:
        doc["rules"] = {
            "evaluated": engine_stats.rules_evaluated,
            "findings_by_rule": dict(sorted(engine_stats.findings_by_rule.items())),
            # A truncated search may have missed a valid chain. Carried into the
            # output rather than left in the console, because a consumer reading
            # only this file would otherwise believe the run was complete.
            "search_truncated": sorted(engine_stats.search_truncated),
        }

    if unscored_families is not None:
        doc["anomalies"]["unscored_families"] = [
            {
                "family": family,
                "reason": unscored_families.reason(family),
                "rows": unscored_families.rows(family),
            }
            for family in sorted(unscored_families)
        ]

    return doc


def write(doc: dict[str, Any], out_path: Path) -> str:
    """Write `run.json` and return its SHA-256.

    `sort_keys` and a fixed separator make the bytes deterministic: two runs
    over one collection produce an identical file, which is what lets the
    manifest hash mean anything.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    out_path.write_text(text, encoding="utf-8", newline="\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
