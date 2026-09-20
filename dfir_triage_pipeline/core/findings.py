"""The Finding record: immutable, traceable, deterministic.

Schema section 7 fixes what a finding carries. The one clause that decides
whether the acceptance gate can be met is this:

    A finding that cannot name the source_file and source_locator of every
    event it matched is not acceptable output.

That is the gate's word "traceable" made checkable, so `MatchedEvent` carries
both and `Finding` cannot be built without them.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

_SEP = b"\x1f"

#: What a finding claims about time. Schema sections 5.2 and 5.4.
TIME_CLAIMS = ("observed_interval", "observed_occurrence", "none")


@dataclass(frozen=True, slots=True)
class MatchedEvent:
    """One event inside a finding, with the provenance that makes it checkable."""

    event_id: str
    timestamp: datetime
    timestamp_type: str
    source_artifact: str
    event_type: str
    source_file: str
    source_locator: str
    step: str | None = None

    def __post_init__(self) -> None:
        if not self.source_file or not self.source_locator:
            raise ValueError(
                "a matched event must name its source_file and source_locator; "
                "a finding that cannot is not acceptable output (schema section 7)"
            )

    @classmethod
    def of(cls, event: Any, step: str | None = None) -> MatchedEvent:
        return cls(
            event_id=event.event_id,
            timestamp=event.timestamp,
            timestamp_type=event.timestamp_type,
            source_artifact=event.source_artifact,
            event_type=event.event_type,
            source_file=event.source_file,
            source_locator=event.source_locator,
            step=step,
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule match. Frozen, and keyed by content rather than by identity."""

    rule_id: str
    rule_version: str
    schema_version: str
    title: str
    severity: str
    weight: int
    attack_technique: str
    matched: tuple[MatchedEvent, ...]
    entity_keys: tuple[tuple[str, str], ...]
    time_claim: str
    reason: str
    window_observed_seconds: float | None = None
    notes: tuple[str, ...] = field(default=())
    #: The producing rule's class, carried so `entity_score` can exclude
    #: known-behavior findings from the ranking without re-reading the rule
    #: set. Defaults to `corpus-validated`, so a Finding built by hand -- every
    #: unit test that does not go through `run()` -- behaves as before.
    #:
    #: NOT a `finding_id` input, deliberately: the id is a content hash over
    #: the rule, the matched events and the entity keys, and reclassifying a
    #: rule does not make it a different finding.
    rule_class: str = "corpus-validated"

    def __post_init__(self) -> None:
        if not self.matched:
            raise ValueError("a finding must match at least one event")
        if self.time_claim not in TIME_CLAIMS:
            raise ValueError(f"time_claim must be one of {TIME_CLAIMS}")
        if self.time_claim == "observed_interval" and self.window_observed_seconds is None:
            raise ValueError("observed_interval requires window_observed_seconds")
        if self.time_claim == "none" and self.window_observed_seconds is not None:
            raise ValueError("time_claim 'none' cannot carry an observed window")

    @property
    def finding_id(self) -> str:
        """Deterministic content hash, for the same reason event_id is (CD-002).

        A random id would make two runs over one collection produce different
        output and break diffing and regression tests.
        """
        h = hashlib.sha256()
        h.update(self.rule_id.encode("utf-8"))
        h.update(_SEP)
        for event_id in sorted(m.event_id for m in self.matched):
            h.update(event_id.encode("utf-8"))
            h.update(_SEP)
        for name, value in sorted(self.entity_keys):
            h.update(f"{name}={value}".encode())
            h.update(_SEP)
        return h.hexdigest()[:16]

    @property
    def first_timestamp(self) -> datetime:
        return min(m.timestamp for m in self.matched)

    @property
    def score_contribution(self) -> int:
        return self.weight

    def provenance_lines(self) -> list[str]:
        """One line per matched event, naming the file and the locator."""
        return [
            f"{m.step or m.event_type}: {m.source_file} :: {m.source_locator} "
            f"@ {m.timestamp.isoformat(timespec='microseconds')} ({m.timestamp_type})"
            for m in self.matched
        ]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic order: earliest matched timestamp, rule id, then content.

    Schema section 9. Same input, same findings, same order, every run.
    """
    return sorted(
        findings,
        key=lambda f: (
            f.first_timestamp,
            f.rule_id,
            tuple(sorted(m.event_id for m in f.matched)),
        ),
    )


FINDING_COLUMNS = (
    "finding_id",
    "rule_id",
    "severity",
    "weight",
    "attack_technique",
    "title",
    "first_timestamp_utc",
    "time_claim",
    "window_observed_seconds",
    "entity_keys",
    "matched_event_ids",
    "provenance",
    "reason",
)


def to_row(finding: Finding) -> dict[str, str]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "weight": str(finding.weight),
        "attack_technique": finding.attack_technique,
        "title": finding.title,
        "first_timestamp_utc": finding.first_timestamp.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        "time_claim": finding.time_claim,
        "window_observed_seconds": (
            "" if finding.window_observed_seconds is None
            else f"{finding.window_observed_seconds:.6f}"
        ),
        "entity_keys": "; ".join(f"{k}={v}" for k, v in sorted(finding.entity_keys)),
        "matched_event_ids": " ".join(sorted(m.event_id for m in finding.matched)),
        "provenance": " | ".join(finding.provenance_lines()),
        "reason": finding.reason,
    }
