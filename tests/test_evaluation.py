"""Ranking metrics for the anomaly layer (B-3, B-4).

The properties asserted here are the ones that would let a metric flatter the
model without anything failing: counting an entity once per artefact that
recorded it, counting an unscored entity as a miss, or a ranking that reorders
between runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline import anomaly, evaluation, features
from dfir_triage_pipeline.anomaly import Scored


class _Event:
    """Minimal stand-in carrying only what `entity_of` reads."""

    def __init__(self, name: str | None) -> None:
        self.details = {"path_basename_canonical": name} if name else {}


def _row(name: str | None, pct: float, family: str = "prefetch") -> Scored:
    return Scored(
        event=_Event(name),
        score=pct / 100.0,
        is_outlier=pct < 5.0,
        family=family,
        percentile_in_family=pct,
    )


class TestRankEntities:
    def test_entity_takes_its_best_row(self) -> None:
        """An entity is as suspicious as its most anomalous row.

        An analyst who opens an entity sees every row it has, so burying one
        anomalous row under nine ordinary ones is a property of how many
        artefacts recorded it -- not evidence that the entity is ordinary.
        """
        ranked = evaluation.rank_entities(
            [_row("a.exe", 50.0), _row("a.exe", 2.0), _row("a.exe", 90.0)]
        )
        assert len(ranked) == 1
        assert ranked[0].best_percentile == 2.0
        assert ranked[0].row_count == 3

    def test_ten_rows_count_as_one_entity(self) -> None:
        """B-4's whole point. `invoice_scan.exe` is ~10 rows across 3 artefacts;
        counting it ten times inflates every metric by the collection's shape."""
        ranked = evaluation.rank_entities([_row("invoice_scan.exe", 5.0) for _ in range(10)])
        assert len(ranked) == 1
        assert ranked[0].row_count == 10

    def test_rows_without_an_entity_are_dropped(self) -> None:
        """An EVTX log-on record has no executable. Grouping such rows under a
        placeholder would put unrelated events in competition with each other."""
        ranked = evaluation.rank_entities([_row(None, 1.0), _row("a.exe", 50.0)])
        assert [r.entity for r in ranked] == ["a.exe"]

    def test_rank_is_one_based_and_ordered_by_anomaly(self) -> None:
        ranked = evaluation.rank_entities(
            [_row("c.exe", 80.0), _row("a.exe", 5.0), _row("b.exe", 40.0)]
        )
        assert [(r.rank, r.entity) for r in ranked] == [(1, "a.exe"), (2, "b.exe"), (3, "c.exe")]

    def test_ties_are_broken_deterministically(self) -> None:
        """Two entities on the same percentile are genuinely tied and the order
        between them means nothing -- but an unstable order would make two runs
        of the same evaluation disagree, which is worse than an arbitrary one."""
        rows = [_row("z.exe", 10.0), _row("a.exe", 10.0), _row("m.exe", 10.0)]
        first = [r.entity for r in evaluation.rank_entities(rows)]
        second = [r.entity for r in evaluation.rank_entities(list(reversed(rows)))]
        assert first == second == ["a.exe", "m.exe", "z.exe"]

    def test_family_travels_with_the_percentile(self) -> None:
        """Percentiles compare only within a family, so the number is
        uninterpretable without it."""
        ranked = evaluation.rank_entities(
            [_row("a.exe", 30.0, "amcache"), _row("a.exe", 4.0, "prefetch")]
        )
        assert ranked[0].family == "prefetch"

    def test_unpercentiled_rows_are_skipped(self) -> None:
        """A bare AnomalyModel produces no percentile. Treating None as 0.0
        would rank an unranked row as the most anomalous thing in the corpus."""
        bare = Scored(event=_Event("a.exe"), score=0.1, is_outlier=False)
        assert evaluation.rank_entities([bare]) == []


class TestEvaluateRanking:
    def test_found_when_inside_top_k(self) -> None:
        rows = [_row("invoice_scan.exe", 1.0)] + [_row(f"b{i}.exe", 50.0 + i) for i in range(20)]
        result = evaluation.evaluate_ranking(rows, k=10)
        assert result.found == ("invoice_scan.exe",)
        assert result.missed == ()
        assert result.positions["invoice_scan.exe"] == 1

    def test_missed_when_outside_top_k(self) -> None:
        rows = [_row("invoice_scan.exe", 99.0)] + [_row(f"b{i}.exe", float(i)) for i in range(20)]
        result = evaluation.evaluate_ranking(rows, k=10)
        assert result.missed == ("invoice_scan.exe",)
        assert result.found == ()
        assert result.recall_at_k == 0.0

    def test_unscored_is_not_counted_as_a_miss(self) -> None:
        """The reporting rule from groundtruth/verification-method.md section 2:
        a recall figure that charges the pipeline for rows it was never given
        is not reported. An entity with no model for its family is unscored."""
        result = evaluation.evaluate_ranking([_row("other.exe", 5.0)], k=10)
        assert result.unscored == ("invoice_scan.exe",)
        assert result.missed == ()
        assert result.evaluable == ()
        assert result.recall_at_k == 0.0  # no evaluable rows, not a failure

    def test_recall_denominator_excludes_unscored(self) -> None:
        rows = [_row("a.exe", 1.0), _row("filler.exe", 50.0)]
        result = evaluation.evaluate_ranking(rows, ground_truth={"a.exe", "ghost.exe"}, k=10)
        assert result.evaluable == ("a.exe",)
        assert result.unscored == ("ghost.exe",)
        assert result.recall_at_k == 1.0  # 1 of 1 evaluable, not 1 of 2

    def test_lift_measures_gain_over_random_ordering(self) -> None:
        """Lift is the number to lead with: precision@K is capped by a
        single-scenario corpus, lift is not."""
        rows = [_row(f"b{i}.exe", 10.0 + i) for i in range(100)]
        rows.append(_row("invoice_scan.exe", 1.0))  # ranks 1 of 101
        result = evaluation.evaluate_ranking(rows, k=10)
        assert result.positions["invoice_scan.exe"] == 1
        # recall 1.0 against a chance recall of 10/101
        assert result.lift == pytest.approx(101 / 10)

    def test_lift_is_below_one_when_ranking_is_worse_than_chance(self) -> None:
        """An entity just outside the window scores zero recall, so zero lift.
        A model that ranks the attack below average is worse than shuffling."""
        rows = [_row(f"b{i}.exe", float(i)) for i in range(100)]
        rows.append(_row("invoice_scan.exe", 9.5))  # ten entities rank ahead
        result = evaluation.evaluate_ranking(rows, k=10)
        assert result.positions["invoice_scan.exe"] == 11
        assert result.lift == 0.0

    def test_lift_is_zero_when_nothing_found(self) -> None:
        rows = [_row("invoice_scan.exe", 99.0)] + [_row(f"b{i}.exe", float(i)) for i in range(50)]
        assert evaluation.evaluate_ranking(rows, k=5).lift == 0.0

    def test_precision_is_capped_by_the_corpus(self) -> None:
        """One attack entity against K=10 caps precision at 0.10. This is a
        property of a single-scenario corpus, not a result about the model."""
        rows = [_row("invoice_scan.exe", 1.0)] + [_row(f"b{i}.exe", 50.0 + i) for i in range(20)]
        assert evaluation.evaluate_ranking(rows, k=10).precision_at_k == pytest.approx(0.1)

    def test_empty_input_does_not_raise(self) -> None:
        result = evaluation.evaluate_ranking([], k=10)
        assert result.total_entities == 0
        assert result.recall_at_k == 0.0
        assert result.lift == 0.0

    def test_sweep_covers_every_k(self) -> None:
        rows = [_row("invoice_scan.exe", 50.0)] + [_row(f"b{i}.exe", float(i)) for i in range(60)]
        results = evaluation.sweep(rows, ks=(1, 5, 10, 25, 50))
        assert [r.k for r in results] == [1, 5, 10, 25, 50]
        # Recall is monotonic in K: a larger window cannot find less.
        recalls = [r.recall_at_k for r in results]
        assert recalls == sorted(recalls)


EVIDENCE = Path.home() / "dfir-evidence"

needs_collections = pytest.mark.skipif(
    not (EVIDENCE / "collection_clean_b").is_dir()
    or not (EVIDENCE / "collection_s1_v2").is_dir(),
    reason="clean_b and s1_v2 collections are required",
)


@pytest.fixture(scope="module")
def s1_scored():
    """Fit on clean_b, score s1_v2 -- the configuration every result uses.
    Runs under the default scorer (MODA*-G since 2026-09-22), so this fixture
    is now a MODA fit on real evidence and takes minutes, not seconds; it is
    gated behind @needs_collections and scoped per-module so it runs once."""
    train = collect_events(EVIDENCE / "collection_clean_b")[0]
    test = collect_events(EVIDENCE / "collection_s1_v2")[0]
    assert train and test, "a collection produced no events; tests would pass vacuously"

    rarity = features.build_rarity_index(train)
    scored = anomaly.PerFamilyModel().fit(train, rarity).score(test, rarity)
    assert scored, "no rows scored"
    return scored


@needs_collections
class TestAgainstRealEvidence:
    def test_the_attack_entity_is_present_and_scored(self, s1_scored) -> None:
        """If this fails the harness is measuring the wrong thing, and every
        number it produces afterwards is meaningless."""
        ranked = evaluation.rank_entities(s1_scored)
        entities = {r.entity for r in ranked}
        assert "invoice_scan.exe" in entities, (
            "the ground-truth entity is absent from the ranking; "
            f"{len(entities)} entities were ranked"
        )

    def test_metrics_are_computable_on_real_evidence(self, s1_scored) -> None:
        result = evaluation.evaluate_ranking(s1_scored, k=10)
        assert result.total_entities > 0
        assert result.unscored == (), "the attack entity was not scored at all"
        assert result.evaluable == ("invoice_scan.exe",)
        # No assertion on the VALUE. The anomaly layer is not expected to
        # surface Scenario 1 (shared/DECIDED.md), and asserting a threshold
        # here would be tuning the corpus to the test.

    def test_entity_ranking_is_smaller_than_row_ranking(self, s1_scored) -> None:
        """The B-4 claim, checked rather than assumed: aggregation must
        actually collapse rows, or it is doing nothing."""
        ranked = evaluation.rank_entities(s1_scored)
        rows_with_entities = sum(1 for s in s1_scored if evaluation.entity_of(s))
        assert len(ranked) < rows_with_entities
