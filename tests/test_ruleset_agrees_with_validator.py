"""The engine's loader and the standalone checker must agree.

`rules/validate_rules.py` and `core/ruleset.py` implement the same grammar
twice, on purpose: one shared implementation would mean a bug in the grammar
passes both. What makes that safe rather than reckless is this file -- if the
two ever disagree about the real rules in the repository, the gate fails.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from dfir_triage_pipeline.core.ruleset import load_rules

REPO = Path(__file__).resolve().parent.parent
RULES_ROOT = REPO / "rules"
VALIDATOR = RULES_ROOT / "validate_rules.py"


@pytest.fixture(scope="module")
def validator():
    spec = importlib.util.spec_from_file_location("validate_rules", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_the_checker_passes_every_rule_in_the_repository(validator):
    assert validator.main([str(RULES_ROOT)]) == 0


def test_the_engine_loads_every_file_the_checker_checked(validator):
    on_disk = {p.name for p in RULES_ROOT.rglob("*.yml") if p.is_file()}
    loaded = {r.source_path for r in load_rules(RULES_ROOT, include_disabled=True)}
    assert loaded == on_disk


def test_drafts_are_excluded_by_extension_not_by_accident(tmp_path):
    """rules/blocked/ holds rules that are specified but cannot load.

    This asserts against a draft it creates rather than against whatever
    happens to be in rules/blocked/. That directory is empty now that
    R-ATOMIC-0003 moved into atomic/, so the original version of this test
    iterated over nothing and proved nothing -- the same vacuous-loop failure
    the A-9 mutation check caught elsewhere.
    """
    (tmp_path / "atomic").mkdir()
    real = RULES_ROOT / "atomic" / "R-ATOMIC-0002-log-clearing.yml"
    (tmp_path / "atomic" / real.name).write_text(real.read_text(encoding="utf-8"),
                                                 encoding="utf-8")
    (tmp_path / "blocked").mkdir()
    (tmp_path / "blocked" / "R-TEST-9999-parked.yml.draft").write_text(
        real.read_text(encoding="utf-8"), encoding="utf-8")

    loaded = {r.source_path for r in load_rules(tmp_path, include_disabled=True)}
    assert loaded == {real.name}, (
        "a .yml.draft entered the loader's glob; rules/blocked/ would then fail "
        "every run, which is what schema section 1 spells the exclusion out for"
    )


@pytest.fixture
def every_rule():
    """Every rule in the repository, guaranteed non-empty.

    The four tests below assert grammar invariants by looping over the loaded
    rules and asserting inside the loop. **If `load_rules` ever returned an
    empty list they would all pass while checking nothing** -- and they are
    the tests enforcing that presence steps stay out of sliding windows
    (D-027) and that every rule carries a measured base rate. Silence there
    would be the most expensive silence in the suite.

    That is not hypothetical in this repository. `rules/blocked/` emptied out
    when R-ATOMIC-0003 moved into `atomic/`, and the test guarding it "iterated
    over nothing and proved nothing" until it was rewritten to build its own
    fixture -- the note is still in that test below. The same shape appeared
    again in `tests/test_curated_eid_coverage.py`, which matched `_CHANNELS`
    fragments against `path.name`, examined zero files and passed in 0.10s
    (D-059).

    One guard shared by every test that iterates the rule set, so a future
    test gets it by asking for the fixture rather than by remembering.
    """
    rules = load_rules(RULES_ROOT, include_disabled=True)
    assert len(rules) >= 10, (
        f"load_rules returned {len(rules)} rule(s); the grammar invariants "
        "below pass vacuously on an empty set, so they refuse to run on one"
    )
    return rules


def test_every_correlation_rule_names_a_shared_entity(every_rule):
    """The schema-level half of A-9. A rule that cannot name a shared entity
    cannot be loaded, so proximity can never stand in for identity."""
    for rule in every_rule:
        if rule.kind == "correlation":
            assert rule.join_on, f"{rule.rule_id} has no join.on"


def test_every_presence_step_is_excluded_from_the_window(every_rule):
    """Schema 5.2. Checked against the loaded rules rather than trusted."""
    presence = {"registry", "amcache"}
    for rule in every_rule:
        for step in rule.steps:
            if presence.intersection(step.select.source_artifacts):
                assert not step.in_window, (
                    f"{rule.rule_id}.{step.name} selects a presence-typed artifact "
                    "and must not enter a sliding window"
                )


def test_every_rule_records_its_measured_base_rate(every_rule):
    """Schema 8.1, added in 1.4.0.

    `expected` was required on atomic rules only until the first run over all
    three collections showed R-CORR-0003 firing five times on a collection with
    no attack in it. The four rules most likely to be read as detections were
    the four with no measurement recorded beside them.
    """
    for rule in every_rule:
        names = {name for name, _ in rule.expected}
        assert names == {"clean_a", "clean_b", "s1_v2"}, (
            f"{rule.rule_id} does not record a base rate for every collection"
        )


def test_every_window_justification_cites_a_number(every_rule):
    """A round figure chosen because it looks tidy misses the only chain in the
    corpus, so the justification has to carry a measurement."""
    for rule in every_rule:
        if rule.window is not None:
            assert any(ch.isdigit() for ch in rule.window.justification)


def test_claude_md_gate_line_matches_this_run(request):
    """CLAUDE.md's pytest figure must match the suite it describes.

    That file carries its own instruction -- "when these numbers change, change
    them here in the same commit" -- and the figure went stale three times in
    two days anyway, each time because a commit that added tests set the number
    from the previous measurement. An instruction a human has to remember is a
    defect waiting for a busy afternoon.

    So it is checked instead. `passed + skipped` must equal what this session
    collected. Anyone adding a test now gets a failure naming the new number
    rather than a document that quietly stops being true.

    Skipped on a partial run, because the gate line describes the whole suite.
    """
    positional = [a for a in request.config.invocation_params.args
                  if not a.startswith("-")]
    if positional:
        pytest.skip("partial run; the gate line describes the full suite")

    text = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
    match = re.search(r"->\s+(\d+)\s+passed,\s+(\d+)\s+skipped", text)
    assert match, "CLAUDE.md has no 'N passed, M skipped' gate line to check"

    stated = int(match.group(1)) + int(match.group(2))
    collected = request.session.testscollected
    assert stated == collected, (
        f"CLAUDE.md's gate line totals {stated} but this run collected "
        f"{collected}. Update the line in the same commit as the change that "
        f"moved it -- that file says so itself."
    )
