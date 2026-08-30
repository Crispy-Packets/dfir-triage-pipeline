"""The engine's loader and the standalone checker must agree.

`rules/validate_rules.py` and `core/ruleset.py` implement the same grammar
twice, on purpose: one shared implementation would mean a bug in the grammar
passes both. What makes that safe rather than reckless is this file -- if the
two ever disagree about the real rules in the repository, the gate fails.
"""

from __future__ import annotations

import importlib.util
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


def test_drafts_are_excluded_by_extension_not_by_accident():
    """rules/blocked/ holds rules that are specified but cannot load. If a
    .yml.draft ever entered the glob it would fail every run, which is exactly
    why the exclusion is spelled out in schema section 1."""
    drafts = list(RULES_ROOT.rglob("*.yml.draft"))
    loaded = {r.source_path for r in load_rules(RULES_ROOT, include_disabled=True)}
    for draft in drafts:
        assert draft.name not in loaded


def test_every_correlation_rule_names_a_shared_entity():
    """The schema-level half of A-9. A rule that cannot name a shared entity
    cannot be loaded, so proximity can never stand in for identity."""
    for rule in load_rules(RULES_ROOT, include_disabled=True):
        if rule.kind == "correlation":
            assert rule.join_on, f"{rule.rule_id} has no join.on"


def test_every_presence_step_is_excluded_from_the_window():
    """Schema 5.2. Checked against the loaded rules rather than trusted."""
    presence = {"registry", "amcache"}
    for rule in load_rules(RULES_ROOT, include_disabled=True):
        for step in rule.steps:
            if presence.intersection(step.select.source_artifacts):
                assert not step.in_window, (
                    f"{rule.rule_id}.{step.name} selects a presence-typed artifact "
                    "and must not enter a sliding window"
                )


def test_every_window_justification_cites_a_number():
    """A round figure chosen because it looks tidy misses the only chain in the
    corpus, so the justification has to carry a measurement."""
    for rule in load_rules(RULES_ROOT, include_disabled=True):
        if rule.window is not None:
            assert any(ch.isdigit() for ch in rule.window.justification)
