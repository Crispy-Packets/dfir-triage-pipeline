"""Narration layer: registry, citation validator, and the off-by-default rule.

No model is fitted, no Ollama is contacted -- the client is mocked. These tests
must pass with narration OFF (the default), which is the gate's guarantee that
the suite never depends on a running LLM.
"""

from __future__ import annotations

import pytest

from dfir_triage_pipeline.core import citations, narration


def _facts():
    return {
        "collection": "collection_s1_v3",
        "scorer": "moda_g",
        "rule_ids": ["R-CORR-0001", "R-CORR-0003", "R-CORR-0006"],
        "verdict_entities": [
            {
                "entity": "invoice_scan.exe",
                "severity": "critical",
                "score": 99,
                "rule_ids": ["R-CORR-0003", "R-CORR-0006"],
                "techniques": ["T1547.001"],
            },
            {
                "entity": "onedrive.exe",
                "severity": "medium",
                "score": 60,
                "rule_ids": ["R-CORR-0001"],
                "techniques": [],
            },
        ],
        "prioritisation_ranking_not_detections": [
            {"entity": "invoice_scan.exe", "family": "amcache", "percentile_in_family": 1.0},  # noqa: E501
            {"entity": "svchost.exe", "family": "prefetch", "percentile_in_family": 2.0},
        ],
    }


def _verdict_prose(extra: str = "") -> str:
    """Prose that names the critical verdict -- the baseline a test varies from."""
    return (
        "invoice_scan.exe was scored 99 (critical) by rules R-CORR-0003 and "
        "R-CORR-0006 under the moda_g scorer. " + extra
    )


class TestOffByDefault:
    def test_unset_flag_is_disabled(self, monkeypatch):
        monkeypatch.delenv(narration.NARRATION_FLAG, raising=False)
        assert narration.narration_enabled() is False

    def test_null_backend_is_disabled(self, monkeypatch):
        monkeypatch.setenv(narration.NARRATION_FLAG, "null")
        assert narration.narration_enabled() is False

    def test_ollama_spec_enables(self, monkeypatch):
        monkeypatch.setenv(narration.NARRATION_FLAG, "ollama:qwen2.5:7b")
        assert narration.narration_enabled() is True


class TestRegistry:
    def test_ollama_tag_keeps_its_colon(self, monkeypatch):
        # `qwen2.5:7b` must survive: only the FIRST colon splits backend/model.
        n = narration.make_narrator("ollama:qwen2.5:7b", narration.DEFAULT_ENDPOINT)
        assert n.name == "ollama"
        assert n.model == "qwen2.5:7b"

    def test_unknown_backend_raises(self):
        with pytest.raises(ValueError, match="unknown DFIR_NARRATION backend"):
            narration.make_narrator("gpt4all:x", narration.DEFAULT_ENDPOINT)

    def test_ollama_without_model_raises(self):
        with pytest.raises(ValueError, match="needs a model"):
            narration.make_narrator("ollama:", narration.DEFAULT_ENDPOINT)

    def test_remote_endpoint_is_honoured(self, monkeypatch):
        # Ollama lives on another host; the endpoint points at it, not localhost.
        n = narration.make_narrator("ollama:qwen2.5:7b", "http://192.168.1.50:11434")
        assert n.endpoint == "http://192.168.1.50:11434"


class TestValidator:
    def test_clean_prose_validates(self):
        text = _verdict_prose(
            "It also ranks in the top 1.0 percentile of amcache in the "
            "prioritisation ranking."
        )
        r = citations.validate(text, _facts())
        assert r.validated is True
        assert r.unresolvable == []
        assert r.mentions_scorer is True

    def test_fabricated_rule_id_is_caught(self):
        r = citations.validate(_verdict_prose("Rule R-CORR-9999 fired."), _facts())
        assert r.validated is False
        assert "rule_id:R-CORR-9999" in r.unresolvable

    def test_fabricated_exe_is_caught(self):
        r = citations.validate(_verdict_prose("evil_totally_made_up.exe too."), _facts())
        assert r.validated is False
        assert "exe:evil_totally_made_up.exe" in r.unresolvable

    def test_exe_check_is_case_insensitive(self):
        r = citations.validate("INVOICE_SCAN.EXE was flagged.", _facts())
        assert not any(u.startswith("exe:") for u in r.unresolvable)

    def test_fabricated_percentile_is_caught(self):
        r = citations.validate(_verdict_prose("It sat at the 47.0 percentile."), _facts())
        assert r.validated is False
        assert any(u.startswith("number:") for u in r.unresolvable)

    def test_allowed_percentile_passes(self):
        r = citations.validate(_verdict_prose("Top 2.0 percentile in prefetch."), _facts())
        assert not any(u.startswith("number:") for u in r.unresolvable)

    def test_verdict_score_is_an_allowed_number(self):
        # 99 comes from the verdict entity, not the ranking -- both are citable.
        r = citations.validate(_verdict_prose(), _facts())
        assert not any(u.startswith("number:") for u in r.unresolvable)

    def test_missing_scorer_mention_is_flagged_not_fatal(self):
        r = citations.validate("invoice_scan.exe was flagged by R-CORR-0001.", _facts())
        assert r.validated is True  # scorer mention is non-fatal
        assert r.mentions_scorer is False


class TestCompleteness:
    """Recall, not precision. The first live narration fabricated nothing and was
    still wrong: it omitted the 99/critical entity and described the anomaly
    ranking instead. Precision-only validation accepted it. These tests are the
    regression."""

    #: Verbatim from the first live run (qwen2.5:7b, prompt v1, s1_v3 vs
    #: clean_c). Frozen as evidence of the failure mode, not paraphrased.
    FIRST_LIVE_FAILURE = (
        "The moda_g scorer analysed 132 anomalies in collection_s1_v3. The "
        "anomaly layer detected rules such as R-ATOMIC-0002 and R-ATOMIC-0006, "
        "with dllhost.exe ranking highest, followed by onedrivesetup.exe and "
        "runtimebroker.exe with a percentile of 0.0986. Several suspicious PDFs "
        "were downloaded."
    )

    def test_omitting_the_critical_entity_is_rejected(self):
        text = (
            "Under the moda_g scorer, svchost.exe leads the ranking at the 2.0 "
            "percentile of prefetch."
        )
        r = citations.validate(text, _facts())
        assert r.validated is False
        assert "missing:invoice_scan.exe" in r.unresolvable
        assert r.missing_mentions == ["invoice_scan.exe"]

    def test_naming_the_critical_entity_clears_the_check(self):
        r = citations.validate(_verdict_prose(), _facts())
        assert r.missing_mentions == []

    def test_top_scorer_is_required_when_nothing_is_critical(self):
        facts = _facts()
        for v in facts["verdict_entities"]:
            v["severity"] = "high"
        r = citations.validate("Nothing much happened.", facts)
        assert "missing:invoice_scan.exe" in r.unresolvable  # the 99, not the 60

    def test_the_first_live_failure_is_now_rejected(self):
        # It cited nothing fabricated -- and must still fail, on omission.
        r = citations.validate(self.FIRST_LIVE_FAILURE, _facts())
        assert r.validated is False
        assert "missing:invoice_scan.exe" in r.missing_mentions or (
            "missing:invoice_scan.exe" in r.unresolvable
        )

    def test_the_first_live_failure_is_flagged_as_backwards_attribution(self):
        r = citations.validate(self.FIRST_LIVE_FAILURE, _facts())
        assert r.describes_ranking_as_detection is True

    def test_correct_attribution_is_not_flagged(self):
        r = citations.validate(
            _verdict_prose("The anomaly layer ranks it first; it detects nothing."),
            _facts(),
        )
        assert r.describes_ranking_as_detection is False

    def test_percentile_written_suffix_first_is_checked(self):
        # `a percentile of 0.0986` was invisible to the original number regex.
        r = citations.validate(
            _verdict_prose("runtimebroker.exe sat at a percentile of 47.5."),
            _facts(),
        )
        assert "number:47.5" in r.unresolvable


class TestNarrateWithMockedClient:
    def _doc(self):
        return {
            "collection": {"name": "collection_s1_v3"},
            "entities": [
                {
                    "value": "invoice_scan.exe",
                    "key": "entity.exe_name",
                    "score": 99,
                    "severity": "critical",
                    "rule_ids": ["R-CORR-0001"],
                    "techniques": ["T1547.001"],
                },
            ],
            "anomalies": {
                "scorer": "moda_g",
                "scored_entities": [
                    {
                        "entity": "invoice_scan.exe",
                        "family": "amcache",
                        "percentile_in_family": 1.0,
                    },
                ],
            },
            "findings": [
                {
                    "rule_id": "R-CORR-0001",
                    "entity_keys": [{"key": "entity.exe_name", "value": "invoice_scan.exe"}],
                },
            ],
        }

    def test_accepted_narration_stores_text(self, monkeypatch):
        monkeypatch.setenv(narration.NARRATION_FLAG, "ollama:qwen2.5:7b")

        def fake_generate(self, prompt):
            return "invoice_scan.exe was flagged by R-CORR-0001 under the moda_g scorer."

        monkeypatch.setattr(narration._OllamaNarrator, "generate", fake_generate)
        monkeypatch.setattr(narration._OllamaNarrator, "digest", lambda self: "sha256:abc")
        block = narration.narrate(self._doc())
        assert block["status"] == "accepted"
        assert "invoice_scan.exe" in block["text"]
        assert block["is_verdict"] is False
        assert block["validation"]["mentions_scorer"] is True

    def test_fabrication_is_rejected_not_stored_as_text(self, monkeypatch):
        monkeypatch.setenv(narration.NARRATION_FLAG, "ollama:qwen2.5:7b")
        monkeypatch.setattr(
            narration._OllamaNarrator,
            "generate",
            lambda self, prompt: "Rule R-CORR-9999 flagged badguy.exe.",
        )
        monkeypatch.setattr(narration._OllamaNarrator, "digest", lambda self: None)
        block = narration.narrate(self._doc())
        assert block["status"] == "rejected"
        assert "text" not in block  # rejected prose is namespaced, not top-level
        assert block["rejected"]["text"]
        assert block["validation"]["unresolvable"]

    def test_facts_lead_with_the_verdict_not_the_ranking(self):
        # The bug this shape fixes: the model narrated the ranking because the
        # ranking was what the fact slice put in front of it.
        facts = narration._facts(self._doc())
        assert list(facts)[:3] == ["collection", "scorer", "verdict_entities"]
        top = facts["verdict_entities"][0]
        assert top["entity"] == "invoice_scan.exe"
        assert top["severity"] == "critical"
        assert top["score"] == 99
        assert top["rule_ids"] == ["R-CORR-0001"]
        # The ranking key names what it is not, in the prompt the model reads.
        assert "prioritisation_ranking_not_detections" in facts
        assert "top_anomalies" not in facts

    def test_prompt_text_puts_the_verdict_before_the_ranking(self, monkeypatch):
        # Ordering `_facts()` is not enough: json.dumps(sort_keys=True) would
        # alphabetise the ranking ahead of the verdict and reinstate the bug.
        monkeypatch.setenv(narration.NARRATION_FLAG, "ollama:qwen2.5:7b")
        seen = {}

        def capture(self, prompt):
            seen["prompt"] = prompt
            return "invoice_scan.exe was flagged by R-CORR-0001 under moda_g."

        monkeypatch.setattr(narration._OllamaNarrator, "generate", capture)
        monkeypatch.setattr(narration._OllamaNarrator, "digest", lambda self: None)
        narration.narrate(self._doc())
        body = seen["prompt"]
        assert body.index("verdict_entities") < body.index(
            "prioritisation_ranking_not_detections"
        )

    def test_facts_order_verdicts_worst_first(self):
        doc = self._doc()
        doc["entities"] = [
            {"value": "npp.exe", "score": 75, "severity": "high", "rule_ids": []},
            {"value": "invoice_scan.exe", "score": 99, "severity": "critical", "rule_ids": []},
            {"value": "vboxuser", "score": 88, "severity": "high", "rule_ids": []},
        ]
        order = [v["entity"] for v in narration._facts(doc)["verdict_entities"]]
        assert order == ["invoice_scan.exe", "vboxuser", "npp.exe"]

    def test_unreachable_ollama_records_error_not_raises(self, monkeypatch):
        monkeypatch.setenv(narration.NARRATION_FLAG, "ollama:qwen2.5:7b")

        def boom(self, prompt):
            raise OSError("connection refused")

        monkeypatch.setattr(narration._OllamaNarrator, "generate", boom)
        block = narration.narrate(self._doc())
        assert block["status"] == "error"
        assert "connection refused" in block["error"]
        assert "text" not in block
