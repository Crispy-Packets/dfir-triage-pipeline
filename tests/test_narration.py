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
        "finding_count": 3,
        "rule_ids": ["R-CORR-0001", "R-CORR-0003", "R-CORR-0006"],
        "verdict_entities": ["invoice_scan.exe", "onedrive.exe"],
        "top_anomalies": [
            {"entity": "invoice_scan.exe", "family": "amcache", "percentile_in_family": 1.0},  # noqa: E501
            {"entity": "svchost.exe", "family": "prefetch", "percentile_in_family": 2.0},
        ],
    }


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
        text = (
            "invoice_scan.exe was flagged by rules R-CORR-0001 and R-CORR-0003. "
            "Under the moda_g scorer it ranks in the top 1.0 percentile of amcache."
        )
        r = citations.validate(text, _facts())
        assert r.validated is True
        assert r.unresolvable == []
        assert r.mentions_scorer is True

    def test_fabricated_rule_id_is_caught(self):
        r = citations.validate("Rule R-CORR-9999 fired.", _facts())
        assert r.validated is False
        assert "rule_id:R-CORR-9999" in r.unresolvable

    def test_fabricated_exe_is_caught(self):
        r = citations.validate("evil_totally_made_up.exe was the culprit.", _facts())
        assert r.validated is False
        assert "exe:evil_totally_made_up.exe" in r.unresolvable

    def test_exe_check_is_case_insensitive(self):
        r = citations.validate("INVOICE_SCAN.EXE was flagged.", _facts())
        assert not any(u.startswith("exe:") for u in r.unresolvable)

    def test_fabricated_percentile_is_caught(self):
        r = citations.validate("It sat at the 47.0 percentile.", _facts())
        assert r.validated is False
        assert any(u.startswith("number:") for u in r.unresolvable)

    def test_allowed_percentile_passes(self):
        r = citations.validate("Top 2.0 percentile in prefetch.", _facts())
        assert not any(u.startswith("number:") for u in r.unresolvable)

    def test_missing_scorer_mention_is_flagged_not_fatal(self):
        r = citations.validate("invoice_scan.exe was flagged by R-CORR-0001.", _facts())
        assert r.validated is True  # scorer mention is non-fatal
        assert r.mentions_scorer is False


class TestNarrateWithMockedClient:
    def _doc(self):
        return {
            "collection": {"name": "collection_s1_v3"},
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

    def test_unreachable_ollama_records_error_not_raises(self, monkeypatch):
        monkeypatch.setenv(narration.NARRATION_FLAG, "ollama:qwen2.5:7b")

        def boom(self, prompt):
            raise OSError("connection refused")

        monkeypatch.setattr(narration._OllamaNarrator, "generate", boom)
        block = narration.narrate(self._doc())
        assert block["status"] == "error"
        assert "connection refused" in block["error"]
        assert "text" not in block
