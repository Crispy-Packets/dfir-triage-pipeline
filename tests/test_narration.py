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
        "rule_ids": ["R-ATOMIC-0002", "R-CORR-0001", "R-CORR-0003", "R-CORR-0006"],
        "verdict_entities": [
            {
                "entity": "invoice_scan.exe",
                "kind": "program",
                "priority_band": "critical",
                "triage_score": 99,
                "rule_ids": ["R-CORR-0003", "R-CORR-0006"],
                "techniques": ["T1547.001"],
                # The real rank, as the record holds it -- NOT rank 1. Withholding
                # this is what produced the "ranked first" hallucination.
                "anomaly_rank": {
                    "rank": 14,
                    "of": 443,
                    "family": "amcache",
                    "percentile_in_family": 0.9579,
                },
            },
            {
                "entity": "vboxuser",
                "kind": "user account",
                "priority_band": "high",
                "triage_score": 88,
                "rule_ids": ["R-ATOMIC-0002"],
                "techniques": ["T1070.001"],
            },
            {
                "entity": "onedrive.exe",
                "kind": "program",
                "priority_band": "medium",
                "triage_score": 60,
                "rule_ids": ["R-CORR-0001"],
                "techniques": [],
                "anomaly_rank": {
                    "rank": 44,
                    "of": 443,
                    "family": "prefetch",
                    "percentile_in_family": 3.8462,
                },
            },
        ],
        "verdict_findings": [
            {
                "id": "F:2f2ac42d6fd95ae7",
                "rule": "R-CORR-0003",
                "title": "An executed binary is also registered to run at logon",
                "entities": ["invoice_scan.exe"],
                "date": "2026-09-13",
                "time_utc": "11:50",
                "time_claim": "observed_occurrence",
            },
            {
                "id": "F:51e94ba50068aac2",
                "rule": "R-ATOMIC-0002",
                "title": "Windows event log cleared",
                "entities": ["winvm", "vboxuser"],
                "date": "2026-09-13",
                "time_utc": "12:15",
                "time_claim": "observed_occurrence",
                "evidence": [
                    "C/Windows/System32/winevt/logs/Security.evtx :: EventRecordID=15568"
                ],
            },
        ],
        "anomaly_ranking_meaning": "0 is the most unusual row of its kind.",
        "ranking_sentences_already_written_do_not_restate": [
            "In the moda_g anomaly ranking, invoice_scan.exe is rank 14 of 443 "
            "(amcache, percentile 0.9579; 0 = most unusual of its kind). This "
            "ranks unusualness; it is not a detection.",
        ],
    }


def _verdict_prose(extra: str = "") -> str:
    """Prose that names the critical verdict -- the baseline a test varies from."""
    return (
        "invoice_scan.exe has triage score 99 (critical) from rules R-CORR-0003 "
        "and R-CORR-0006 under the moda_g scorer. " + extra
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
            "invoice_scan.exe was executed and is registered to run at logon."
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
        r = citations.validate(
            _verdict_prose("onedrive.exe sits at percentile 3.8462."), _facts()
        )
        assert not any(u.startswith("number:") for u in r.unresolvable)

    def test_verdict_score_is_an_allowed_number(self):
        # 99 comes from the verdict entity, not the ranking -- both are citable.
        r = citations.validate(_verdict_prose(), _facts())
        assert not any(u.startswith("number:") for u in r.unresolvable)

    def test_missing_scorer_mention_is_flagged_not_fatal(self):
        r = citations.validate("invoice_scan.exe was flagged by R-CORR-0003.", _facts())
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
            v["priority_band"] = "high"
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

    def test_the_false_rank_claim_is_now_rejected(self):
        """The second live failure, now caught.

        qwen2.5:7b (prompt v2) wrote that invoice_scan.exe was "ranked first" in
        the moda_g ranking. The record says rank 14 of 443. Nothing was
        fabricated, nothing required was omitted, attribution was correct -- so
        precision and completeness both passed and it was ACCEPTED.

        Person A's viewer renders the record directly beneath the prose, which
        put "ranked first" on screen above "rank 14 of 443". Their reference
        checker rejected the text this validator had accepted; these checks are
        ported from it.

        A rank is an ENUMERABLE field, so a claim about it is checkable. That is
        the boundary: relation claims over enumerable structured fields can be
        verified; claims over open semantics cannot (see the test below).
        """
        text = (
            "invoice_scan.exe was scored 99 (critical) by R-CORR-0003 and "
            "R-CORR-0006, and is ranked first in the moda_g prioritisation ranking."
        )
        r = citations.validate(text, _facts())
        assert r.validated is False
        assert any("rank_claim:invoice_scan.exe" in e for e in r.relation_errors)
        assert any("rank 14 of 443" in e for e in r.relation_errors)

    def test_the_correct_rank_is_accepted(self):
        text = _verdict_prose(
            "invoice_scan.exe is rank 14 of 443 in the moda_g ranking."
        )
        r = citations.validate(text, _facts())
        assert r.relation_errors == []
        assert r.validated is True

    def test_a_wrong_explicit_rank_is_rejected(self):
        r = citations.validate(
            _verdict_prose("invoice_scan.exe is rank 3 of 443 in the moda_g ranking."),
            _facts(),
        )
        assert r.validated is False
        assert any("claimed rank 3" in e for e in r.relation_errors)

    def test_rank_claim_carries_the_subject_across_sentences(self):
        # "This file is ranked first" names nothing; the subject is inherited.
        text = _verdict_prose("This file is ranked first in the moda_g ranking.")
        r = citations.validate(text, _facts())
        assert any("rank_claim:invoice_scan.exe" in e for e in r.relation_errors)

    def test_comparison_of_suspicion_is_rejected(self):
        r = citations.validate(
            _verdict_prose("dllhost.exe is less suspicious than invoice_scan.exe."),
            _facts(),
        )
        assert r.validated is False
        assert any(e.startswith("comparison:") for e in r.relation_errors)

    def test_severity_score_phrasing_is_rejected(self):
        # Merges two fields: 99 is the triage score, critical is the band.
        r = citations.validate(
            "invoice_scan.exe has a critical severity score of 99.", _facts()
        )
        assert r.validated is False
        assert any(e.startswith("merged_fields:") for e in r.relation_errors)

    def test_true_score_superlatives_are_accepted(self):
        """Verified, not banned. v3 banned "the highest triage score" and so
        rejected true statements -- 99 IS the highest. The record holds every
        score, so an ordering claim over them is checkable, and a true one passes.
        """
        for phrase in (
            "invoice_scan.exe has the highest triage score in this run.",
            "vboxuser has the second-highest triage score.",
            "onedrive.exe has the lowest triage score.",
        ):
            r = citations.validate(_verdict_prose(phrase), _facts())
            assert not any(e.startswith("score_ordering:") for e in r.relation_errors), phrase

    def test_false_score_superlatives_are_rejected(self):
        for phrase in (
            "onedrive.exe has the highest triage score in this run.",
            "invoice_scan.exe has the second-highest triage score.",
            "vboxuser has the lowest triage score.",
        ):
            r = citations.validate(_verdict_prose(phrase), _facts())
            assert r.validated is False, phrase
            assert any(e.startswith("score_ordering:") for e in r.relation_errors), phrase

    def test_band_qualifier_narrows_the_comparison(self):
        # Among the high band, vboxuser (88) is the only member: highest AND lowest.
        r = citations.validate(
            _verdict_prose("vboxuser has the lowest triage score among the high-band entities."),
            _facts(),
        )
        assert not any(e.startswith("score_ordering:") for e in r.relation_errors)

    def test_order_words_between_findings_are_rejected(self):
        """The corpus shows why: invoice_scan.exe's Recycle Bin deletion is
        recorded at 10:30, BEFORE its download at 10:44. A model telling a story
        writes "downloaded, then deleted". Order is the timeline's job."""
        r = citations.validate(
            _verdict_prose("invoice_scan.exe was executed, then registered to run at logon."),
            _facts(),
        )
        assert r.validated is False
        assert any(e.startswith("order_claim:") for e in r.relation_errors)

    def test_a_recorded_time_is_accepted(self):
        r = citations.validate(
            _verdict_prose("invoice_scan.exe was executed (last run 11:50 UTC)."), _facts()
        )
        assert not any(u.startswith("time:") for u in r.unresolvable)

    def test_an_invented_time_is_rejected(self):
        r = citations.validate(
            _verdict_prose("invoice_scan.exe was executed at 09:14 UTC."), _facts()
        )
        assert r.validated is False
        assert "time:09:14" in r.unresolvable

    def test_an_invented_date_is_rejected(self):
        r = citations.validate(
            _verdict_prose("invoice_scan.exe was executed on 2026-09-01."), _facts()
        )
        assert "date:2026-09-01" in r.unresolvable

    def test_a_user_account_is_never_executed(self):
        """v3's own output: "vboxuser has triage score 88 (high). This entity was
        executed" -- vboxuser is a user account. The kind comes from run.json, so
        the check is mechanical, and the pronoun is resolved to vboxuser."""
        r = citations.validate(
            _verdict_prose(
                "vboxuser has triage score 88 (high). This entity was executed."
            ),
            _facts(),
        )
        assert r.validated is False
        assert any(e.startswith("kind:vboxuser") for e in r.relation_errors)

    def test_a_program_may_be_executed(self):
        r = citations.validate(_verdict_prose("invoice_scan.exe was executed."), _facts())
        assert not any(e.startswith("kind:") for e in r.relation_errors)

    def test_a_rule_must_belong_to_the_sentence_subject(self):
        # R-CORR-0001 fired on onedrive.exe, not invoice_scan.exe.
        r = citations.validate(
            _verdict_prose("invoice_scan.exe was downloaded and executed (R-CORR-0001)."),
            _facts(),
        )
        assert r.validated is False
        assert any(e.startswith("pairing:R-CORR-0001") for e in r.relation_errors)

    def test_the_wrong_event_log_is_rejected(self):
        """v5 wrote "System event log" for a clear recorded in Security.evtx --
        copied from the prompt's made-up example. The path contains System32, so
        the check must read the .evtx file name, not the whole path."""
        r = citations.validate(
            _verdict_prose("The System event log on winvm was cleared (R-ATOMIC-0002)."),
            _facts(),
        )
        assert r.validated is False
        assert "log:System" in r.unresolvable

    def test_the_recorded_event_log_is_accepted(self):
        r = citations.validate(
            _verdict_prose("The Security event log on winvm was cleared (R-ATOMIC-0002)."),
            _facts(),
        )
        assert not any(u.startswith("log:") for u in r.unresolvable)

    def test_a_name_early_in_the_sentence_is_its_subject(self):
        """"The user account vboxuser ..." opens like a pronoun phrase but names
        its subject. v5 was wrongly rejected: R-ATOMIC-0002 was pinned on the
        previous sentence's entity instead of vboxuser, which owns it."""
        r = citations.validate(
            _verdict_prose(
                "The user account vboxuser (triage score 88, high) had the Security "
                "event log cleared at 12:15 UTC (R-ATOMIC-0002)."
            ),
            _facts(),
        )
        assert not any(e.startswith("pairing:") for e in r.relation_errors)
        assert r.validated is True

    def test_an_invented_host_is_rejected(self):
        """v6 wrote "an event log on host-7" -- copied from the prompt example.
        The record's host is winvm."""
        r = citations.validate(
            _verdict_prose("The Security event log on host-7 was cleared (R-ATOMIC-0002)."),
            _facts(),
        )
        assert r.validated is False
        assert "host:host-7" in r.unresolvable

    def test_an_unnamed_host_is_not_read_as_a_host_name(self):
        # v7: "the Security event log on the host was cleared" -- vague, true.
        r = citations.validate(
            _verdict_prose(
                "The Security event log on the host was cleared (R-ATOMIC-0002)."
            ),
            _facts(),
        )
        assert not any(u.startswith("host:") for u in r.unresolvable)

    def test_the_recorded_host_is_accepted(self):
        r = citations.validate(
            _verdict_prose("The Security event log on winvm was cleared (R-ATOMIC-0002)."),
            _facts(),
        )
        assert not any(u.startswith("host:") for u in r.unresolvable)

    def test_an_unfilled_template_blank_is_rejected(self):
        r = citations.validate(
            _verdict_prose("The Security event log on <host> was cleared (R-ATOMIC-0002)."),
            _facts(),
        )
        assert r.validated is False
        assert "blank:<host>" in r.unresolvable

    def test_a_bare_the_is_not_a_back_reference(self):
        # "The Security event log..." is about the log, not invoice_scan.exe --
        # pinning R-ATOMIC-0002 on the previous subject would be a false reject.
        r = citations.validate(
            _verdict_prose("The Security event log on winvm was cleared (R-ATOMIC-0002)."),
            _facts(),
        )
        assert not any(e.startswith("pairing:") for e in r.relation_errors)

    def test_stating_each_score_on_its_own_is_accepted(self):
        r = citations.validate(
            _verdict_prose("onedrive.exe has triage score 60 (high) from R-CORR-0001."),
            _facts(),
        )
        assert r.relation_errors == []
        assert r.validated is True

    def test_open_semantic_claims_remain_uncheckable(self):
        """The honest boundary, restated correctly after the first attempt got it
        wrong.

        The original version of this test asserted that NO relational claim could
        be checked, and said so in CLAUDE.md and the docs. Person A disproved it
        by writing a checker. Rank claims are checkable because rank is
        enumerable. What stays out of reach is open semantics -- intent, motive,
        causation -- where there is no field to compare against.
        """
        text = _verdict_prose(
            "invoice_scan.exe was deployed by the operator to establish "
            "persistence."
        )
        r = citations.validate(text, _facts())
        assert r.validated is True  # every token resolves; the intent claim does not
        assert r.relation_errors == []

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
        assert top["priority_band"] == "critical"
        assert top["triage_score"] == 99
        assert top["rule_ids"] == ["R-CORR-0001"]
        # The ranking key names what it is not, in the prompt the model reads.
        assert "ranking_sentences_already_written_do_not_restate" in facts
        assert "top_anomalies" not in facts
        assert "prioritisation_ranking_not_detections" not in facts

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
            "ranking_sentences_already_written_do_not_restate"
        )
        # The model is handed the ranking as FINISHED sentences, never as a list
        # to paraphrase -- that is what makes a misstated rank impossible here.
        assert "is rank 1 of 1" in body  # this fixture has one scored entity

    def test_prompt_example_carries_no_evidence(self):
        """Prompt v4's worked example was written from collection_s1_v3, and the
        model reproduced it nearly verbatim: a correct narration that proved
        nothing, because the answer was in the prompt. The example must teach
        style only, so it may name nothing from the real corpus."""
        example = narration._PROMPT.split("TEMPLATE")[1].split("FACTS:")[0].lower()
        for real in ("invoice_scan", "vboxuser", "winvm", "onedrive", "npp.", "11:50", "12:15"):
            assert real not in example, real
        # And no invented instance either: v5 leaked "System", v6 leaked
        # "host-7". Only blanks, so there is no concrete detail to copy.
        for fake in ("updater_x", "alice", "host-7", "07:42", "08:05", "system event"):
            assert fake not in example, fake
        assert "<host>" in example and "<program>" in example

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
