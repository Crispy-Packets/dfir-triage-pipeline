"""Optional, detachable LLM narration of a run.

Design mirrors the scorer registry in `anomaly.py`. The narration layer is:

- **Off by default.** With `DFIR_NARRATION` unset, `narrate()` is never called
  and run.json carries no `narration` key. The gate does not depend on Ollama.
- **Model-agnostic behind a registry.** `DFIR_NARRATION=backend:model` selects a
  backend from a closed `_NARRATOR_REGISTRY` (only `ollama` today; `null` is the
  default no-op). An unknown backend raises rather than silently skipping.
- **Non-authoritative.** The narration is a DERIVED artifact: it is written back
  into run.json BEFORE the manifest is hashed (so the manifest covers it), and
  it can never alter a finding or a verdict. `is_verdict` is false, always.
- **Validated, not trusted.** `citations.py` checks every rule id, executable and
  numeric the prose cites against the facts the model was shown, and records what
  it could not resolve. A model that fabricates a finding is caught mechanically.

The narrator only ever sees `_facts(doc)` -- a small slice of run.json, never raw
evidence. That slice is both the prompt input and the validator's allowed
vocabulary: the model may only cite what it was given.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any, Protocol

from dfir_triage_pipeline.core import citations

#: The spec-string env var. Presence turns narration on. Format `backend:model`,
#: e.g. `ollama:qwen2.5:7b` (the model half may itself contain colons -- only the
#: FIRST colon separates backend from model, so `qwen2.5:7b` survives intact).
NARRATION_FLAG = "DFIR_NARRATION"
#: Default backend is the no-op: unset flag => no narration, no dependency.
DEFAULT_BACKEND = "null"
#: Ollama HTTP endpoint. Overridable for a non-local host.
ENDPOINT_FLAG = "DFIR_NARRATION_ENDPOINT"
DEFAULT_ENDPOINT = "http://localhost:11434"

#: Fixed decode settings -- determinism is a forensic requirement. temperature 0
#: and a fixed seed reproduce on the same model/host; num_ctx is set EXPLICITLY
#: because Ollama's default (2048) silently truncates a longer prompt.
_TEMPERATURE = 0.0
_SEED = 20260830
_NUM_CTX = 8192
_TIMEOUT_S = 300

#: Bump this when the prompt changes; the value is recorded in run.json so a
#: narration can be tied to the exact instruction that produced it.
PROMPT_VERSION = "7"
#: v7: the example is a TEMPLATE with <blanks>, not a made-up instance. Every
#: concrete example leaked into the output: v4's real facts were copied whole,
#: v5 copied "System event log", v6 copied the host "host-7" (the record says
#: winvm). A 7B model copies whatever concrete detail it is shown; a blank
#: carries none, and a blank left in the output is rejected mechanically.
#: v6: findings carry their evidence paths, and the example names no log. v5's
#: example said "the System event log"; the facts never said WHICH log was
#: cleared (the rule title is only "Windows event log cleared"), so the model
#: took "System" from the example. The record says Security.evtx.
#: v5: the worked example uses MADE-UP names, numbers and times. v4's example
#: was written from collection_s1_v3 itself, and the model reproduced it almost
#: verbatim -- a correct output that proved nothing, because the answer was in
#: the prompt. An example must teach the style and carry none of the content.
#: v4: the model is told WHAT each rule found (finding titles, times, entity
#: kind). v3 had only rule ids, so it either listed codes or guessed their
#: meaning ("vboxuser was executed" -- vboxuser is a user account).
#: v3 rewrites the wording rules after the second live run: the model said
#: "ranked first" (record: rank 14 of 443), called percentile 0.0 "less
#: suspicious" (0 is MOST unusual), and merged two fields as "severity score".
#: Ranking prose is now written by code and forbidden here; the rest is
#: wording the record can be checked against.
_PROMPT = (
    "You are a DFIR triage report assistant. Write a concise, factual summary "
    "(<= 200 words) of the triage result described by the JSON facts below.\n"
    "\nWHAT TO WRITE:\n"
    "- LEAD with `verdict_entities`: the highest-priority entity first. Name it, "
    "its priority band, its triage score, and the rule ids that fired on it. "
    "The RULES are what detected it, and that is the point of the summary.\n"
    "- Then the other verdict entities, briefly, highest priority first.\n"
    "- Write 3 to 5 sentences. Say WHAT the rules found, using the `title` of "
    "each entry in `verdict_findings` (rephrase plainly, keep the meaning "
    "exactly), with its rule id in brackets.\n"
    "- An entity of kind 'user account' is never executed or run. Say what "
    "was recorded for that account.\n"
    "- Name a log, file or registry key only as it appears in `evidence`. "
    "Which event log was cleared is in the .evtx file name there.\n"
    "- Give a time only as it appears in `time_utc` (HH:MM UTC). Where "
    "`time_utc` is null, the time is a registry key's last-write time: say "
    "the value is 'present', never when it was created or written.\n"
    "\nWORDING (these are not style preferences):\n"
    "- The number is the TRIAGE SCORE; the label (critical/high/medium) is the "
    "PRIORITY BAND. They are two different fields. Never write 'severity score' "
    "or 'priority score' -- write 'triage score 99 (critical)'.\n"
    "- A triage score is the summed weight of the rules that matched. It marks "
    "where to look first. It is NOT a judgement that the entity is malicious.\n"
    "- Name the entity in every sentence. Never 'this file', 'it' or 'the "
    "binary' carried across a sentence boundary.\n"
    "\nDO NOT:\n"
    "- Do NOT write about the anomaly ranking at all. Ranking sentences are "
    "already written for you and appear verbatim in the report; restating, "
    "paraphrasing or summarising them is an error. Never say an entity is "
    "'first', 'top' or 'ranked' in the anomaly ranking.\n"
    "- You MAY say which entity has the highest triage score; that claim is "
    "checked against the scores below.\n"
    "- Do NOT use order words between findings (then, after, before, later, "
    "followed by, subsequently). The recorded order is not the obvious one; "
    "the report's timeline states it.\n"
    "- Do NOT compare entities by suspicion, risk, safety or unusualness ('less "
    "suspicious', 'more anomalous', 'safer'). Those are not facts in the "
    "record.\n"
    "- Do NOT state intent, motive or attribution ('the attacker wanted', "
    "'designed to evade'). Report what the rules matched, nothing beyond.\n"
    "- Do NOT invent a number, a rule id or a name. Cite only what is below.\n"
    "- Plain prose, no markdown headers.\n"
    "\nTEMPLATE of the required style. Every <blank> must be filled from "
    "FACTS below; never leave a <blank> in your summary, and never add a "
    "detail FACTS does not contain.\n"
    "<program> has the highest triage score in this run (<score>, <band>), "
    "from <n> corpus-validated rules. <program> was executed (last run "
    "<HH:MM> UTC) and is registered to run at logon (<rule id>). For the user "
    "account <user> (triage score <score>, <band>), the <log name> event log "
    "on <host> was cleared at <HH:MM> UTC (<rule id>).\n"
    "\nFACTS:\n"
)

class Narrator(Protocol):
    """A backend that turns the fact slice into prose. One method, so another
    backend (a different local server, a different API) is one class away."""

    name: str

    def generate(self, prompt: str) -> str: ...


class _NullNarrator:
    """The default: narration is off. Never called when the flag is unset, but
    registered so `backend:` of `null` is a valid, explicit no-op."""

    name = "null"

    def generate(self, prompt: str) -> str:  # pragma: no cover - never invoked
        raise RuntimeError("null narrator does not generate; narration is off")


class _OllamaNarrator:
    """Ollama `/api/generate`, stdlib HTTP only (no `ollama` package to install).

    Fails LOUDLY: if the endpoint is unreachable or errors, the exception
    propagates to `narrate()`, which records `status='error'` -- the run is never
    silently left without the narration the operator asked for.
    """

    def __init__(self, model: str, endpoint: str) -> None:
        self.name = "ollama"
        self.model = model
        self.endpoint = endpoint.rstrip("/")

    def generate(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": _TEMPERATURE,
                    "seed": _SEED,
                    "num_ctx": _NUM_CTX,
                },
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.endpoint}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return str(body.get("response", "")).strip()

    def digest(self) -> str | None:
        """The model's digest from `/api/tags`, for provenance. None if the tag
        list cannot be read -- provenance is best-effort, never a hard failure."""
        try:
            req = urllib.request.Request(f"{self.endpoint}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=30) as resp:
                tags = json.loads(resp.read().decode("utf-8"))
            for m in tags.get("models", []):
                if m.get("name") == self.model:
                    return m.get("digest")
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            return None
        return None


def _parse_spec(spec: str) -> tuple[str, str]:
    """`backend:model` -> (backend, model). Only the first colon splits, so an
    Ollama tag like `qwen2.5:7b` keeps its own colon."""
    backend, _, model = spec.partition(":")
    return backend.strip(), model.strip()


#: Closed registry. Adding a backend is adding a builder here -- callers cannot
#: inject one, the same closed-set guarantee the scorer registry gives.
_NARRATOR_REGISTRY: dict[str, Any] = {
    "null": lambda model, endpoint: _NullNarrator(),
    "ollama": lambda model, endpoint: _OllamaNarrator(model, endpoint),
}


def make_narrator(spec: str, endpoint: str) -> Any:
    """Build the narrator named by `spec`, or raise on an unknown backend."""
    backend, model = _parse_spec(spec)
    builder = _NARRATOR_REGISTRY.get(backend)
    if builder is None:
        known = ", ".join(sorted(_NARRATOR_REGISTRY))
        raise ValueError(f"unknown {NARRATION_FLAG} backend {backend!r}; known: {known}")
    if backend != "null" and not model:
        raise ValueError(f"{NARRATION_FLAG}={backend!r} needs a model, e.g. {backend}:qwen2.5:7b")
    return builder(model, endpoint)


def narration_enabled() -> bool:
    """True when a non-null backend is selected."""
    spec = os.environ.get(NARRATION_FLAG, "").strip()
    return bool(spec) and _parse_spec(spec)[0] != "null"


#: Severity order, worst first -- the narration must lead with the worst.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _facts(doc: dict[str, Any]) -> dict[str, Any]:
    """The small, closed slice of run.json the narrator sees and the validator
    allows. Never raw evidence -- only what run.json already asserts.

    Shaped VERDICT-FIRST, deliberately. The first live run (qwen2.5:7b, prompt
    v1) fabricated nothing yet narrated the wrong panel: the fact slice led with
    the anomaly ranking, so the model described benign OS binaries and never
    mentioned the 99/critical entity the rules actually detected. The anomaly
    layer's own measured behaviour is that it RANKS and leads with benign noise
    -- so handing it to a model first guarantees that failure. `entities` (the
    scored verdict panel) leads now; the ranking follows under a key name that
    states what it is not.
    """
    anomalies = doc.get("anomalies", {})
    scored = anomalies.get("scored_entities", [])
    entities = doc.get("entities", []) or []
    findings = doc.get("findings", [])

    # Every scored entity's rank in the anomaly ranking, by name. The model is
    # given the rank of the entities it actually writes about -- NOT a truncated
    # top-N. The first live failure was caused by exactly that truncation:
    # invoice_scan.exe sits at rank 14/443, the slice passed only the top 10, so
    # the model had no rank for the entity it was describing and invented one
    # ("ranked first"). A fact withheld is a fact hallucinated.
    ranks: dict[str, dict[str, Any]] = {}
    for i, e in enumerate(scored, 1):
        name = e.get("entity")
        if name and name not in ranks:
            ranks[name] = {
                "rank": i,
                "of": len(scored),
                "family": e.get("family"),
                "percentile_in_family": e.get("percentile_in_family"),
            }

    ranked = sorted(
        (e for e in entities if e.get("value")),
        key=lambda e: (
            _SEVERITY_RANK.get(str(e.get("severity", "")).lower(), 9),
            -(e.get("score") or 0),
        ),
    )
    verdict_entities = []
    for e in ranked[:10]:
        name = e.get("value")
        item = {
            "entity": name,
            "kind": _KIND.get(str(e.get("key")), "entity"),
            "priority_band": e.get("severity"),
            "triage_score": e.get("score"),
            "rule_ids": e.get("rule_ids", []),
            "techniques": e.get("techniques", []),
        }
        if name in ranks:
            item["anomaly_rank"] = ranks[name]
        verdict_entities.append(item)
    # Fall back to the findings' own entity keys only when the verdict panel is
    # absent (an older run.json), so the validator's vocabulary is never empty.
    if not verdict_entities:
        verdict_entities = [
            {
                "entity": v,
                "priority_band": None,
                "triage_score": None,
                "rule_ids": [],
                "techniques": [],
            }
            for v in sorted(
                {
                    e.get("value")
                    for f in findings
                    for e in f.get("entity_keys", [])
                    if e.get("key") == "entity.exe_name" and e.get("value")
                }
            )
        ]

    return {
        "collection": doc.get("collection", {}).get("name"),
        "scorer": anomalies.get("scorer"),
        "verdict_entities": verdict_entities,
        "rule_ids": sorted({f.get("rule_id") for f in findings if f.get("rule_id")}),
        "verdict_findings": _verdict_findings(findings, verdict_entities),
        # The ranking is NOT handed over as a list to paraphrase. Code writes
        # every ranking sentence (see `ranking_sentences`); the model is told
        # the ranking is off-limits. A fixed template cannot misstate a rank.
        "anomaly_ranking_meaning": anomalies.get("meaning"),
        "ranking_sentences_already_written_do_not_restate": _ranking_sentences(
            verdict_entities, anomalies.get("scorer")
        ),
    }


#: Entity key -> the plain word the model should use. A user account is never
#: "executed"; v3 wrote "vboxuser ... was executed" because it had no kind.
_KIND = {
    "entity.exe_name": "program",
    "entity.user": "user account",
    "entity.host": "host",
}


def _verdict_findings(
    findings: list[dict[str, Any]], verdict_entities: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """What each corpus-validated rule FOUND, for the entities being narrated.

    Without this the model had rule ids and nothing else: it either listed codes
    or guessed what they meant. With it, every sentence can say what happened and
    stay checkable -- the title, time and entities all come from run.json.

    Times: `time_utc` is given only when the finding's time claim is an observed
    one. A presence-only time is a registry key's last-write time, shared with
    its sibling values; it is NOT when the value was written, so it is withheld
    rather than handed to a model that would narrate it as an event time.

    Ordered by rule id, not by time, deliberately: a time-ordered list invites
    a story ("downloaded, then deleted"), and in this corpus the recorded order
    is not the obvious one.
    """
    names = {v.get("entity") for v in verdict_entities if v.get("entity")}
    out: list[dict[str, Any]] = []
    for f in findings:
        if f.get("rule_class") != "corpus-validated":
            continue
        ents = [k.get("value") for k in f.get("entity_keys", []) if k.get("value")]
        if not names.intersection(ents):
            continue
        ts = str(f.get("first_timestamp_utc") or "")
        observed = bool(ts) and f.get("time_claim") not in (None, "none")
        out.append(
            {
                "id": f"F:{f.get('finding_id')}",
                "rule": f.get("rule_id"),
                "title": f.get("title"),
                "entities": ents,
                "date": ts[:10] or None,
                "time_utc": ts[11:16] if observed else None,
                "time_claim": f.get("time_claim"),
                # Where the finding came from. Lets the model name the right
                # log / file / key instead of inventing one, and lets the
                # validator check a named log against the record.
                "evidence": [
                    f"{m.get('source_file')} :: {m.get('source_locator')}"
                    for m in f.get("matched", [])
                    if m.get("source_file")
                ],
            }
        )
    out.sort(key=lambda x: (str(x["rule"]), str(x["date"]), str(x["time_utc"])))
    return out


def _ranking_sentences(verdict_entities: list[dict[str, Any]], scorer: str | None) -> list[str]:
    """The anomaly-ranking prose, written by CODE from the record.

    Taken away from the model deliberately. Two of the three errors in the first
    accepted narration were ranking claims ("ranked first" when the record said
    rank 14 of 443; "percentile 0.0 ... less suspicious" when 0 means MOST
    unusual). A template cannot make either mistake, and it keeps the
    rules-detect / anomalies-rank distinction true by construction.
    """
    out: list[str] = []
    for v in verdict_entities:
        r = v.get("anomaly_rank")
        if not r:
            continue
        out.append(
            f"In the {scorer} anomaly ranking, {v['entity']} is rank {r['rank']} "
            f"of {r['of']} ({r['family']}, percentile {r['percentile_in_family']}; "
            f"0 = most unusual of its kind). This ranks unusualness; it is not a "
            f"detection."
        )
    return out


def narrate(doc: dict[str, Any]) -> dict[str, Any]:
    """Produce the `narration` block for `doc`. Always returns a dict (never
    raises): a backend failure is recorded as `status='error'`, so a run is never
    aborted or silently stripped of a narration the operator requested."""
    spec = os.environ.get(NARRATION_FLAG, "").strip()
    endpoint = os.environ.get(ENDPOINT_FLAG, DEFAULT_ENDPOINT).strip() or DEFAULT_ENDPOINT
    narrator = make_narrator(spec, endpoint)
    backend, model = _parse_spec(spec)

    facts = _facts(doc)
    # NOT sort_keys: the fact slice is ordered verdict-first ON PURPOSE, and
    # alphabetising would put `prioritisation_ranking_not_detections` ahead of
    # `verdict_entities` -- reinstating the exact bug prompt v2 exists to fix.
    # `_facts()` builds a fixed key order, so the prompt stays deterministic.
    prompt = _PROMPT + json.dumps(facts, indent=2)
    block: dict[str, Any] = {
        "is_verdict": False,
        "backend": backend,
        "model": model,
        "endpoint": endpoint.split("//")[-1].split("/")[0],  # host only
        "temperature": _TEMPERATURE,
        "seed": _SEED,
        "prompt_version": PROMPT_VERSION,
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "generated_at": datetime.now(UTC).isoformat(),
    }
    try:
        text = narrator.generate(prompt)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        block["status"] = "error"
        block["error"] = f"{type(exc).__name__}: {exc}"
        return block

    result = citations.validate(text, facts)
    if hasattr(narrator, "digest"):
        block["model_digest"] = narrator.digest()
    block["validation"] = {
        "validated": result.validated,
        "citations": result.citations,
        "unresolvable": result.unresolvable,
        "mentions_scorer": result.mentions_scorer,
        "missing_mentions": result.missing_mentions,
        "describes_ranking_as_detection": result.describes_ranking_as_detection,
        "relation_errors": result.relation_errors,
    }
    if result.validated:
        block["status"] = "accepted"
        block["text"] = text
    else:
        # Rejected prose is kept for audit but namespaced so it can never be
        # read as a finding, and never rendered as an authoritative narration.
        block["status"] = "rejected"
        block["rejected"] = {"text": text}
    return block
