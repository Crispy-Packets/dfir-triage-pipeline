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
PROMPT_VERSION = "2"
_PROMPT = (
    "You are a DFIR triage report assistant. Write a concise, factual narration "
    "(<= 200 words) of the triage result described by the JSON facts below. "
    "Rules:\n"
    "- LEAD with `verdict_entities`: the highest-severity entity first, naming its "
    "severity, its score, and the rule ids that fired on it. This is the detection "
    "and it is the point of the narration.\n"
    "- `prioritisation_ranking_not_detections` is SECONDARY context: an ordering "
    "the anomaly scorer produced to prioritise analyst attention. Describe it as a "
    "ranking only. Never say the anomaly layer detected, flagged or identified "
    "anything -- the RULES detect, the anomaly layer only RANKS.\n"
    "- Mention the ranking only after the verdict, and only briefly.\n"
    "- Refer to entities ONLY by their name as written in the facts.\n"
    "- Cite rule ids (e.g. R-CORR-0001) and numbers (scores, percentiles) EXACTLY "
    "as they appear in the facts. Invent nothing. Do not characterise activity the "
    "facts do not describe.\n"
    "- Name the anomaly scorer that produced the ranking.\n"
    "- Plain prose, no markdown headers.\n\nFACTS:\n"
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

    ranked = sorted(
        (e for e in entities if e.get("value")),
        key=lambda e: (
            _SEVERITY_RANK.get(str(e.get("severity", "")).lower(), 9),
            -(e.get("score") or 0),
        ),
    )
    verdict_entities = [
        {
            "entity": e.get("value"),
            "severity": e.get("severity"),
            "score": e.get("score"),
            "rule_ids": e.get("rule_ids", []),
            "techniques": e.get("techniques", []),
        }
        for e in ranked[:10]
    ]
    # Fall back to the findings' own entity keys only when the verdict panel is
    # absent (an older run.json), so the validator's vocabulary is never empty.
    if not verdict_entities:
        verdict_entities = [
            {"entity": v, "severity": None, "score": None, "rule_ids": [], "techniques": []}
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
        "prioritisation_ranking_not_detections": [
            {
                "entity": e.get("entity"),
                "family": e.get("family"),
                "percentile_in_family": e.get("percentile_in_family"),
            }
            for e in scored[:10]
        ],
    }


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
