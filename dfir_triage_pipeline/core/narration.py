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
import re
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
PROMPT_VERSION = "12"
#: v12 (2026-09-26): every name carries its KIND. v11's first live run on srv22
#: passed every check and was still wrong twice: it called the server
#: "an account named win-ni9fbk23slo..." added to "a group with the name cn=a
#: admin,..." (roles swapped), and wrote "a program attempted to log in" for
#: remote logons whose only name, an IP address, had been withheld. The model
#: had bare names and guessed what each was. Now each sentence prompt lists
#: SUBJECTS as "name (kind)", a withheld name as its kind alone, and the
#: validator rejects a name used in the wrong role (`role:`) and a "program"
#: or "attempted" the cited title does not support.
#: v11 (2026-09-26): the BRIEFING style -- one model call per finding. Both
#: v9 and v10 live runs on collection_srv22 made the same error in one long
#: answer: the Domain Admins addition cited to R-ATOMIC-0022 (a failed-logon
#: burst) instead of R-ATOMIC-0019, even with `must_cite` and a tightened
#: shape. Deterministic model, same class of error twice: more prompt wording
#: would not remove it. Now the model sees ONE finding at a time and never sees
#: a rule id; code appends the finding's own id, so a wrong pairing cannot be
#: written. The same checks then run per sentence and on the whole text. The
#: precedent is `_ranking_sentences`: code writes what the model gets wrong.
#: v10 (2026-09-26), after live run 1 of v9 on collection_srv22 was rejected:
#: it omitted both of the top entity's findings and cited R-ATOMIC-0022 (a
#: failed-logon burst) for a group addition. The facts now open with
#: `must_cite` -- computed by the validator's own `_required_rules` -- and the
#: SHAPE ties the rule id to the entry whose title was used. Times are each
#: finding's FIRST record and names containing numbers are withheld, because
#: the viewer's re-check verifies nothing else (measured, see
#: `_briefing_findings`). Dates are written only as the facts write them.
#: v9 (2026-09-26): a BRIEFING of what happened, for a non-technical reader,
#: not a verdict. The model now sees `briefing_findings` -- every critical,
#: high and medium finding, validated or not, labelled -- because on a real
#: compromise (collection_srv22) the story lived in unvalidated rules and the
#: model, shown only `admin`, copied action phrases from the template onto
#: facts they did not fit ("the Security event log ... was cleared"; no log
#: was cleared). The template now carries no action words at all.
#: v8: cover every verdict finding on the top entity (v7 omitted the Recycle
#: Bin deletion, R-CORR-0006), and keep each time in the sentence that cites
#: its own rule (v7 put R-CORR-0003's 11:50 next to R-ATOMIC-0006).
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
    "You are writing a short BRIEFING of what happened on a computer, for a "
    "manager who is not a security specialist. It is NOT a verdict: describe "
    "what the records show, never judge it.\n"
    "\nWHAT TO WRITE (3 to 7 sentences, plain words):\n"
    "- Use `briefing_findings` and `verdict_findings`. Each entry is one thing a "
    "rule found: its `title` says WHAT was found, `entities` say about what, "
    "`time_utc` and `date` say when its FIRST record was written "
    "(`also_at_utc` lists further records of the same kind).\n"
    "- Describe each thing in the words of its `title` -- rephrase for a "
    "manager, but never claim an action the title does not name. If a title "
    "says an account was added to a group, do not say it was created; if a "
    "title says a program was inventoried, do not say it ran.\n"
    "- Put the rule id in brackets after each thing, e.g. (R-CORR-0007).\n"
    "- Every rule id in `must_cite` MUST appear in your briefing, in brackets, "
    "each in a sentence built from an entry with that `rule`.\n"
    "- Give times as `HH:MM UTC on YYYY-MM-DD`, copied exactly from `time_utc` "
    "and `date` (never write a month name). "
    "Where a finding has no `time_utc`, give no time for it.\n"
    "- A finding with `class` 'not yet validated' is a real record from a rule "
    "that has not been measured on clean systems; you may say so.\n"
    "\nDO NOT:\n"
    "- Do NOT use judgement words -- attacker, malicious, malware, hacker, "
    "compromised, breach, criminal, infected -- unless a finding's `title` uses them.\n"
    "- Do NOT state counts or numbers other than times, dates and triage scores "
    "given in the facts.\n"
    "- Do NOT use order or simultaneity words between findings (then, after, "
    "before, later, followed by, at the same time, meanwhile). Each sentence "
    "carries its own time; the reader sees the order.\n"
    "- Do NOT write network addresses, account SIDs or version numbers.\n"
    "- Do NOT mention the anomaly ranking.\n"
    "- Do NOT invent a name, rule id, time, host or event-log name.\n"
    "- Plain prose, no headings, no lists.\n"
    "\nSHAPE of each sentence (a pattern, not words to copy):\n"
    "<when> -- <who or what> -- <what the entry's title says> (<that same entry's rule>).\n"
    "\nFACTS:\n"
)

#: One repair attempt, no more. When the first narration is rejected, the model
#: is shown its own text and the validator's exact reasons, and asked to fix
#: them. Prompt v8 showed that adding general rules changed nothing (the output
#: was byte-identical to v7); specific, per-error feedback is what a small model
#: can act on. Bounded at one so a model cannot be ground at until it happens to
#: pass -- and BOTH attempts are recorded, so the retry is visible, not hidden.
MAX_REPAIRS = 1
_REPAIR_PROMPT = (
    "\n\nYOUR PREVIOUS SUMMARY:\n{text}\n\n"
    "It was REJECTED by the fact checker. Every reason below is a real error "
    "in that summary:\n{reasons}\n\n"
    "Rewrite the summary so that every reason is fixed, following every rule "
    "above. Output only the new summary.\n"
)


#: Which way the prose is produced. "briefing" (v11, default): one call per
#: finding, rule id attached by code. "single": the v10 one-shot prompt over
#: the whole fact slice -- kept because its tests pin the repair and bounding
#: behaviour, and so the two can be compared on one run.
STYLE_FLAG = "DFIR_NARRATION_STYLE"
_STYLES = ("briefing", "single")

#: Cap on sentences: 12 covers every distinct critical/high/medium rule on
#: collection_srv22 (11 rules, R-CORR-0007 twice) -- the whole story, entry to
#: payload -- and at CPU speed keeps the narration to a few minutes.
_SENTENCE_CAP = 12

_SENTENCE_PROMPT = (
    "Rewrite ONE record from a computer's history as ONE plain English sentence "
    "for a manager who is not a security specialist. Describe it; do not judge it.\n"
    "\nRULES:\n"
    "- {start}\n"
    "- Say what the TITLE says, in plain words. Never claim an action the TITLE "
    "does not name.\n"
    "- SUBJECTS lists each name with what it IS. Copy names exactly, and use "
    "each only as what it is: a computer is never an account, an account is "
    "never a group, a network address is never a program. A subject shown "
    "without a name is described only by its kind (e.g. 'one network address'). "
    "If there are no SUBJECTS, do not invent one. Never write 'unknown'.\n"
    "- No judgement words: attacker, malicious, malware, hacker, compromised, "
    "breach, criminal, infected.\n"
    "- No numbers except the time and date given above. No network addresses.\n"
    "- Do not mention any other event, and no order words (then, after, before, "
    "later, meanwhile, at the same time) unless the TITLE itself uses them.\n"
    "- Exactly one sentence. No codes, no brackets, no quotation marks. Do not "
    "start with 'It', 'This' or 'That'.\n"
    "\nTITLE: {title}\n"
    "SUBJECTS: {names}\n"
    "{also}"
    "\nSentence:"
)
_SENTENCE_REPAIR = (
    "\n\nYOUR SENTENCE:\n{text}\n\nIt was REJECTED by the fact checker for:\n"
    "{reasons}\n\nWrite the sentence again with every reason fixed, following "
    "every rule above. Output only the sentence.\n"
)
#: Results that judge the WHOLE text, not one sentence; ignored when a single
#: sentence is checked, and applied in full when the sentences are joined.
_WHOLE_TEXT_ONLY = ("missing_finding:", "missing:", "too_short:")


def narration_style() -> str:
    style = os.environ.get(STYLE_FLAG, "").strip().lower() or "briefing"
    if style not in _STYLES:
        raise ValueError(f"{STYLE_FLAG}={style!r}: expected one of {', '.join(_STYLES)}")
    return style


def _sentence_entries(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """Which findings get a sentence -- chosen by CODE, deterministically.

    Every entry whose rule is in `must_cite` (the validator will require it),
    then one entry for each remaining rule in severity order, up to
    `_SENTENCE_CAP` in total. Printed in time order, untimed entries last; each
    sentence carries its own time, so the order is the record's, not a claim.
    """
    must = set(facts.get("must_cite", []))
    pool = list(facts.get("verdict_findings", [])) + list(facts.get("briefing_findings", []))
    seen: set[tuple] = set()
    chosen: list[dict[str, Any]] = []

    def take(e: dict[str, Any]) -> None:
        key = (e.get("rule"), tuple(e.get("entities", []) or []), e.get("date"), e.get("time_utc"))
        if key not in seen and e.get("rule") and e.get("title"):
            seen.add(key)
            chosen.append(e)

    for e in pool:
        if e.get("rule") in must:
            take(e)
    # Then ONE entry per remaining rule -- its first in severity-then-time
    # order. Measured on srv22: capping entries instead let three RDP-logon
    # entries crowd out the Domain Admins addition and the payload.
    ruled = {e.get("rule") for e in chosen}
    for e in facts.get("briefing_findings", []):
        if len(chosen) >= max(_SENTENCE_CAP, len(must)):
            break
        if e.get("rule") not in ruled:
            take(e)
            ruled.add(e.get("rule"))
    chosen.sort(key=lambda e: (e.get("date") is None, str(e.get("date")), str(e.get("time_utc"))))
    return chosen


def _sentence_prompt(e: dict[str, Any]) -> str:
    if e.get("time_utc") and e.get("date"):
        start = f"Start with exactly: At {e['time_utc']} UTC on {e['date']},"
    else:
        start = "Give no time or date: the record carries none."
    names = [
        f"{sj['name']} (a {sj['kind']})" if sj.get("name") else f"one {sj['kind']} (not named)"
        for sj in e.get("subjects", []) or []
    ]
    also = ""
    if e.get("also_at_utc"):
        also = "ALSO RECORDED AT (you may mention): " + "; ".join(
            f"{t.replace(' on ', ' UTC on ')}" for t in e["also_at_utc"]
        ) + "\n"
    return _SENTENCE_PROMPT.format(
        start=start, title=e.get("title"), names="; ".join(names) or "(none)", also=also
    )


def _attach_rule(text: str, rule: str) -> str:
    """First line only, quotes and any rule-like code the model added removed,
    then the finding's OWN rule id appended by code."""
    line = next((ln.strip() for ln in str(text).splitlines() if ln.strip()), "")
    line = line.strip().strip('"').strip("'").strip()
    line = re.sub(r"\s*\(?\bR-(?:ATOMIC|CORR)-\d{4}\b\)?", "", line).strip()
    # The SUBJECTS labels are for the model, not the reader; v12 copied them
    # ("sysinternalssuite.zip (a file)", "one account (not named)").
    line = re.sub(
        r"\s*\((?:an?\s+(?:account|computer|program|file|network address|item)|not named)\)",
        "", line,
    )
    line = line.rstrip(" .")
    return f"{line} ({rule})."


def _sentence_problems(sentence: str, facts: dict[str, Any]) -> list[str]:
    r = citations.validate(sentence, facts)
    return [u for u in r.unresolvable if not u.startswith(_WHOLE_TEXT_ONLY)]


def _narrate_briefing(narrator: Any, facts: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """One call per finding, one repair per sentence. Returns the joined text
    and a per-sentence audit. A sentence still failing after its repair is
    dropped and recorded; if its rule was required, the whole-text check then
    rejects the narration -- honest, never patched over."""
    must = set(facts.get("must_cite", []))
    sentences: list[str] = []
    audit: list[dict[str, Any]] = []
    for e in _sentence_entries(facts):
        prompt = _sentence_prompt(e)
        text = _attach_rule(narrator.generate(prompt), e["rule"])
        problems = _sentence_problems(text, facts)
        tries = [{"text": text, "unresolvable": problems}]
        if problems:
            repair = _SENTENCE_REPAIR.format(
                text=text, reasons="\n".join(f"- {u}" for u in problems)
            )
            text = _attach_rule(narrator.generate(prompt + repair), e["rule"])
            problems = _sentence_problems(text, facts)
            tries.append({"text": text, "unresolvable": problems})
        audit.append({
            "finding": e.get("id"),
            "rule": e["rule"],
            "required": e["rule"] in must,
            "kept": not problems,
            "attempts": tries,  # audit only, never render a rejected attempt
        })
        if not problems:
            sentences.append(text)
    return " ".join(sentences), audit


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

    verdict_findings = _verdict_findings(findings, verdict_entities)
    facts = {
        "collection": doc.get("collection", {}).get("name"),
        "scorer": anomalies.get("scorer"),
        "verdict_entities": verdict_entities,
        "rule_ids": sorted({f.get("rule_id") for f in findings if f.get("rule_id")}),
        "verdict_findings": verdict_findings,
        "briefing_findings": _briefing_findings(
            findings, exclude={v["id"] for v in verdict_findings}
        ),
        # The ranking is NOT handed over as a list to paraphrase. Code writes
        # every ranking sentence (see `ranking_sentences`); the model is told
        # the ranking is off-limits. A fixed template cannot misstate a rank.
        "anomaly_ranking_meaning": anomalies.get("meaning"),
        "ranking_sentences_already_written_do_not_restate": _ranking_sentences(
            verdict_entities, anomalies.get("scorer")
        ),
    }
    # First key, so a 7B model meets it before the findings.
    return {"must_cite": _must_cite(facts), **facts}


#: Entity key -> the plain word the model should use. A user account is never
#: "executed"; v3 wrote "vboxuser ... was executed" because it had no kind.
_KIND = {
    "entity.exe_name": "program",
    "entity.user": "user account",
    "entity.host": "host",
}


#: What each entity key IS, in the words a sentence may use for it.
_SUBJECT_KIND = {
    "entity.user": "account",
    "entity.host": "computer",
    "entity.src_ip": "network address",
}
_PROGRAM_EXT = (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".msi", ".scr", ".com")


def _subjects(f: dict[str, Any]) -> list[dict[str, Any]]:
    """Each entity of a finding as {"name", "kind"}. A name containing a number
    (IP address, SID, versioned file) is withheld -- `name` None -- because the
    viewer cannot verify it; its kind is kept, so the sentence can still say
    "from one network address" instead of guessing "a program"."""
    out: list[dict[str, Any]] = []
    for k in f.get("entity_keys", []) or []:
        value = str(k.get("value") or "")
        if not value:
            continue
        key = str(k.get("key") or "")
        if key == "entity.exe_name":
            kind = "program" if value.lower().endswith(_PROGRAM_EXT) else "file"
        else:
            kind = _SUBJECT_KIND.get(key, "item")
        name = None if _NUMBER_IN_NAME_RE.search(value) else value
        if name is None and key == "entity.user":
            kind = "account"
        out.append({"name": name, "kind": kind})
    return out


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
                "subjects": _subjects(f),
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


_BRIEF_SEVERITIES = ("critical", "high", "medium")
_BRIEF_CAP = 20


def _briefing_findings(
    findings: list[dict[str, Any]], exclude: set[str]
) -> list[dict[str, Any]]:
    """Every critical/high/medium finding, validated or not, for the briefing.

    Added for prompt v9. `verdict_findings` holds only corpus-validated rules, and
    on a real compromise (collection_srv22) the story -- the guessed password,
    the Domain Admins addition, the payload -- is in rules that are not yet
    validated. Each entry carries its `class` so the model can say so, and its
    `title` so the claim check can hold every sentence to what the rule found.

    Times: `time_utc` is the finding's FIRST observed event -- the one time the
    viewer can verify, because its re-check reads `first_timestamp_utc` and
    nothing else. Measured on srv22: every "last" time (a chain's success, the
    end of a run of logons) was withheld by the viewer. Presence-only events
    carry no time, for the reason `_verdict_findings` states.

    Deduplicated on (rule, entities): one registry value seen in a hive and its
    RegBack copy is one thing to tell a reader, not two. Duplicates are MERGED:
    each merged finding's own first time is kept in `also_at_utc`, so srv22's
    two group additions (Administrators 23:02, Domain Admins 23:24 -- same
    entity keys) keep both.

    Names containing a number (IP addresses, SIDs, "nmap-7.93-setup.exe") are
    left out of `entities`: the viewer cannot tie a number inside a name to a
    record and withholds the prose (measured). The title still says what the
    finding is; the reader loses the address, not the fact.
    """
    rank = {"critical": 0, "high": 1, "medium": 2}
    groups: dict[tuple, tuple[dict[str, Any], str, list[str], list[str]]] = {}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        fid = f"F:{f.get('finding_id')}"
        if sev not in _BRIEF_SEVERITIES or fid in exclude:
            continue
        ents = [k.get("value") for k in f.get("entity_keys", []) if k.get("value")]
        key = (f.get("rule_id"), tuple(sorted(ents)))
        group = groups.setdefault(key, (f, sev, ents, []))
        observed = sorted(
            str(m.get("timestamp_utc"))
            for m in f.get("matched", [])
            if m.get("timestamp_utc") and m.get("timestamp_type") != "presence"
        )
        if observed:
            group[3].append(observed[0][:16])
    out: list[dict[str, Any]] = []
    for f, sev, ents, times in groups.values():
        firsts = sorted(set(times))
        entry: dict[str, Any] = {
            "id": f"F:{f.get('finding_id')}",
            "rule": f.get("rule_id"),
            "title": f.get("title"),
            "severity": sev,
            "class": "validated" if f.get("rule_class") == "corpus-validated"
            else "not yet validated",
            "entities": [e for e in ents if not _NUMBER_IN_NAME_RE.search(str(e))],
            "subjects": _subjects(f),
            "date": firsts[0][:10] if firsts else None,
            "time_utc": firsts[0][11:16] if firsts else None,
        }
        if len(firsts) > 1:
            entry["also_at_utc"] = [f"{t[11:16]} on {t[:10]}" for t in firsts[1:]]
        out.append(entry)
    out.sort(key=lambda e: (rank.get(e["severity"], 9), str(e["date"]), str(e["time_utc"])))
    return out[:_BRIEF_CAP]


#: A number the viewer would read inside a name -- its `NUM_RE`, verbatim.
_NUMBER_IN_NAME_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w])")


def _must_cite(facts: dict[str, Any]) -> list[str]:
    """The rule ids the validator will require, computed by the validator's own
    function, so the prompt and the check cannot drift apart. Live run 1 of v9
    omitted both of the top entity's findings; a 7B model does not reliably
    derive "highest-priority entity -> its rules" from the facts alone."""
    return sorted(citations._required_rules(facts))


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

    style = narration_style()
    facts = _facts(doc)
    # NOT sort_keys: the fact slice is ordered verdict-first ON PURPOSE, and
    # alphabetising would put the ranking sentences ahead of
    # `verdict_entities` -- the ordering bug prompt v2 was written to fix.
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
        "style": style,
        "prompt_sha256": hashlib.sha256(
            (prompt if style == "single" else _SENTENCE_PROMPT + _SENTENCE_REPAIR).encode("utf-8")
        ).hexdigest(),
        # The exact facts the model saw, so a narration can be tied to its input
        # without re-deriving the slice.
        "facts_sha256": hashlib.sha256(
            json.dumps(facts, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        # Written by CODE from the record, not by the model -- the viewer renders
        # them under the AI summary with their own label. Present in every state
        # (they do not depend on the model), so a withheld summary still leaves
        # the ranking context on screen.
        "ranking_sentences": facts["ranking_sentences_already_written_do_not_restate"],
        "generated_at": datetime.now(UTC).isoformat(),
    }
    try:
        attempts: list[dict[str, Any]] = []
        if style == "briefing":
            text, block["sentences"] = _narrate_briefing(narrator, facts)
            result = citations.validate(text, facts)
            block["attempts"] = sum(len(a["attempts"]) for a in block["sentences"])
            _finish(block, narrator, result, text)
            return block
        text = narrator.generate(prompt)
        result = citations.validate(text, facts)
        for _ in range(MAX_REPAIRS):
            if result.validated:
                break
            # Audit only -- rejected prose, like `rejected.text`, is never
            # rendered. Kept so a reader can see what the repair changed.
            attempts.append({"text": text, "unresolvable": result.unresolvable})
            repair = _REPAIR_PROMPT.format(
                text=text, reasons="\n".join(f"- {u}" for u in result.unresolvable)
            )
            text = narrator.generate(prompt + repair)
            result = citations.validate(text, facts)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        block["status"] = "error"
        block["error"] = f"{type(exc).__name__}: {exc}"
        return block

    # How many generations it took, and every rejected attempt before the last.
    block["attempts"] = len(attempts) + 1
    if attempts:
        block["repair"] = {
            "reason": "first narration rejected; one repair with the checker's reasons",
            "rejected_attempts": attempts,  # audit only, never render
        }
    _finish(block, narrator, result, text)
    return block


def _finish(block: dict[str, Any], narrator: Any, result: Any, text: str) -> None:
    """Record the validation and the outcome -- shared by both styles."""
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
