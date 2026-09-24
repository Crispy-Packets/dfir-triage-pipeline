"""Citation validator for narration prose. Decoupled from any model.

`validate(text, facts)` extracts every rule id, executable name and salient
number the prose cites and checks each against `facts` -- the exact slice of
run.json the narrator was shown. Anything it cannot resolve to the facts is a
potential fabrication and is reported in `unresolvable`.

This runs on ANY narrator's output; it never imports or knows about a backend.
That separation is the point: the model is untrusted, the check is fixed.

The check has two halves, and the second exists because the first was not
enough:

- **Precision** -- nothing cited is fabricated. Every rule id, executable and
  salient number resolves to `facts`.
- **Completeness** -- the thing that matters is actually there. The first live
  narration (qwen2.5:7b) fabricated nothing and still failed: it omitted the
  99/critical entity entirely and described the anomaly ranking instead. A
  precision-only validator accepted it. `required_mentions` closes that: every
  `critical` verdict entity (or the top-scoring one if none is critical) must
  appear in the prose, or the narration is rejected.

Scope, stated honestly: the validator catches fabricated RULE IDS, EXECUTABLE
names and salient NUMBERS (percentiles, ranks, scores), and omission of the
top verdict entity. It does not police free-text that matches none of those
patterns -- the prompt constrains the model to refer to entities only by name,
which is what keeps the surface small enough to check mechanically. A
`validated` narration is one whose checkable citations all resolve and which
names the verdict, not a guarantee of perfect prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Rule ids: the same shape validate_rules.py enforces (R-ATOMIC/CORR/TEST-NNNN).
_RULE_RE = re.compile(r"\bR-(?:ATOMIC|CORR|TEST)-\d{4}\b")
#: Executable tokens. Lowercased before comparison; entity keys are lowercase.
_EXE_RE = re.compile(r"\b[\w.\-]+\.exe\b", re.IGNORECASE)
#: Salient numbers: a percentile/score/rank. Matches `14`, `1.0`, `1/443`, `99`.
#: Only numbers ADJACENT to a triage word or symbol are checked, to avoid
#: flagging incidental digits (a year, a count) the facts need not contain.
_NUM_RE = re.compile(
    r"(?<![\w.])(\d+(?:\.\d+)?)\s*(?:%|percentile|/\s*\d+|score|rank)",
    re.IGNORECASE,
)
#: The same numbers written the other way round -- `percentile of 0.0986`,
#: `score of 99`, `rank 14`. The first live run wrote `a percentile of 0.0986`,
#: which `_NUM_RE` could not see, so the number went unchecked.
_NUM_RE_SUFFIX = re.compile(
    r"\b(?:percentile|score|rank)\s+(?:of\s+)?(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
#: Backwards attribution: the anomaly layer described as if it DETECTED. This is
#: the project's own two-panel rule stated as a check -- rules detect, the
#: anomaly layer ranks. Non-fatal: recorded as a flag, not a rejection, because
#: the phrasing space is open-ended and a regex cannot own a verdict.
_DETECT_CONFUSION_RE = re.compile(
    r"anomal\w+(?:\s+\w+){0,3}?\s+(?:detect|flagg?|identif)\w*",
    re.IGNORECASE,
)


#: Rank claims. A rank is an ENUMERABLE field -- 443 positions in this run -- so
#: a claim about it is checkable against the record, which is why these exist.
#: Ported from Person A's reference checker (viewer side, 2026-09-23) after it
#: rejected a narration this validator had accepted.
_RANK_WORD_RE = re.compile(r"\b(rank(?:ed|ing)?|place[ds]?|position)\b", re.IGNORECASE)
_SUPERLATIVE_RE = re.compile(
    r"\b(first|1st|top|highest|leading|number one|#1)\b", re.IGNORECASE
)
_RANK_N_RE = re.compile(r"\brank(?:ed)?\s+(?:#\s*)?(\d+)\b", re.IGNORECASE)
#: Comparative suspicion. The anomaly layer orders UNUSUALNESS; it does not grade
#: suspicion, so any such comparison is an assertion the record cannot support.
_COMPARISON_RE = re.compile(
    r"\b(less|more|least|most)\s+(suspicious|unusual|anomalous|malicious|dangerous|"
    r"risky|benign|concerning)\b|\bsafer\b|\bconsidered (?:benign|safe)\b",
    re.IGNORECASE,
)
#: "severity score" merges two distinct fields: the triage score (a number) and
#: the severity band (critical/high/...). Saying it as one invites the reader to
#: treat a rule-weight sum as a judgement of maliciousness.
_SEVERITY_SCORE_RE = re.compile(r"\b(?:severity|priority) score\b", re.IGNORECASE)
#: Superlatives about the triage score itself -- "the highest triage score",
#: "second-highest", "the lowest ... score". No rank word is present, so
#: `_RANK_WORD_RE` does not see them, but they are still ordering claims over an
#: enumerable field. They are VERIFIED against the recorded scores, not banned:
#: v3 banned them and so rejected true statements ("the highest triage score"
#: of 99 is simply true). "among the high-band entities" narrows the set.
_SCORE_SUPERLATIVE_RE = re.compile(
    r"\b(?:the\s+)?(?:second|third)?[-\s]?(?:highest|lowest|greatest|largest|"
    r"smallest|top|biggest)\s+(?:triage\s+)?(?:score|priority|band)\b",
    re.IGNORECASE,
)
_BAND_QUALIFIER_RE = re.compile(r"\bamong (?:the )?(\w+)[-\s]band\b", re.IGNORECASE)
#: Order words between findings. Checking a claimed order needs timestamps
#: on both sides and a rule for presence-only times; until that exists, order
#: is the report timeline's job and any order word from the model is refused.
#: The corpus shows why: invoice_scan.exe's Recycle Bin deletion is recorded at
#: 10:30, BEFORE its download at 10:44 -- a model telling a story reverses it.
_ORDER_WORD_RE = re.compile(
    r"\b(then|afterwards?|subsequently|followed by|later|after which|prior to|"
    r"before|after)\b",
    re.IGNORECASE,
)
#: A sentence that opens with a pronoun refers back to the previous subject.
_PRONOUN_START_RE = re.compile(
    # A bare "The ..." is NOT a back-reference ("The Security event log was
    # cleared" is about the log, not the previous entity). "The" counts only
    # with a noun that stands for an entity: "The file", "The entity".
    r"^\s*(?:it\b|this\b(?:\s+(?:file|binary|entity|program|executable|"
    r"installer|account|user)\b)?|(?:the|that|these)\s+(?:file|binary|entity|"
    r"program|executable|installer|account|user)\b)",
    re.IGNORECASE,
)
#: Execution said of an entity. Checked only when the subject is a user
#: account: v3 wrote "vboxuser ... This entity was executed", and a user
#: account is never executed. The entity's kind comes from run.json.
_EXECUTED_RE = re.compile(
    r"\b(?:was|were|is|has been|been)\s+(?:executed|run|launched|started)\b|\bran\b",
    re.IGNORECASE,
)
#: A named Windows event log. Checked against the .evtx FILE NAMES in the
#: findings' evidence -- not the whole path, which for every log contains
#: `System32` and would make "System event log" look valid. v5 wrote
#: "System event log" for a clear recorded in Security.evtx.
_LOG_NAME_RE = re.compile(
    r"\b(Security|System|Application|Setup|PowerShell|Sysmon|Windows PowerShell)"
    r"\s+(?:event\s+)?log\b",
    re.IGNORECASE,
)
#: The host an event log lives on. v6 wrote "an event log on host-7" -- a host
#: from the prompt's example; the record says winvm. It must be a host the
#: findings name.
_LOG_HOST_RE = re.compile(
    r"\blog\s+on\s+(?:the\s+)?(?:host\s+|machine\s+)?([A-Za-z][\w\-]*)",
    re.IGNORECASE,
)
#: Words that follow "log on the host" without being a host name. v7 wrote
#: "the Security event log on the host was cleared" -- vague, not false -- and
#: the check first read "was" as the host.
_NOT_A_HOST = {
    "was", "were", "is", "has", "had", "and", "at", "which", "that", "where",
    "host", "machine", "system", "computer", "device", "endpoint", "it",
}
#: A template blank left unfilled, e.g. `<host>`. The prompt's example is a
#: template; a blank surviving into the prose means a fact was not supplied.
_BLANK_RE = re.compile(r"<[a-z][a-z :_\-]{0,20}>", re.IGNORECASE)
#: Clock times and dates stated in prose. Each must be one the record holds.
_TIME_RE = re.compile(r"\b([01]?\d|2[0-3]):([0-5]\d)\b")
_DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
#: Sentence split, for subject carry-over: "invoice_scan.exe ... It is ranked
#: first" -- the second sentence names nothing, so it inherits the last subject.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


@dataclass
class ValidationResult:
    validated: bool
    citations: dict[str, list[str]]
    unresolvable: list[str]
    mentions_scorer: bool
    numbers_checked: list[str] = field(default_factory=list)
    #: Verdict entities the prose was required to name and did not. Non-empty
    #: means rejection: the narration omitted the detection.
    missing_mentions: list[str] = field(default_factory=list)
    #: True when the prose credits the anomaly layer with detecting. Advisory.
    describes_ranking_as_detection: bool = False
    #: Relation-level failures: a rank claim contradicting the record, a
    #: comparison of suspicion, or the merged "severity score" phrasing. Fatal.
    relation_errors: list[str] = field(default_factory=list)


def _verdicts(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """`verdict_entities` as dicts. Tolerates the old flat list-of-names shape so
    an older fact slice still validates."""
    out: list[dict[str, Any]] = []
    for v in facts.get("verdict_entities", []) or []:
        out.append({"entity": v} if isinstance(v, str) else v)
    return out


def _ranking(facts: dict[str, Any]) -> list[dict[str, Any]]:
    return facts.get("prioritisation_ranking_not_detections") or facts.get("top_anomalies") or []


def _allowed_rule_ids(facts: dict[str, Any]) -> set[str]:
    allowed = {r for r in facts.get("rule_ids", []) if r}
    for v in _verdicts(facts):
        allowed.update(r for r in v.get("rule_ids", []) or [] if r)
    allowed.update(f.get("rule") for f in facts.get("verdict_findings", []) or [] if f.get("rule"))
    return allowed


def _allowed_exes(facts: dict[str, Any]) -> set[str]:
    exes = {v.get("entity") for v in _verdicts(facts)}
    exes.update(a.get("entity") for a in _ranking(facts))
    return {e.lower() for e in exes if e}


def _allowed_numbers(facts: dict[str, Any]) -> set[str]:
    """Every number the prose is permitted to state, as normalised strings."""
    allowed: set[str] = set()
    fc = facts.get("finding_count")
    if fc is not None:
        allowed.add(_norm(fc))
    for v in _verdicts(facts):
        for key in ("triage_score", "score"):
            if v.get(key) is not None:
                allowed.add(_norm(v[key]))
        r = v.get("anomaly_rank") or {}
        for key in ("rank", "of", "percentile_in_family"):
            if r.get(key) is not None:
                allowed.add(_norm(r[key]))
    for a in _ranking(facts):
        pct = a.get("percentile_in_family")
        if pct is not None:
            allowed.add(_norm(pct))
    return allowed


def _required_mentions(facts: dict[str, Any]) -> set[str]:
    """The entities the narration MUST name: every `critical` verdict entity, or
    the single top-scoring one when nothing is critical. This is the recall half
    -- a narration that omits the detection is not a narration of the run."""
    verdicts = _verdicts(facts)
    critical = [
        v["entity"]
        for v in verdicts
        if v.get("entity")
        and str(
            v.get("priority_band") or v.get("severity_band") or v.get("severity") or ""
        ).lower()
        == "critical"
    ]
    if critical:
        return {e.lower() for e in critical}
    scored = [
        v
        for v in verdicts
        if v.get("entity") and (v.get("triage_score") or v.get("score")) is not None
    ]
    if scored:
        top = max(scored, key=lambda v: v.get("triage_score") or v.get("score") or 0)
        return {str(top["entity"]).lower()}
    return set()


def _norm(n: Any) -> str:
    """Normalise a number so `1.0`, `1`, and `1.00` compare equal."""
    try:
        f = float(n)
    except (TypeError, ValueError):
        return str(n).strip()
    return str(int(f)) if f == int(f) else str(f)


def _recorded_ranks(facts: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Each verdict entity's recorded anomaly rank, keyed by lowercased name.

    A rank is an ENUMERABLE field: there are exactly `of` positions, and the
    record names one. That is what makes a rank claim checkable at all, and it
    is why these checks can exist while a claim about intent cannot.
    """
    out: dict[str, dict[str, Any]] = {}
    for v in _verdicts(facts):
        name = v.get("entity")
        rank = v.get("anomaly_rank")
        if name and rank:
            out[str(name).lower()] = rank
    return out


def _known_names(facts: dict[str, Any]) -> list[str]:
    """Every entity name the prose may use as a subject, lowercased, longest
    first so `onedrive.exe` is not found inside `onedrivesetup.exe`."""
    names = {str(v["entity"]).lower() for v in _verdicts(facts) if v.get("entity")}
    names.update(str(a["entity"]).lower() for a in _ranking(facts) if a.get("entity"))
    return sorted(names, key=len, reverse=True)


def _subjects(sent: str, known: list[str]) -> list[str]:
    """Entity names in a sentence, in the order they appear. Covers non-program
    entities (a user account like `vboxuser`) that the `.exe` pattern misses."""
    low = sent.lower()
    found: list[tuple[int, str]] = []
    taken: list[tuple[int, int]] = []
    for name in known:
        for m in re.finditer(r"(?<![\w.\-])" + re.escape(name) + r"(?![\w\-])", low):
            span = (m.start(), m.end())
            if any(a < span[1] and span[0] < b for a, b in taken):
                continue
            taken.append(span)
            found.append((m.start(), name))
    for m in _EXE_RE.finditer(low):
        if not any(a < m.end() and m.start() < b for a, b in taken):
            found.append((m.start(), m.group(0)))
    return [n for _, n in sorted(found)]


def _score_position(
    facts: dict[str, Any], name: str, band: str | None, lowest: bool
) -> tuple[int, int] | None:
    """(position, of) of `name` among verdict entities by triage score, 1-based,
    counting from the top (or the bottom when `lowest`), ties sharing a place."""
    rows = []
    for v in _verdicts(facts):
        score = v.get("triage_score", v.get("score"))
        vband = str(v.get("priority_band") or v.get("severity_band") or v.get("severity") or "")
        if v.get("entity") is None or score is None:
            continue
        if band and vband.lower() != band.lower():
            continue
        rows.append((str(v["entity"]).lower(), score))
    mine = [sc for n, sc in rows if n == name]
    if not mine:
        return None
    better = {sc for _, sc in rows if (sc < mine[0] if lowest else sc > mine[0])}
    return len(better) + 1, len(rows)


def _leading_subject(sent: str, known: list[str], previous: str | None) -> str | None:
    """The grammatical subject of a sentence, when it can be told mechanically:
    a known entity name the sentence opens with, or -- if it opens with a
    pronoun ("It", "This entity") -- the previous sentence's subject. Otherwise
    None, and subject-dependent checks are skipped rather than guessed."""
    low = sent.strip().lower()
    if low.startswith("the "):
        low_rest = low[4:]
    else:
        low_rest = low
    for name in known:
        if low.startswith(name) or low_rest.startswith(name):
            return name
    # "The user account vboxuser ..." opens with what looks like a pronoun
    # phrase but names its subject at once. A known name within the first few
    # words is the subject; only a sentence that names nobody early inherits
    # the previous one. v5 was wrongly rejected for exactly this.
    head = " ".join(low.split()[:5])
    early = [n for n in known if re.search(r"(?<![\w.\-])" + re.escape(n) + r"(?![\w\-])", head)]
    if early:
        return min(early, key=head.find)
    if _PRONOUN_START_RE.match(sent):
        return previous
    return None


def _entity_kind(facts: dict[str, Any], name: str) -> str | None:
    for v in _verdicts(facts):
        if str(v.get("entity", "")).lower() == name:
            return v.get("kind")
    return None


def _rules_for(facts: dict[str, Any], name: str) -> set[str]:
    """Rule ids the record ties to `name`: its own rule_ids, plus every verdict
    finding that names it. A sentence about `name` may cite only these."""
    rules: set[str] = set()
    for v in _verdicts(facts):
        if str(v.get("entity", "")).lower() == name:
            rules.update(r for r in v.get("rule_ids", []) or [] if r)
    for f in facts.get("verdict_findings", []) or []:
        if name in {str(e).lower() for e in f.get("entities", [])}:
            if f.get("rule"):
                rules.add(f["rule"])
    return rules


def _allowed_logs(facts: dict[str, Any]) -> set[str]:
    """Event-log names the record holds: the .evtx file names in evidence."""
    logs: set[str] = set()
    for f in facts.get("verdict_findings", []) or []:
        for ev in f.get("evidence", []) or []:
            path = str(ev).split(" :: ")[0]
            base = path.replace("\\", "/").rsplit("/", 1)[-1]
            if base.lower().endswith(".evtx"):
                logs.add(base[: -len(".evtx")].lower())
    return logs


def _allowed_times(facts: dict[str, Any]) -> tuple[set[str], set[str]]:
    times, dates = set(), set()
    for f in facts.get("verdict_findings", []) or []:
        if f.get("time_utc"):
            times.add(str(f["time_utc"]))
        if f.get("date"):
            dates.add(str(f["date"]))
    return times, dates


def _relation_errors(text: str, facts: dict[str, Any]) -> list[str]:
    """Relation-level checks: claims ABOUT facts, not the facts themselves.

    Ported from the viewer-side reference checker after it rejected a narration
    this module had accepted. The accepted text said an entity was "ranked
    first" when the record said rank 14 of 443, called percentile 0.0 "less
    suspicious" when 0 means MOST unusual, and merged the triage score with the
    severity band ("critical severity score of 99"). Every token in it resolved,
    so precision and completeness both passed; the errors were in the relations
    drawn between true facts.

    Subject carry-over matters: "invoice_scan.exe ... It is ranked first" names
    nothing in the second sentence, so the check inherits the last-named entity
    rather than skipping the sentence.
    """
    problems: list[str] = []
    ranks = _recorded_ranks(facts)

    known = _known_names(facts)
    last: list[str] = []
    prev_subject: str | None = None
    for sent in _SENTENCE_SPLIT_RE.split(text):
        own = _subjects(sent, known)
        lead = _leading_subject(sent, known, prev_subject)
        prev_subject = lead or (own[0] if own else prev_subject)

        # A user account is never executed. Kind comes from run.json.
        if lead and _entity_kind(facts, lead) == "user account":
            m = _EXECUTED_RE.search(sent)
            if m:
                problems.append(
                    f"kind:{lead} is a user account; {m.group(0).strip()!r} "
                    f"cannot be said of it"
                )

        # A rule cited in a sentence must belong to that sentence's subject.
        if lead:
            mine = _rules_for(facts, lead)
            if mine:
                for rid in _RULE_RE.findall(sent):
                    if rid not in mine:
                        problems.append(
                            f"pairing:{rid} cited for {lead}; record ties {lead} "
                            f"to {', '.join(sorted(mine))}"
                        )
        subjects = own or last
        last = own or last

        if _RANK_WORD_RE.search(sent):
            for name in subjects:
                rec = ranks.get(name)
                if _SUPERLATIVE_RE.search(sent):
                    got = f"rank {rec['rank']} of {rec['of']}" if rec else "no recorded rank"
                    if rec is None or rec.get("rank") != 1:
                        problems.append(f"rank_claim:{name} claimed first/top; record: {got}")
                for want in _RANK_N_RE.findall(sent):
                    if rec is not None and int(want) != rec.get("rank"):
                        problems.append(
                            f"rank_claim:{name} claimed rank {want}; "
                            f"record: rank {rec['rank']} of {rec['of']}"
                        )

        m = _COMPARISON_RE.search(sent)
        if m:
            problems.append(f"comparison:{m.group(0).strip()}")

        m = _SCORE_SUPERLATIVE_RE.search(sent)
        if m:
            phrase = m.group(0).lower()
            lowest = any(w in phrase for w in ("lowest", "smallest"))
            want = 3 if "third" in phrase else 2 if "second" in phrase else 1
            bq = _BAND_QUALIFIER_RE.search(sent)
            band = bq.group(1) if bq else None
            if not subjects:
                problems.append(f"score_ordering:{m.group(0).strip()!r} names no entity")
            else:
                name = subjects[0]
                pos = _score_position(facts, name, band, lowest)
                if pos is None or pos[0] != want:
                    got = f"position {pos[0]} of {pos[1]}" if pos else "no recorded score"
                    problems.append(
                        f"score_ordering:{name} claimed {m.group(0).strip()!r}; "
                        f"record: {got}"
                    )

        m = _ORDER_WORD_RE.search(sent)
        if m:
            problems.append(
                f"order_claim:{m.group(0)!r} -- order between findings is the "
                f"timeline's job, not the narration's"
            )

        if _SEVERITY_SCORE_RE.search(sent):
            problems.append(
                "merged_fields:'severity/priority score' -- the number is the "
                "triage score, the label is the priority band"
            )
    return problems


def validate(text: str, facts: dict[str, Any]) -> ValidationResult:
    """Check `text`'s citations against `facts`. Never raises."""
    unresolvable: list[str] = []

    rules_cited = sorted(set(_RULE_RE.findall(text)))
    allowed_rules = _allowed_rule_ids(facts)
    for r in rules_cited:
        if r not in allowed_rules:
            unresolvable.append(f"rule_id:{r}")

    exes_cited = sorted({m.lower() for m in _EXE_RE.findall(text)})
    allowed_exes = _allowed_exes(facts)
    for e in exes_cited:
        if e not in allowed_exes:
            unresolvable.append(f"exe:{e}")

    nums_cited = sorted(
        {_norm(m) for m in _NUM_RE.findall(text)}
        | {_norm(m) for m in _NUM_RE_SUFFIX.findall(text)}
    )
    allowed_nums = _allowed_numbers(facts)
    for n in nums_cited:
        if n not in allowed_nums:
            unresolvable.append(f"number:{n}")

    # Times and dates: a stated clock time or date must be one the record holds.
    # The model is shown only observed times; a presence-only time is withheld.
    ok_times, ok_dates = _allowed_times(facts)
    for hh, mm in _TIME_RE.findall(text):
        t = f"{int(hh):02d}:{mm}"
        if t not in ok_times:
            unresolvable.append(f"time:{t}")
    for d in _DATE_RE.findall(text):
        if d not in ok_dates:
            unresolvable.append(f"date:{d}")

    # A named event log must be one the evidence holds. Skipped when the facts
    # carry no evidence at all (an older slice) rather than rejecting blind.
    ok_logs = _allowed_logs(facts)
    if ok_logs:
        for m in _LOG_NAME_RE.finditer(text):
            name = m.group(1).lower()
            if name not in ok_logs:
                unresolvable.append(f"log:{m.group(1)}")

    entities_named = {
        str(e).lower()
        for f in facts.get("verdict_findings", []) or []
        for e in f.get("entities", []) or []
    }
    if entities_named:
        for m in _LOG_HOST_RE.finditer(text):
            word = m.group(1).lower()
            if word in _NOT_A_HOST:
                continue
            if word not in entities_named:
                unresolvable.append(f"host:{m.group(1)}")

    for m in _BLANK_RE.finditer(text):
        unresolvable.append(f"blank:{m.group(0)}")

    # Completeness: the verdict must actually be narrated. Omitting it is a
    # failure of the same kind as fabricating -- the prose does not describe the
    # run -- so it is fatal, and named in `unresolvable` for one audit trail.
    lowered = text.lower()
    missing = sorted(e for e in _required_mentions(facts) if e not in lowered)
    unresolvable.extend(f"missing:{e}" for e in missing)

    # Relation-level checks. Fatal: a rank claim that contradicts the record is
    # as wrong as a fabricated one, and passing it would put the narration on
    # screen next to the record it contradicts.
    relation_errors = _relation_errors(text, facts)
    unresolvable.extend(relation_errors)

    scorer = facts.get("scorer")
    mentions_scorer = bool(scorer) and scorer.lower() in lowered

    return ValidationResult(
        validated=not unresolvable,
        citations={"rule_ids": rules_cited, "exes": exes_cited},
        unresolvable=unresolvable,
        mentions_scorer=mentions_scorer,
        numbers_checked=nums_cited,
        missing_mentions=missing,
        describes_ranking_as_detection=bool(_DETECT_CONFUSION_RE.search(text)),
        relation_errors=relation_errors,
    )
