"""The run.json contract, and the one adapter that reads it.

run.json v1.5.0 (the pipeline's current output) is the source of truth. The
v1.4.0 fixtures the viewer was first built on are still readable, as legacy.
`normalize_run()` turns either into one view model the screens draw from, so
no screen needs to know which version it is looking at.

Normalising is re-shaping, never re-scoring: every score, severity, class,
percentile and rank shown comes from the file as written. The only things the
adapter derives are groupings and counts (which phases an entity's findings
sit in; how many findings have each severity), and each is labelled as such
where it is shown.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path

CURRENT_SCHEMA = "1.5.0"
LEGACY_SCHEMAS = {"1.4.0"}
PHASE_ORDER = ["delivery", "execute", "persist", "destroy", "exfiltrate"]
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# entity.exe_name holds file names, not only executables (PDFs, archives, media
# in this run), so it is shown as "file", never as "binary".
KIND_OF_KEY = {"entity.exe_name": "file", "entity.binary": "file",
               "entity.user": "user", "entity.host": "host"}


def kind_of(key) -> str:
    return KIND_OF_KEY.get(str(key), str(key).replace("entity.", "") or "other")


def is_legacy(run) -> bool:
    return str(run.get("run_json_version")) in LEGACY_SCHEMAS


# --------------------------------------------------------------------------- #
# Findings                                                                    #
# --------------------------------------------------------------------------- #

def _norm_finding(f: dict) -> dict:
    """v1.5 names its source events `matched`; v1.4 called them `events` and
    listed `event_ids` separately. Both become `events` + `event_ids`."""
    n = dict(f)
    evs = f.get("events")
    if evs is None:
        evs = [dict(e, resolved=True) for e in f.get("matched", []) if isinstance(e, dict)]
    n["events"] = evs
    n["event_ids"] = f.get("event_ids") or [e.get("event_id") for e in evs
                                            if isinstance(e, dict) and e.get("event_id")]
    tech = str(f.get("attack_technique") or "")
    n["technique_family"] = f.get("technique_family") or (tech.split(".")[0] if tech else "")
    n["notes"] = [str(x) for x in f.get("notes", [])] if isinstance(f.get("notes"), list) else []
    n["timed"] = str(f.get("time_claim", "")) != "none"
    return n


# --------------------------------------------------------------------------- #
# Entities                                                                    #
# --------------------------------------------------------------------------- #

def _phases_of(finding_ids, by_id) -> list:
    seen = {by_id[i].get("phase") for i in finding_ids if i in by_id}
    return [p for p in PHASE_ORDER if p in seen]


def _norm_entity(e: dict, by_id: dict) -> dict:
    n = dict(e)
    n["kind"] = e.get("kind") or kind_of(e.get("key"))
    ids = [i for i in e.get("finding_ids", []) if isinstance(i, str)]
    n["finding_ids"] = ids
    # v1.5 records phase_span as a count; the screens show the phases
    # themselves, taken from the entity's own findings.
    span = e.get("phase_span")
    n["phase_span"] = span if isinstance(span, list) else _phases_of(ids, by_id)
    n["rule_ids"] = [str(r) for r in e.get("rule_ids", [])]
    n["rule_count"] = e.get("rule_count", len(n["rule_ids"]))
    n["finding_count"] = e.get("finding_count", len(ids))
    n["techniques"] = [str(t) for t in e.get("techniques", [])]
    n["listed"] = True
    # Findings that name this entity but are not among the ones behind its
    # score (in v1.5 these are the Class 2 context findings). Kept apart so the
    # score is never presented as covering them, yet they stay reachable.
    key, val = str(e.get("key")), str(e.get("value"))
    n["context_ids"] = [
        fid for fid, f in by_id.items() if fid not in ids and any(
            isinstance(k, dict) and str(k.get("key")) == key and str(k.get("value")) == val
            for k in f.get("entity_keys", []))]
    n["all_ids"] = ids + n["context_ids"]
    return n


def _grouped_entities(findings, listed_values) -> list:
    """Every entity named by a finding but absent from run.json's entity list
    (v1.5 lists only the entities the rules layer scored). Grouped by name so
    the Context page can drill into them; they carry NO triage score."""
    groups: dict = {}
    for f in findings:
        for k in f.get("entity_keys", []):
            if not isinstance(k, dict):
                continue
            val, key = str(k.get("value", "")), str(k.get("key", ""))
            if not val or (key, val) in listed_values:
                continue
            g = groups.setdefault((key, val), {
                "key": key, "value": val, "kind": kind_of(key), "finding_ids": [],
                "rule_ids": [], "techniques": [], "score": None, "listed": False})
            g["finding_ids"].append(f["finding_id"])
            g.setdefault("all_ids", g["finding_ids"])
            if f.get("rule_id") not in g["rule_ids"]:
                g["rule_ids"].append(f.get("rule_id"))
            t = f.get("attack_technique")
            if t and t not in g["techniques"]:
                g["techniques"].append(t)
    by_id = {f["finding_id"]: f for f in findings}
    out = []
    for g in groups.values():
        sevs = [by_id[i].get("severity") for i in g["finding_ids"]]
        g["severity"] = max(sevs, key=lambda s: SEV_ORDER.get(s, 0))
        g["phase_span"] = _phases_of(g["finding_ids"], by_id)
        g["finding_count"] = len(g["finding_ids"])
        g["rule_count"] = len(g["rule_ids"])
        out.append(g)
    out.sort(key=lambda g: (-SEV_ORDER.get(g["severity"], 0), -g["finding_count"],
                            g["value"]))
    return out


# --------------------------------------------------------------------------- #
# Anomalies (prioritisation layer — never a verdict)                          #
# --------------------------------------------------------------------------- #

def _norm_anomalies(an: dict) -> dict:
    an = an if isinstance(an, dict) else {}
    scored, unscored = [], []
    if isinstance(an.get("scored_entities"), list):            # v1.5
        fam_seen: Counter = Counter()
        for i, s in enumerate(an["scored_entities"], 1):
            if isinstance(s, dict):
                fam = str(s.get("family", ""))
                fam_seen[fam] += 1
                scored.append({"rank": i, "entity": str(s.get("entity", "")),
                               "family": fam, "family_rank": fam_seen[fam],
                               "percentile": s.get("percentile_in_family")})
        # Within a family, tied percentiles share a position (competition
        # ranking: 1, 2, 2, 4) — a list order must not imply one outranks the other.
        by_fam: dict = {}
        for s in scored:
            by_fam.setdefault(s["family"], []).append(s)
        for rows in by_fam.values():
            vals = [r["percentile"] for r in rows]
            for r in rows:
                p = r["percentile"]
                if isinstance(p, (int, float)) and not isinstance(p, bool):
                    r["family_rank"] = 1 + sum(1 for v in vals if isinstance(v, (int, float))
                                               and not isinstance(v, bool) and v < p)
                    r["tied"] = sum(1 for v in vals if v == p)
                else:
                    r["tied"] = 1
        for s in scored:
            s["family_n"] = fam_seen[s["family"]]
        for u in an.get("unscored_families", []) or []:
            if isinstance(u, dict):
                unscored.append({"family": str(u.get("family", "")),
                                 "rows": u.get("rows"), "reason": str(u.get("reason", ""))})
    elif isinstance(an.get("families"), dict):                  # v1.4 fixture
        i = 0
        for fam, blk in an["families"].items():
            if not isinstance(blk, dict):
                continue
            if not blk.get("scored", False):
                unscored.append({"family": str(fam), "rows": blk.get("n"),
                                 "reason": str(blk.get("reason", ""))})
                continue
            ents = blk.get("entities", [])
            for j, e in enumerate(ents, 1):
                i += 1
                scored.append({"rank": i, "entity": str(e.get("value", "")),
                               "family": str(fam), "family_rank": j,
                               "family_n": len(ents),
                               "percentile": e.get("percentile_in_family")})
    return {
        "scorer": an.get("scorer"),
        "is_verdict": an.get("is_verdict"),
        "meaning": an.get("meaning") or an.get("note") or "",
        "scored": scored, "unscored": unscored,
        "fixture": bool(an.get("_fixture")),
        # v1.5: 0 is the most unusual row of its kind. The v1.4 fixture used
        # the opposite direction; say which, never assume.
        "low_is_unusual": isinstance(an.get("scored_entities"), list),
    }


def anomaly_of(view, value) -> dict | None:
    """Where an entity sits in the prioritisation list, if it is there."""
    for s in view["anomalies"]["scored"]:
        if s["entity"] == value:
            return s
    return None


# --------------------------------------------------------------------------- #
# Narration — AI prose about the findings, never a finding                    #
# --------------------------------------------------------------------------- #

CITE_RE = re.compile(r"\[\[([^\[\]]+)\]\]")
RULE_RE = re.compile(r"\bR-(?:ATOMIC|CORR)-\d{4}\b")


def narration_citations(nar) -> list:
    """Legacy (v1.4) citations: the declared list plus every inline [[id]]."""
    declared = [str(c) for c in nar.get("citations", [])]
    inline = CITE_RE.findall(str(nar.get("text", "")))
    return declared + [c.strip() for c in inline]


EXE_RE = re.compile(r"\b[\w.\-]+\.(?:exe|dll|sys|ps1|bat|cmd|tmp|msi)\b", re.I)
NUM_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w])")
RANK_WORD_RE = re.compile(r"\b(rank(?:ed|ing)?|place[ds]?|position)\b", re.I)
SUPERLATIVE_RE = re.compile(r"\b(first|1st|top|highest|leading|number one|#1)\b", re.I)
RANK_N_RE = re.compile(r"\brank(?:ed)?\s+(?:#\s*)?(\d+)\b", re.I)
COMPARISON_RE = re.compile(
    r"\b(less|more|least|most)\s+(suspicious|unusual|anomalous|malicious|dangerous|"
    r"risky|benign|concerning)\b|\bsafer\b|\bconsidered (?:benign|safe)\b", re.I)
SEVERITY_SCORE_RE = re.compile(r"\bseverity score\b", re.I)


def _numbers_in(values) -> set:
    out: set = set()
    for tok in re.findall(r"\d+(?:\.\d+)?", " ".join(map(str, values))):
        out.add(tok)
        out.add(tok.lstrip("0") or "0")
        if "." in tok:
            whole, frac = tok.split(".")
            for k in range(1, len(frac)):
                out.add(f"{whole}.{frac[:k]}")
            out.add(str(round(float(tok))))
    return out


ORDINALS = {"first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5, "sixth": 6,
            "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10}
ORDINAL_RE = re.compile(r"\b(\d+)(?:st|nd|rd|th)\b|\b(" + "|".join(ORDINALS) + r")\b", re.I)
SCORE_NUM_RE = re.compile(r"\bscore\b[^.\d]{0,24}?(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*\)?\s*"
                          r"(?:triage\s+)?score\b", re.I)
SEVERITY_NUM_RE = re.compile(r"\bseverity\b[^.\d]{0,12}?(?:of|=|:|is)\s*\d", re.I)
VERDICT_WORD_RE = re.compile(r"\b(malicious|malware|compromised|attacker|infected|"
                             r"threat actor|backdoor|trojan)\b", re.I)
NEGATED_RE = re.compile(r"\b(not|no|never|isn't|is not|without)\b[\w\s,]{0,24}$", re.I)
INTERPRET_RE = re.compile(r"\b(considered|meaning|indicating|suggesting|so they are|"
                          r"therefore)\b[^.]{0,48}?\b(normal|harmless|legitimate|safe|clean|"
                          r"benign|suspicious|dangerous|expected)\b", re.I)


def _names_in(sent: str, known: list) -> list:
    """Every known entity name in a sentence (users, hosts and file names of any
    extension, not only .exe), longest first so "a.exe" doesn't match inside
    "aa.exe", plus any file-like token for the not-in-run check."""
    low, found = sent.lower(), []
    for nm in known:
        k = low.find(nm)
        while k != -1:
            before = low[k - 1] if k else " "
            after = low[k + len(nm)] if k + len(nm) < len(low) else " "
            if not (before.isalnum() or before in "._-") and not (
                    after.isalnum() or after in "_-" or (after == "." and
                    k + len(nm) + 1 < len(low) and low[k + len(nm) + 1].isalnum())):
                if nm not in found:
                    found.append(nm)
                break
            k = low.find(nm, k + 1)
    return found


def relation_problems(text: str, view) -> list:
    """Relation checks the pipeline's validator does not make (see the
    narration handoff). A floor, not proof:
      - a number must come from the record of what the prose cites, and a
        number beside "score" must be that entity's triage score;
      - a rank claim (first/top, "rank 3", "2nd") must equal the recorded
        position; the subject carries over from the previous sentence;
      - no comparison or interpretation of suspicion, safety or normality;
      - no verdict words (malicious, compromised…) unless negated;
      - severity is a band: no "severity score", no number after "severity"."""
    problems: list = []
    ranks = {s["entity"].lower(): s for s in view["anomalies"]["scored"]}
    ents = {str(e.get("value", "")).lower(): e for e in view["all_entities"]}
    known = sorted((set(ranks) | set(ents)) - {""}, key=len, reverse=True)
    names = set(_names_in(text, known)) | {m.lower() for m in EXE_RE.findall(text)}
    rules_cited = set(RULE_RE.findall(text))
    vals: list = []
    for nm in names:
        e = ents.get(nm)
        if e:
            vals += [e.get("score"), e.get("raw_sum"), e.get("rule_count"),
                     e.get("finding_count")]
            for i in e.get("all_ids", e.get("finding_ids", [])):
                f = view["by_id"].get(i, {})
                vals += [f.get("weight"), f.get("first_timestamp_utc")]
        a = ranks.get(nm)
        if a:
            vals += [a["rank"], len(view["anomalies"]["scored"]), a["percentile"],
                     a.get("family_rank"), a.get("family_n")]
    for f in view["findings"]:
        if f.get("rule_id") in rules_cited:
            vals += [f.get("weight"), f.get("first_timestamp_utc")]
    allowed = _numbers_in(vals)
    for tok in NUM_RE.findall(RULE_RE.sub(" ", text)):
        if tok not in allowed and (tok.lstrip("0") or "0") not in allowed:
            problems.append(f"the number {tok} is not in the record for what it cites")
    last: list = []
    for sent in re.split(r"(?<=[.!?])\s+", text):
        own = _names_in(sent, known) or [m.lower() for m in EXE_RE.findall(sent)]
        subj = own or last
        last = own or last
        if RANK_WORD_RE.search(sent):
            for nm in subj:
                a = ranks.get(nm)
                got = f"position {a['rank']} of {len(ranks)}" if a else "not ranked"
                if SUPERLATIVE_RE.search(sent) and (a is None or a["rank"] != 1):
                    problems.append(f"it calls {nm} ranked first/top; the record says {got}")
                wants = [int(w) for w in RANK_N_RE.findall(sent)]
                for m in ORDINAL_RE.finditer(sent):
                    wants.append(int(m.group(1)) if m.group(1)
                                 else ORDINALS[m.group(2).lower()])
                for want in wants:
                    if want != 1 and (a is None or want != a["rank"]):
                        problems.append(f"it gives {nm} rank {want}; the record says {got}")
        for m in SCORE_NUM_RE.finditer(sent):
            val = m.group(1) or m.group(2)
            scores = {str(ents[nm].get("score")) for nm in subj
                      if nm in ents and ents[nm].get("score") is not None}
            if scores and val not in scores:
                problems.append(f"it gives a score of {val}; the triage score recorded is "
                                f"{', '.join(sorted(scores))}")
        m = COMPARISON_RE.search(sent) or INTERPRET_RE.search(sent)
        if m:
            problems.append(f"it compares or interprets (“{m.group(0)}”); the "
                            "anomaly ranking orders unusualness and grades no one's "
                            "suspicion or safety")
        for m in VERDICT_WORD_RE.finditer(sent):
            if not NEGATED_RE.search(sent[:m.start()]):
                problems.append(f"it uses a verdict word (“{m.group(0)}”) the "
                                "record does not carry — rules report matches")
        if SEVERITY_SCORE_RE.search(sent) or SEVERITY_NUM_RE.search(sent):
            problems.append("it gives severity a number: severity is a band (critical, "
                            "high…); the number is the triage score")
    return list(dict.fromkeys(problems))


def narration_gate(run, view) -> dict:
    """Decide whether narration may be shown. Returns
    {present, show, reason, legacy, cites_findings, cites_rules, cites_exes}.

    v1.5 rules (from the pipeline owner): show only `status == "accepted"`;
    on anything else show nothing of the prose — `rejected.text` is never
    read. On top of that the viewer re-checks what it can: the validator must
    say `validated`, nothing may be unresolvable, the ranking must not be
    described as detection, and every cited rule id and executable must exist
    in this run. Any failure withholds the text.
    """
    nar = run.get("narration")
    base = {"present": nar is not None, "show": False, "reason": "",
            "legacy": False, "cites_findings": [], "cites_rules": [], "cites_exes": []}
    if nar is None:
        base["reason"] = "This run carries no narration. Narration is off by default."
        return base
    if not isinstance(nar, dict):
        base["reason"] = "The narration field is not an object."
        return base
    fids = {f["finding_id"] for f in view["findings"]}

    if "status" not in nar or nar.get("status") == "provisional":   # legacy v1.4
        base["legacy"] = True
        cites = list(dict.fromkeys(narration_citations(nar)))
        bad = [c for c in cites if c not in fids]
        base["cites_findings"] = cites
        if bad:
            base["reason"] = (f"{len(bad)} citation(s) do not resolve to a finding_id "
                              f"in this run: {', '.join(bad)}.")
            return base
        base["show"] = True
        return base

    status = str(nar.get("status"))
    if status != "accepted":
        base["reason"] = f"status is “{status}” — only accepted narration is shown."
        return base
    val = nar.get("validation") if isinstance(nar.get("validation"), dict) else {}
    cit = val.get("citations") if isinstance(val.get("citations"), dict) else {}
    rules = [str(r) for r in cit.get("rule_ids", [])]
    exes = [str(x) for x in cit.get("exes", [])]
    base["cites_rules"], base["cites_exes"] = rules, exes
    problems = []
    if val.get("validated") is not True:
        problems.append("the pipeline's validator did not mark it validated")
    if val.get("unresolvable"):
        problems.append("the validator lists unresolvable citations")
    if val.get("describes_ranking_as_detection"):
        problems.append("it describes the anomaly ranking as detection")
    known_rules = {f.get("rule_id") for f in view["findings"]}
    known_names = ({str(e.get("value")) for e in view["all_entities"]}
                   | {s["entity"] for s in view["anomalies"]["scored"]})
    missing_r = [r for r in rules if r not in known_rules]
    missing_x = [x for x in exes if x not in known_names]
    if missing_r:
        problems.append(f"cited rule(s) not in this run: {', '.join(missing_r)}")
    if missing_x:
        problems.append(f"cited name(s) not in this run: {', '.join(missing_x)}")
    # Rule ids written in the prose must be declared citations too.
    undeclared = sorted(set(RULE_RE.findall(str(nar.get("text", "")))) - set(rules))
    if undeclared:
        problems.append(f"rule id(s) in the text but not declared: {', '.join(undeclared)}")
    # Relation checks: a sentence can join true facts into a false claim.
    problems += relation_problems(str(nar.get("text", "")), view)
    if problems:
        base["reason"] = "The viewer's re-check failed: " + "; ".join(problems) + "."
        return base
    base["show"] = True
    return base


# --------------------------------------------------------------------------- #
# Manifest — every attested file, not only run.json                          #
# --------------------------------------------------------------------------- #

def parse_manifest(text: str) -> dict:
    """`sha256sum` format (`<hash>  <file>` per line) → {file: hash}. A single
    bare hash (the v1.4 fixtures) attests run.json."""
    out: dict = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if not parts:
            continue
        h = parts[0].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            continue
        name = parts[1].strip().lstrip("*").strip() if len(parts) > 1 else "run.json"
        out[Path(name).name] = h
    return out


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def verify_manifest(attested: dict, files: dict) -> dict:
    """attested {name: hash}; files {name: bytes|None} for what is at hand.
    Returns {name: "verified" | "mismatch" | "absent"}. Absent is not a
    mismatch: the file simply is not here to check."""
    res = {}
    for name, h in attested.items():
        b = files.get(name)
        res[name] = "absent" if b is None else ("verified" if sha256_bytes(b) == h
                                                else "mismatch")
    return res


def read_manifest_dir(run_path: Path) -> tuple[dict, dict]:
    """(attested, results) for a run folder on disk. Read-only."""
    mf = run_path.parent / "manifest.sha256"
    if not mf.is_file():
        return {}, {}
    try:
        attested = parse_manifest(mf.read_text(encoding="utf-8"))
    except Exception:
        return {}, {}
    files = {n: ((run_path.parent / n).read_bytes() if (run_path.parent / n).is_file()
                 else None) for n in attested}
    return attested, verify_manifest(attested, files)


# --------------------------------------------------------------------------- #
# The view model                                                              #
# --------------------------------------------------------------------------- #

def normalize_run(run: dict) -> dict:
    findings = [_norm_finding(f) for f in run.get("findings", []) if isinstance(f, dict)]
    by_id = {f["finding_id"]: f for f in findings}
    entities = [_norm_entity(e, by_id) for e in run.get("entities", []) if isinstance(e, dict)]
    listed = {(str(e.get("key")), str(e.get("value"))) for e in entities}
    grouped = _grouped_entities(findings, listed) if not is_legacy(run) else []
    coll = run.get("collection")
    sev = Counter(f.get("severity") for f in findings)
    cls = Counter(f.get("rule_class") for f in findings)
    ph = Counter(f.get("phase") for f in findings)
    counts = {
        "findings_total": len(findings), "entities_total": len(entities),
        "findings_by_severity": dict(sev), "findings_by_class": dict(cls),
        "findings_by_phase": dict(ph),
    }
    view = {
        "version": str(run.get("run_json_version", "?")),
        "legacy": is_legacy(run),
        "fixture": isinstance(run.get("_fixture"), dict) and bool(run["_fixture"].get("is_fixture")),
        "collection": (coll.get("name") if isinstance(coll, dict) else coll) or "—",
        "collection_path": coll.get("path") if isinstance(coll, dict) else None,
        "findings": findings, "by_id": by_id,
        "entities": entities, "grouped": grouped, "all_entities": entities + grouped,
        "counts": counts,
        "anomalies": _norm_anomalies(run.get("anomalies")),
        "rules": run.get("rules") if isinstance(run.get("rules"), dict) else None,
        "ingest": run.get("ingest") if isinstance(run.get("ingest"), dict) else None,
        "events": run.get("events") if isinstance(run.get("events"), dict) else None,
    }
    view["untimed"] = sum(1 for f in findings if not f["timed"])
    return view
