"""HTML building blocks. Presentation only — no Streamlit, no data changes.

Every value that comes from run.json passes through `esc()` before it reaches
HTML. run.json is evidence: file paths, user names, command lines and titles
are written by whatever was on the examined machine, so they are untrusted
input. Unescaped, an entity named `</span><div class='banner banner-ok'>…`
could draw a fake "Manifest verified" banner inside the viewer.
"""
from __future__ import annotations

import html
from collections import Counter, defaultdict
from datetime import date, timedelta

from .model import ATTACK_NAMES, PHASE_ORDER, as_int

SEV_COLOR = {
    "critical": "var(--sev-crit)", "high": "var(--sev-high)",
    "medium": "var(--sev-med)", "low": "var(--sev-low)", "info": "var(--muted)",
}
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Info"}
CLASS_LABEL = {
    "corpus-validated": "CLASS 1 · corpus-validated rule",
    "known-behavior": "CLASS 2 · known-behavior · context",
}


def esc(v) -> str:
    """Escape any value for HTML text and single- or double-quoted attributes."""
    return html.escape("" if v is None else str(v), quote=True)


def fam_pos(a) -> str:
    """'5 of 344', or '=12 of 344 (7 tied)' when others share the percentile."""
    tied = a.get("tied", 1) or 1
    pos = f"{'=' if tied > 1 else ''}{a.get('family_rank', '?')} of {a.get('family_n', '?')}"
    return pos + (f" ({tied} tied)" if tied > 1 else "")


def fmt_pct(v) -> str:
    """A percentile on its 0–100 scale, one format everywhere."""
    return f"{v:.2f}" if isinstance(v, (int, float)) and not isinstance(v, bool) else esc(v)


def num(v) -> str:
    """Numbers render as numbers; anything else is escaped text."""
    return str(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else esc(v)


def tech_name(tech) -> str:
    t = str(tech or "")
    return ATTACK_NAMES.get(t, ATTACK_NAMES.get(t.split(".")[0], ""))


# --------------------------------------------------------------------------- #
# Chips and labels                                                            #
# --------------------------------------------------------------------------- #

def sev_chip(sev) -> str:
    """Severity chip: ink label + colour dot (text never wears the ramp)."""
    c = SEV_COLOR.get(sev, "var(--muted)")
    strong = " sev-strong" if sev == "critical" else ""
    return (f"<span class='chip sev{strong}'><i style='background:{c}'></i>"
            f"{esc(SEV_LABEL.get(sev, sev))}</span>")


def phase_chip(phase) -> str:
    """Phase is position + label, not colour."""
    return f"<span class='chip ph'>{esc(phase)}</span>"


def phase_path(span) -> str:
    if not span:
        return "<span class='note'>—</span>"
    # "·", not "›": the phases are listed in vocabulary order, not in time.
    return "<span class='ph-arrow'>·</span>".join(phase_chip(p) for p in span)


def class_badge(rule_class) -> str:
    verdict = rule_class == "corpus-validated"
    c = "var(--accent)" if verdict else "var(--muted)"
    return (f"<span class='chip' style='color:{c};border-color:{c};"
            f"background:transparent'>{esc(CLASS_LABEL.get(rule_class, rule_class))}"
            "</span>")


def tech_label(tech) -> str:
    """Beside a specific file, only the technique ID — the ATT&CK name is on
    hover. Names like "Malicious File" or "Exfiltration Over C2 Channel" next
    to an installer or OneDrive read as a judgement on that file; the rule's
    own title is what describes the observation. Names appear in full on the
    ATT&CK tiles, under the note that they describe rules."""
    name = tech_name(tech)
    return (f"<span class='mono tid' title='ATT&amp;CK {esc(tech)}: {esc(name)} — the "
            f"technique the rule maps to, not a judgement about this file'>"
            f"{esc(tech)}</span>")


def fmt_ts(ts) -> str:
    """2026-06-20T14:15:30.256094Z -> 2026-06-20 14:15 UTC (display only)."""
    if not ts:
        return "time not recorded"
    ts = str(ts)
    return esc(f"{ts[:10]} {ts[11:16]} UTC" if len(ts) >= 16 else ts)


# --------------------------------------------------------------------------- #
# Overview blocks                                                             #
# --------------------------------------------------------------------------- #

def killchain_bar(findings) -> str:
    """Phases as a stepped path, split by class. A node is filled only by
    Class 1 (corpus-validated) findings; Class 2 context findings are counted
    beneath it and never light a node — so a phase full of commonly-benign
    matches (e.g. network egress mapped to "exfiltrate") does not read as
    that stage having happened."""
    v1 = Counter(f.get("phase") for f in findings if f.get("rule_class") == "corpus-validated")
    v2 = Counter(f.get("phase") for f in findings if f.get("rule_class") != "corpus-validated")
    total = sum(v1.values()) or 1
    cells = []
    for i, ph in enumerate(PHASE_ORDER):
        n, c = v1.get(ph, 0), v2.get(ph, 0)
        fill = (f"color-mix(in srgb, var(--accent) {25 + 75*n/total:.0f}%, "
                f"var(--panel))") if n else "transparent"
        cls = "kc-node on" if n else ("kc-node ctx" if c else "kc-node")
        cells.append(
            f"<div class='kc-cell' title='{ph}: {n} class 1, {c} class 2 (context)'>"
            f"<div class='{cls}' style='background:{fill}'></div>"
            f"<div class='kc-name'>{ph}</div>"
            f"<div class='kc-count'>{n}</div>"
            f"<div class='kc-ctx'>{f'+{c} context' if c else '&nbsp;'}</div></div>")
        if i < len(PHASE_ORDER) - 1:
            link = "kc-link"
            cells.append(f"<div class='{link}'></div>")
    return (f"<div class='kc' role='img' aria-label='Findings by phase: class 1 counts, "
            f"with class 2 context beneath'>{''.join(cells)}</div>"
            "<div class='note' style='margin-top:6px'>Filled: Class 1 (corpus-validated) "
            "findings. <i>+N context</i>: Class 2 matches, commonly benign, never counted "
            "as the stage having happened. Phases are a vocabulary, not an order; the "
            "times show the order.</div>")


def hbar(segments: list[tuple], total: int | None = None) -> str:
    """Horizontal stacked bar. segments = [(label, count, color)]."""
    segments = [(lbl, as_int(c), col) for lbl, c, col in segments]
    total = total or sum(c for _, c, _ in segments) or 1
    seg_html = "".join(
        f"<div title='{esc(lbl)}: {cnt}' style='width:{100*cnt/total:.2f}%;"
        f"background:{col}' class='bar-seg'></div>"
        for lbl, cnt, col in segments if cnt > 0)
    legend = " ".join(
        f"<span class='bl'><i style='background:{col}'></i>{esc(lbl)} "
        f"<b>{cnt}</b></span>" for lbl, cnt, col in segments if cnt > 0)
    return (f"<div class='bar'>{seg_html}</div>"
            f"<div class='bar-legend'>{legend}</div>")


def catbars(category_scores: dict) -> str:
    """Score contribution by rule category — one accent, magnitude as length."""
    order = ["anti_forensics", "privilege_escalation", "execution_context",
             "persistence"]
    vals = {k: category_scores.get(k, 0) for k in order}
    mx = max((v for v in vals.values() if isinstance(v, (int, float))), default=0) or 1
    rows = []
    for name in order:
        v = vals[name] if isinstance(vals[name], (int, float)) else 0
        rows.append(
            f"<div class='cat-row'><div class='cat-name'>{name.replace('_', ' ')}"
            f"</div><div class='cat-track'><div class='cat-fill' style='width:"
            f"{100*v/mx:.1f}%'></div></div>"
            f"<div class='cat-val'>{num(v)}</div></div>")
    return f"<div class='cat'>{''.join(rows)}</div>"


def attack_strip(findings: list[dict]) -> str:
    """Techniques the rules map to, split by class. A technique name is the
    rule's ATT&CK mapping, not a finding about any file."""
    v1 = Counter(str(f.get("attack_technique")) for f in findings
                 if f.get("attack_technique") and f.get("rule_class") == "corpus-validated")
    v2 = Counter(str(f.get("attack_technique")) for f in findings
                 if f.get("attack_technique") and f.get("rule_class") != "corpus-validated")
    techs = set(v1) | set(v2)
    if not techs:
        return "<span class='note'>No ATT&amp;CK techniques mapped in this run.</span>"
    mx = max(v1.values(), default=0) or 1
    cells = []
    for tech in sorted(techs, key=lambda t: (-v1.get(t, 0), -v2.get(t, 0), t)):
        n, c = v1.get(tech, 0), v2.get(tech, 0)
        name = tech_name(tech)
        cls = "att" if n else "att ctx"
        cells.append(
            f"<div class='{cls}' title='{esc(tech)} {esc(name)}: {n} class 1, {c} class 2'>"
            f"<div class='att-top'><span class='att-id'>{esc(tech)}</span>"
            f"<span class='att-n'>{n}</span></div>"
            f"<div class='att-name'>{esc(name) or '&nbsp;'}</div>"
            f"<div class='att-bar'><div style='width:{100*n/mx:.0f}%'></div></div>"
            f"<div class='att-ctx'>{f'+{c} context' if c else '&nbsp;'}</div>"
            f"</div>")
    return (f"<div class='att-wrap'>{''.join(cells)}</div>"
            "<div class='note' style='margin-top:8px'>The technique each rule maps to. "
            "The large number counts Class 1 findings; <i>+N context</i> counts Class 2 "
            "matches, commonly benign. A technique name describes the rule, not a "
            "judgement about any file.</div>")


def activity_timeline(findings: list[dict], selected: tuple | None = None) -> str:
    """When the findings happened: one column per day across the run's span,
    stacked by severity (most severe on the baseline). Native tooltips give the
    per-day breakdown. A projection of first_timestamp_utc — nothing inferred.
    `selected` (lo, hi ISO days) outlines the active date filter."""
    by_day = defaultdict(lambda: defaultdict(int))
    v1_day: Counter = Counter()
    for f in findings:
        if str(f.get("time_claim", "")) == "none":
            continue  # presence only: no time of its own to plot
        ts = str(f.get("first_timestamp_utc") or "")[:10]
        try:
            d = date.fromisoformat(ts)
        except ValueError:
            continue
        by_day[d][f.get("severity", "info")] += 1
        if f.get("rule_class") == "corpus-validated":
            v1_day[d] += 1
    if not by_day:
        return "<span class='note'>No timestamped findings to plot.</span>"
    lo, hi = min(by_day), max(by_day)
    days = [lo + timedelta(n) for n in range((hi - lo).days + 1)]
    order = ["critical", "high", "medium", "low"]
    total_all = sum(sum(v.values()) for v in by_day.values())
    W, H, pad_l, pad_r, pad_t, pad_b = 1000, 190, 8, 8, 22, 30
    pw, ph = W - pad_l - pad_r, H - pad_t - pad_b
    peak = max(sum(v.values()) for v in by_day.values()) or 1
    slot = pw / len(days)
    bw = max(2.0, min(22.0, slot - 3))
    base = pad_t + ph
    bars, peak_lbl = [], ""
    band = ""
    if selected:
        try:
            s0, s1 = date.fromisoformat(selected[0]), date.fromisoformat(selected[1])
            i0 = max(0, (s0 - lo).days)
            i1 = min(len(days) - 1, (s1 - lo).days)
            if i0 <= i1:
                band = (f"<rect x='{pad_l + i0*slot:.1f}' y='{pad_t - 6}' "
                        f"width='{(i1 - i0 + 1)*slot:.1f}' height='{ph + 6}' "
                        f"class='tl-band' rx='4'/>")
        except (ValueError, TypeError):
            band = ""
    for i, d in enumerate(days):
        counts = by_day.get(d)
        if not counts:
            continue
        x = pad_l + i * slot + (slot - bw) / 2
        y = base
        tot = sum(counts.values())
        tip = (f"{d.isoformat()} — {tot} finding(s), {v1_day.get(d, 0)} class 1: "
               + ", ".join(f"{counts[s]} {s}" for s in order if counts.get(s)))
        segs = []
        present = [s for s in order if counts.get(s)]
        for j, s in enumerate(present):
            h = ph * counts[s] / peak
            top = j == len(present) - 1
            gap = 2 if j else 0  # 2px surface gap below every segment but the first
            y -= h
            rx = "3" if top else "0"
            segs.append(
                f"<rect x='{x:.1f}' y='{y:.1f}' width='{bw:.1f}' "
                f"height='{max(h - gap, 1):.1f}' rx='{rx}' "
                f"style='fill:{SEV_COLOR[s]}'/>")
        bars.append(f"<g class='tl-day'><title>{esc(tip)}</title>"
                    f"<rect x='{x - 2:.1f}' y='{pad_t}' width='{bw + 4:.1f}' "
                    f"height='{ph}' style='fill:transparent'/>{''.join(segs)}</g>")
        if tot == peak and not peak_lbl:
            peak_lbl = (f"<text x='{x + bw/2:.1f}' y='{y - 6:.1f}' "
                        f"text-anchor='middle' class='tl-lbl'>{tot}</text>")
    n = len(days)
    idx = sorted({0, n - 1, *[round(k * (n - 1) / 5) for k in range(1, 5)]}) \
        if n > 1 else [0]

    def _tick(i):
        x = pad_l + i * slot + slot / 2
        anchor = "middle"
        if i == idx[0] and n > 1:
            anchor, x = "start", pad_l
        elif i == idx[-1] and n > 1:
            anchor, x = "end", W - pad_r
        return (f"<text x='{x:.1f}' y='{H - 8}' text-anchor='{anchor}' "
                f"class='tl-axis'>{days[i].strftime('%b %d')}</text>")
    ticks = "".join(_tick(i) for i in idx)
    legend = "".join(
        f"<span class='bl'><i style='background:{SEV_COLOR[s]}'></i>"
        f"{SEV_LABEL[s]}</span>" for s in order
        if any(v.get(s) for v in by_day.values()))
    n1 = sum(v1_day.values())
    span = (f"{lo.isoformat()} → {hi.isoformat()} · {n} day(s) · {total_all} plotted, "
            f"{n1} class 1")
    total = sum(sum(v.values()) for v in by_day.values())
    return (f"<div class='tl-head'><div class='bar-legend'>{legend}</div>"
            f"<div class='note'>{span}</div></div>"
            f"<svg viewBox='0 0 {W} {H}' class='tl-svg' role='img' "
            f"aria-label='Findings per day by severity: {total} findings across "
            f"{n} days, peak {peak} on one day'>"
            f"{band}<line x1='{pad_l}' y1='{base}' x2='{W - pad_r}' y2='{base}' "
            f"class='tl-base'/>{''.join(bars)}{peak_lbl}{ticks}</svg>")


KIND_LABEL = {"file": "File name", "binary": "File name", "user": "User account",
              "host": "Host"}


def _n(v, word) -> str:
    return f"{num(v)} {word}" + ("" if v == 1 else "s")


def priority_list(entities) -> str:
    """The triage queue: run.json's scored entities in the pipeline's own
    order. The bar is the triage score — where to look first, not a verdict."""
    ents = [e for e in entities if isinstance(e.get("score"), (int, float))][:8]
    maxs = max((e["score"] for e in ents), default=1) or 1
    rows = []
    for i, e in enumerate(ents, 1):
        sev = e.get("severity", "info")
        col = SEV_COLOR.get(sev, "var(--muted)")
        w = 100 * e["score"] / maxs
        tip = (f"{e.get('value', '')} — rules: {', '.join(map(str, e.get('rule_ids', [])))}; "
               f"techniques: {', '.join(map(str, e.get('techniques', []))) or '—'}")
        rows.append(
            f"<div class='pri-row' title='{esc(tip)}'><div class='pri-rank'>{i:02d}</div>"
            f"<div class='pri-main'><div class='pri-top'>{sev_chip(sev)}"
            f"<span class='pri-val'>{esc(e.get('value', ''))}</span>"
            f"<span class='pri-kind'>{esc(e.get('kind', ''))}</span></div>"
            f"<div class='pri-path'>{phase_path(e.get('phase_span', []))}</div>"
            f"<div class='pri-bar'><div class='pri-fill' style='width:{w:.0f}%;"
            f"background:{col}'></div></div></div>"
            f"<div class='pri-score'>{num(e['score'])}<span>triage score</span></div></div>")
    if not rows:
        return "<span class='note'>No scored entities in this run.</span>"
    return ("<div class='pri'>" + "".join(rows) + "</div>"
            "<div class='note' style='margin-top:10px'>Triage score: the pipeline's score "
            "derived from the weights of the rules that matched (each case file shows the "
            "raw sum and the rules). It marks where to look first; a rule match is not a "
            "judgement that the entity is malicious.</div>")


def _by_class(view, sev) -> str:
    fs = [f for f in view["findings"] if f.get("severity") == sev]
    n1 = sum(1 for f in fs if f.get("rule_class") == "corpus-validated")
    return f"{len(fs)} <span class='fact-sub'>({n1} class 1)</span>"


def facts_card(view) -> str:
    c = view["counts"]
    by_sev, by_class = c["findings_by_severity"], c["findings_by_class"]
    an = view["anomalies"]

    def row(k, v, dot=""):
        d = f"<i class='dot' style='background:{dot}'></i>" if dot else ""
        return (f"<div class='case-row'><span class='case-k'>{k}</span>"
                f"<span class='case-v fact'>{d}{v}</span></div>")

    ev, ing = view.get("events") or {}, view.get("ingest") or {}
    extra = ""
    if isinstance(ev.get("total"), int):
        extra += row("events in timeline", f"{ev['total']:,}")
    if isinstance(ing.get("files_handled"), int):
        extra += row("files parsed", f"{ing['files_handled']:,} / {num(ing.get('files_seen', '?'))}")
    return ("<div class='card facts'>"
            + row("findings", num(c["findings_total"]))
            + row("class 1 / class 2 (context)", f"{num(by_class.get('corpus-validated', 0))} / "
                  f"{num(by_class.get('known-behavior', 0))}")
            + row("critical-band findings", _by_class(view, "critical"), SEV_COLOR["critical"])
            + row("high-band findings", _by_class(view, "high"), SEV_COLOR["high"])
            + row("rule-scored entities", num(c["entities_total"]))
            + extra
            + row("anomaly scorer", f"<span class='scorer'>{esc(an.get('scorer') or '—')}</span>")
            + "<div class='note' style='margin-top:10px'>The scorer ranks anomalies for "
              "attention. It is never a verdict.</div></div>")


def rules_card(view) -> str:
    """Which rules fired, and — just as telling — which were evaluated and
    did not ("we looked, nothing there")."""
    r = view.get("rules")
    if not r or not isinstance(r.get("findings_by_rule"), dict):
        return "<span class='note'>This run does not record rule coverage.</span>"
    fbr = {k: as_int(v) for k, v in r["findings_by_rule"].items()}
    fired = sorted(((k, v) for k, v in fbr.items() if v), key=lambda kv: (-kv[1], kv[0]))
    quiet = sorted(k for k, v in fbr.items() if not v)
    cls = {}
    for f in view["findings"]:
        cls.setdefault(f.get("rule_id"), (f.get("rule_class"), f.get("title", "")))
    mx = max((v for _, v in fired), default=1)
    rows = []
    for rid, n in fired:
        c, title = cls.get(rid, ("", ""))
        tag = "validated" if c == "corpus-validated" else "context"
        rows.append(
            f"<div class='rl-row' title='{esc(title)}'><span class='rl-id mono'>{esc(rid)}</span>"
            f"<span class='rl-cls {tag}'>{tag}</span>"
            f"<div class='cat-track'><div class='cat-fill' style='width:{100*n/mx:.1f}%'>"
            f"</div></div><span class='cat-val'>{n}</span></div>")
    head = (f"<div class='note' style='margin-bottom:8px'>{num(r.get('evaluated', len(fbr)))} "
            f"rules evaluated · {len(fired)} fired · {len(quiet)} found nothing</div>")
    tail = (f"<div class='note' style='margin-top:10px'>Evaluated, no match: "
            f"<span class='mono'>{esc(', '.join(quiet))}</span></div>" if quiet else "")
    return head + "<div class='rl'>" + "".join(rows) + "</div>" + tail


def ingest_card(view) -> str:
    ing = view.get("ingest")
    if not ing or not isinstance(ing.get("events_by_artifact"), dict):
        return "<span class='note'>This run does not record ingest statistics.</span>"
    arts = sorted(((k, as_int(v)) for k, v in ing["events_by_artifact"].items()),
                  key=lambda kv: -kv[1])
    top, rest = arts[:8], arts[8:]
    mx = max((v for _, v in top), default=1) or 1
    rows = "".join(
        f"<div class='cat-row'><div class='cat-name mono' title='{esc(k)}'>{esc(k)}</div>"
        f"<div class='cat-track'><div class='cat-fill' style='width:{100*v/mx:.1f}%'>"
        f"</div></div><div class='cat-val' style='width:70px'>{v:,}</div></div>"
        for k, v in top)
    files = (f"{num(ing.get('files_seen', '?'))} files seen · "
             f"{num(ing.get('files_handled', '?'))} parsed · "
             f"{num(ing.get('files_skipped', '?'))} skipped · "
             f"{num(ing.get('files_failed', '?'))} failed")
    ev = view.get("events") or {}
    first = str(ev.get("first_timestamp_utc") or "")
    epoch = (" The earliest timestamp, 1601-01-01, is a zero Windows FILETIME — a "
             "placeholder in the artifact, not a real event." if first.startswith("1601") else "")
    more = f" · {len(rest)} more artifact types" if rest else ""
    return (f"<div class='note' style='margin-bottom:8px'>{files}{more}</div>"
            f"<div class='cat ing'>{rows}</div>"
            + (f"<div class='note' style='margin-top:10px'>{epoch.strip()}</div>" if epoch else ""))


def why_score(e, view) -> str:
    """The rules behind an entity's triage score, from its own findings."""
    fs = [view["by_id"][i] for i in e.get("finding_ids", []) if i in view["by_id"]]
    seen, rows = set(), []
    for f in sorted(fs, key=lambda f: -as_int(f.get("weight"))):
        rid = f.get("rule_id")
        if rid in seen:
            continue
        seen.add(rid)
        tag = "validated" if f.get("rule_class") == "corpus-validated" else "context"
        rows.append(f"<div class='ws-row'><span class='mono'>{esc(rid)}</span>"
                    f"<span class='rl-cls {tag}'>{tag}</span>"
                    f"<span class='ws-t'>{esc(f.get('title', ''))}</span>"
                    f"<span class='ws-w'>weight {num(f.get('weight'))}</span></div>")
    if not e.get("listed", True):
        return (f"<div class='cf-h' style='margin-top:14px'>Rules that matched it</div>"
                f"{''.join(rows)}")
    raw = e.get("raw_sum")
    head = (f"Raw sum of rule weights <b>{num(raw)}</b> → triage score "
            f"<b>{num(e.get('score'))}</b>, both as recorded in run.json." if raw is not None
            else "Rules behind its triage score:")
    n1 = sum(1 for f in fs if f.get("rule_class") == "corpus-validated")
    ctx = len(e.get("context_ids", []))
    if len(fs) == 1 and n1 == 1:
        basis = " The 1 finding behind the score is Class 1"
    elif fs and n1 == len(fs):
        basis = f" All {len(fs)} findings behind the score are Class 1"
    else:
        basis = f" {n1} of {len(fs)} findings behind it are Class 1"
    basis += (f"; the {ctx} Class 2 context finding(s) that name it do not add to it."
              if ctx else ".")
    return (f"<div class='cf-h' style='margin-top:14px'>Why it is in the queue</div>"
            f"<div class='note' style='margin-bottom:6px'>{head}{basis} A rule match is a "
            f"reason to look, not a conclusion — the source events settle it.</div>"
            f"{''.join(rows)}")


def anomaly_box(e, view) -> str:
    from .contract import anomaly_of
    an = view["anomalies"]
    a = anomaly_of(view, str(e.get("value", "")))
    total = len(an["scored"])
    if a is None:
        body = (f"Not in the {esc(an.get('scorer') or 'anomaly')} ranking "
                f"({total} entities scored).")
    else:
        body = (f"Position <b>{a['rank']}</b> of {total} in the list as ordered in run.json"
                f" · <b>{esc(fam_pos(a))}</b> within "
                f"<span class='mono'>{esc(a['family'])}</span> · percentile "
                f"{fmt_pct(a['percentile'])}"
                + (" (0–100; 0 = most unusual of its kind)" if an["low_is_unusual"] else "")
                + "<div class='note' style='margin-top:3px'>Percentiles compare a row only "
                  "with others of its family.</div>")
    return (f"<div class='anb'><div class='anb-h'>Prioritisation layer · "
            f"<span class='scorer'>{esc(an.get('scorer') or '—')}</span> · not a verdict"
            f"</div>{body}</div>")


def case_file(e, view) -> str:
    kind = KIND_LABEL.get(e.get("kind"), str(e.get("kind", "")).title())
    techs = "".join(f"<div class='cf-tech'>{tech_label(x)}</div>"
                    for x in e.get("techniques", [])) or "<span class='note'>—</span>"
    listed = e.get("listed", True)
    if listed:
        score = (f"<div class='cf-score'><b>{num(e.get('score', 0))}</b>"
                 f"<span>triage score</span></div>")
        band = sev_chip(e.get("severity", "info"))
    else:
        score = ("<div class='cf-score'><b class='muted'>—</b><span>not scored by the "
                 "rules layer</span></div>")
        band = (f"<span class='note'>highest finding band</span> "
                f"{sev_chip(e.get('severity', 'info'))}")
    cats = (catbars(e["category_scores"]) if isinstance(e.get("category_scores"), dict)
            and e["category_scores"] else "")
    return (
        "<div class='cf'>"
        "<div class='cf-top'><div class='cf-idblock'>"
        f"<div class='cf-kind'>{esc(kind)}</div>"
        f"<div class='cf-name'>{esc(e.get('value', ''))}</div>"
        f"<div class='cf-meta'>{band}"
        f"<span>{_n(e.get('rule_count', 0), 'rule')}</span>"
        f"<span>{_n(e.get('finding_count', 0), 'finding')}"
        f"{' behind its score' if listed else ''}</span>"
        + (f"<span class='note'>+{len(e['context_ids'])} context</span>"
           if listed and e.get("context_ids") else "")
        + "</div></div>"
        f"{score}</div>"
        "<div class='cf-grid'>"
        f"<div><div class='cf-h'>Phases of its findings (not an order)</div>"
        f"{phase_path(e.get('phase_span', []))}</div>"
        f"<div><div class='cf-h'>ATT&amp;CK mapping of its rules <span class='h-note'>"
        f"hover for the name</span></div>{techs}</div></div>"
        + why_score(e, view)
        + (f"<div class='cf-h' style='margin-top:14px'>Score by rule category</div>"
           f"{cats}" if cats else "")
        + anomaly_box(e, view)
        + ("" if listed else
           "<div class='note' style='margin-top:10px'>run.json lists only the "
           "entities the rules layer scored; this one is grouped here by name from "
           "its findings.</div>")
        + "</div>")


def finding_card(f) -> str:
    """One finding as a timeline node: the human title leads, provenance follows."""
    sev = f.get("severity", "info")
    wos = f.get("window_observed_seconds")
    window = (f" · window {wos:.1f}s" if isinstance(wos, (int, float)) else "")
    if str(f.get("time_claim", "")) == "none":
        when = (f"{fmt_ts(f.get('first_timestamp_utc'))} "
                "<span class='tc-none'>presence only — not an event time</span>")
    else:
        when = fmt_ts(f.get("first_timestamp_utc"))
    notes = "".join(f"<div class='fd-note'>{esc(n)}</div>" for n in f.get("notes", []))
    evs = [e for e in f.get("events", []) if isinstance(e, dict)]
    if len(evs) > 1 and any(e.get("timestamp_type") == "presence" for e in evs):
        notes += ("<div class='fd-note'>Viewer note: one of its events is presence-only (a "
                  "key's last-write time), so the rule's title does not establish the "
                  "order of its events. Check each event's time below.</div>")
    return (
        f"<div class='fd'><div class='fd-dot' style='background:"
        f"{SEV_COLOR.get(sev, 'var(--muted)')}'></div>"
        f"<div class='fd-time'>{when}</div>"
        f"<div class='fd-title'>{esc(f.get('title', ''))}</div>"
        f"<div class='fd-meta'>{sev_chip(sev)}{phase_chip(f.get('phase', ''))}"
        f"{class_badge(f.get('rule_class', ''))}"
        f"<span class='fd-rule mono'>{esc(f.get('rule_id', ''))}</span>"
        f"{tech_label(f.get('attack_technique', ''))}</div>"
        f"<div class='fd-id'>finding <span class='hash'>{esc(f.get('finding_id', ''))}"
        f"</span> · rule weight {num(f.get('weight', ''))} · "
        f"{esc(f.get('time_claim', ''))}{window}"
        + (f" · rule v{esc(f.get('rule_version'))}" if f.get("rule_version") else "")
        + f"</div>{notes}</div>")


def event_card(ev) -> str:
    eid = esc(ev.get("event_id", "?"))
    if not ev.get("resolved", False):
        return (f"<div class='evt'><b>event {eid}</b> "
                f"<span class='note'>(anchor only — not in sampled timeline)</span></div>")
    step = f" · step: {esc(ev.get('step'))}" if ev.get("step") else ""
    return (
        f"<div class='evt'><b>{eid}</b> · {esc(ev.get('event_type', ''))} · "
        f"{esc(ev.get('source_artifact', ''))}{step}<br>"
        f"<span class='mono'>{esc(ev.get('timestamp_utc', ''))} "
        f"({esc(ev.get('timestamp_type', ''))})</span><br>"
        f"<span class='mono'>{esc(ev.get('source_file', ''))} :: "
        f"{esc(ev.get('source_locator', ''))}</span>"
        + (f"<br><span class='note'>path: {esc(ev.get('path', ''))}</span>"
           if ev.get('path') else "")
        + "</div>")


def anomaly_context_card(f) -> str:
    ac = f.get("anomaly_context")
    if not isinstance(ac, dict) or not ac.get("entities"):
        return ""
    rows = "".join(
        f"<div><span class='mono'>{esc(a.get('entity'))}</span> · "
        f"{esc(a.get('family'))} · percentile {fmt_pct(a.get('percentile_in_family'))} "
        f"(0–100)</div>"
        for a in ac["entities"] if isinstance(a, dict))
    return (f"<div class='anb'><div class='anb-h'>Prioritisation context · not a verdict"
            f"</div>{rows}<div class='note' style='margin-top:4px'>"
            f"{esc(ac.get('meaning', ''))}</div></div>")


# --------------------------------------------------------------------------- #
# Guide                                                                       #
# --------------------------------------------------------------------------- #

SHORTCUTS = [("1 – 7", "Jump to a page: All, Verdict, Context, Prioritisation, "
                       "Narrative, Downloads, Guide"),
             ("L", "Switch light / dark theme"),
             ("X", "Clear every filter")]


def render_legend() -> str:
    """A key to every symbol the viewer uses."""
    def row(sym, txt):
        return (f"<div class='lg-row'><div class='lg-sym'>{sym}</div>"
                f"<div class='lg-txt'>{txt}</div></div>")
    sev = " ".join(sev_chip(s) for s in ("critical", "high", "medium", "low"))
    ph = phase_path(PHASE_ORDER)
    keys = "".join(row(f"<kbd>{k}</kbd>", v) for k, v in SHORTCUTS)
    return "<div class='lg'>" + "".join([
        "<div class='lg-h'>Findings</div>",
        row(sev, "<b>Severity is the weight of the rules that matched, not an "
                 "assessment of the entity.</b> On a <i>finding</i> it is that rule's "
                 "weight band; on an <i>entity</i> it is the band of its triage score. "
                 "Colour is used for severity only, stepping light to deep so it "
                 "stays readable for colour-blind viewers."),
        row("<span class='pri-score' style='width:auto'>75<span>triage score</span></span>",
            "<b>Triage score</b> — the pipeline's score for an entity, derived from the "
            "weights of the rules that matched it. The case file shows both numbers "
            "run.json records: the raw sum of those weights and the score (e.g. 225 → "
            "99). It marks where to look first. An installer can score <i>high</i> "
            "because a downloaded file was executed — a rule matched, not a sign of "
            "harm. The source events are what settle it."),
        row(class_badge("corpus-validated") + " " + class_badge("known-behavior"),
            "<b>Class</b> — the rule's class as recorded in run.json. The <b>Verdict</b> "
            "page holds Class 1 (corpus-validated) findings and the <b>Context</b> page "
            "Class 2 (known-behavior), which is commonly benign and fires on clean hosts "
            "too. The two are never merged, and neither is a conclusion on its own: "
            "each finding is a rule match to verify in its source events."),
        row(ph, "<b>Phase</b> — the stage vocabulary a rule is filed under. Shown by "
                "name, never by colour, and never as an order: the dot between phases "
                "is not an arrow, and the times are what show the order."),
        row("<span class='tc-none'>presence only</span>",
            "<b>Time claim</b> — some artifacts record that a thing exists, not when "
            "it happened (a registry value carries its key's last-write time). Those "
            "findings are marked, listed after the timed ones, left off the Activity "
            "chart, and excluded by a date range."),
        row("<span class='hash'>3c4423d76fff90f9</span>",
            "<b>finding_id / event_id</b> — content-hash anchors. Stable across "
            "runs, safe to cite; drill entity → finding → event to reach the "
            "<span class='mono'>source_file :: source_locator</span>."),
        row("<span class='chip ph'>file</span>",
            "<b>Entity kind</b> — <i>file</i> is a file name the rules keyed on (not "
            "only executables: documents and archives too), <i>user</i> an account, "
            "<i>host</i> the machine."),
        "<div class='lg-h'>Overview</div>",
        row("<span class='pri-rank'>01</span>",
            "<b>Priority</b> — run.json's rule-scored entities in the pipeline's own "
            "order. The bar is the triage score."),
        row("<div class='lg-bars'><i style='height:40%;background:var(--sev-high)'>"
            "</i><i style='height:90%;background:var(--sev-crit)'></i><i "
            "style='height:60%;background:var(--sev-med)'></i></div>",
            "<b>Activity</b> — timed findings per day, both classes, stacked by "
            "severity. Hover a day for its breakdown and how many are Class 1; use the "
            "<b>Date range</b> filter to focus on days, and open <i>Activity as a "
            "table</i> for the exact counts."),
        row("<span class='kc-node on' style='background:var(--accent)'>1</span>",
            "<b>Phases</b> — a node is filled only by Class 1 findings; Class 2 "
            "matches are shown as <i>+N context</i> beneath it and never light a node. "
            "<b>ATT&amp;CK tiles</b> work the same way. A technique name is what a rule "
            "maps to, not a judgement about any file."),
        row("<span class='rl-cls context'>context</span>",
            "<b>Rule coverage</b> — every rule evaluated, how many findings each "
            "produced, and the ones that found nothing. A zero is a measurement: we "
            "looked."),
        "<div class='lg-h'>Prioritisation and narration</div>",
        row("<span class='scorer'>moda_g</span>",
            "<b>Anomaly scorer</b> — the algorithm that produced the ranking, read "
            "from run.json (it can change). A percentile (0–100) ranks a row only "
            "within its artifact family: <b>0 is the most unusual of its kind</b>. "
            "Position in the full list is the order run.json gives; the within-family "
            "position is what the percentile compares, and tied percentiles share a "
            "position (<i>=12 of 344, 7 tied</i>). Unusual is not malicious — "
            "common OS binaries often lead the list. Detection is the rules layer's job."),
        row("<span class='chip ai'>AI-GENERATED</span>",
            "<b>Narration</b> — prose from a local model about the findings, never "
            "a finding. Shown only when the pipeline accepted it <i>and</i> the "
            "viewer's own re-check passes. The re-check confirms cited rules and names "
            "exist in the run, and looks for the known ways prose goes wrong: numbers "
            "not in the record of what it cites, a score or rank that contradicts the "
            "record, severity given a number, comparisons of suspicion or safety, and "
            "verdict words. It is a floor, not proof — read the prose against the "
            "record shown beside it."),
        "<div class='lg-h'>Run</div>",
        row("<span class='seal'></span>",
            "<b>Manifest seal</b> — every file listed in "
            "<span class='mono'>manifest.sha256</span> is hashed and compared. A "
            "mismatch means a file was altered — provenance broken. A file that is "
            "simply not in the folder shows as absent, not as a mismatch."),
        row("<span class='chip ph'>?view=Verdict</span>",
            "<b>Shareable link</b> — the page, run, filters, theme and selected "
            "entity live in the address bar. Copy it (or use <i>Share this view"
            "</i> in the sidebar) and whoever opens it lands on the same view."),
        "<div class='lg-h'>Keyboard</div>",
        keys,
    ]) + "</div>"
