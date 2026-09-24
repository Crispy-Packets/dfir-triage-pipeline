# LLM narration — setup and model bench

Narration is **off by default**. Everything below is opt-in; with `DFIR_NARRATION`
unset the pipeline behaves exactly as before and needs no LLM.

## Topology — two supported setups

The pipeline only ever makes an HTTP call to an Ollama endpoint. **Where Ollama
runs is one setting**, `DFIR_NARRATION_ENDPOINT`; nothing in the code changes.

    A. remote (default setup):  [ pipeline host ] --LAN--> [ Mint laptop, Ollama :11434 ]
    B. local:                   [ pipeline host running Ollama on localhost:11434 ]

| | A. Remote (Mint laptop) | B. Local (this machine) |
|---|---|---|
| Endpoint | `http://<mint-ip>:11434` | `http://localhost:11434` (the default) |
| Ollama config | `OLLAMA_HOST=0.0.0.0` so the LAN can reach it | none — localhost is Ollama's default |
| RAM | model and pipeline on separate machines | MODA fit and model share 16 GB; narration runs after the fit, so they do not overlap |
| Demo risk | depends on the LAN and the second laptop being up | one machine |

`tools\run_with_narration.ps1` covers both: it checks the endpoint and that the
model is pulled **before** the ~6-minute pipeline starts, then runs it with
narration on for that run only.

## Option B — Ollama on this (Windows) machine

One time:

    winget install Ollama.Ollama        # or the installer from ollama.com/download
    ollama pull qwen2.5:7b              # ~4.7 GB
    ollama pull qwen2.5:3b              # optional, ~1.9 GB -- fits a 4 GB GPU entirely

Ollama then runs as a tray app on `localhost:11434` and starts with Windows.
Nothing else to configure: `OLLAMA_HOST` is only needed to expose it to the LAN.

Check, then run:

    .\tools\run_with_narration.ps1 -Check
    .\tools\run_with_narration.ps1 `
        -Collection %USERPROFILE%\dfir-evidence\collection_s1_v3 `
        -Baseline   %USERPROFILE%\dfir-evidence\collection_clean_c

Output lands in `outputs\narrated\` (git-ignored): `run.json` with the
`narration` block, `report.html`, `manifest.sha256`.

**Gotcha: a stale endpoint.** If `DFIR_NARRATION_ENDPOINT` is still set in the
shell from a remote run, the pipeline keeps calling the Mint laptop. The helper
always sets it explicitly; by hand, clear it with
`Remove-Item Env:DFIR_NARRATION_ENDPOINT`.

**Hardware (GTX 1050, 4 GB VRAM):** `qwen2.5:7b` does not fit in 4 GB and runs
partly on the CPU — expect minutes per narration. `qwen2.5:3b` fits entirely on
the GPU and is much faster; it has not been benched against the validator here
yet. Ollama keeps a model loaded for 5 minutes after use (`OLLAMA_KEEP_ALIVE`),
which only matters if the next pipeline run starts inside that window.

**Removing it:** uninstall Ollama from Settings -> Apps. The pipeline never
depended on it; with `DFIR_NARRATION` unset nothing calls it.

## Option A — Ollama on the Mint laptop

On the Mint laptop (one time):

    # install Ollama (see ollama.com/download/linux)
    curl -fsSL https://ollama.com/install.sh | sh

    # let it listen on the LAN, not just localhost, so the pipeline host reaches it
    # (systemd): add  Environment="OLLAMA_HOST=0.0.0.0:11434"  to the service, then
    sudo systemctl daemon-reload && sudo systemctl restart ollama

    # pull the candidate models
    ollama pull qwen2.5:7b
    ollama pull qwen2.5:3b
    # optional dedicated-security candidate:
    # ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-GGUF   (check exact tag on HF)

    # find this laptop's LAN IP
    ip addr show | grep 'inet '     # e.g. 192.168.1.50

Open the firewall for 11434 on the LAN only if the Mint box has one enabled.

## On the pipeline host — enable narration

Point the endpoint at the Mint laptop's IP and pick a backend:model:

    # bash / Linux
    export DFIR_NARRATION=ollama:qwen2.5:7b
    export DFIR_NARRATION_ENDPOINT=http://192.168.1.50:11434
    python -m dfir_triage_pipeline <collection> --output tl.csv \
        --run-json run.json --report --baseline <clean_collection_same_host>

    # PowerShell
    $env:DFIR_NARRATION = "ollama:qwen2.5:7b"
    $env:DFIR_NARRATION_ENDPOINT = "http://192.168.1.50:11434"

Run the pipeline first WITHOUT narration if you want the anomaly fit and the LLM
call to not share RAM — on a 16 GB box a MODA fit and a 7B model are tight
together. Narration happens after scoring, in one shot, so sequential is fine.

## What you get in run.json

A top-level `narration` block (run_json v1.5.0), e.g.:

    "narration": {
      "is_verdict": false,
      "backend": "ollama", "model": "qwen2.5:7b",
      "model_digest": "sha256:...", "endpoint": "192.168.1.50:11434",
      "temperature": 0.0, "seed": 20260830,
      "prompt_version": "8", "prompt_sha256": "...", "facts_sha256": "...",
      "ranking_sentences": ["In the moda_g anomaly ranking, ... (code-written)"],
      "generated_at": "2026-09-22T...Z",
      "status": "accepted",              // or "rejected" / "error"
      "validation": {
        "validated": true,
        "citations": {"rule_ids": [...], "exes": [...]},
        "unresolvable": [],
        "mentions_scorer": true,
        "missing_mentions": [],                    // verdict entities not named
        "relation_errors": [],                     // rank / order / kind / pairing
        "describes_ranking_as_detection": false    // advisory, non-fatal
      },
      "text": "invoice_scan.exe was flagged by R-CORR-0001 ..."
    }

- `status: accepted` — every cited rule id / exe / number resolved to run.json;
  `text` is present and report.html renders it (labelled AI-generated).
- `status: rejected` — a citation did not resolve; the prose is kept under
  `narration.rejected.text` for audit and is NOT rendered. `unresolvable` names
  what failed.
- `status: error` — Ollama was unreachable or errored; `error` holds the reason.
  The run itself still succeeded; only narration is absent.

How the viewer should render each state: `docs/handoff-narration-ui.md`.

## Measured: the first live run, and what it changed

`qwen2.5:7b`, prompt v1, collection_s1_v3 scored against clean_c. The narration
came back **`accepted`, `validated: true`, `unresolvable: []`** — zero fabricated
citations. It was still wrong:

> "The moda_g scorer analysed 132 anomalies... The anomaly layer **detected**
> rules such as R-ATOMIC-0002 and R-ATOMIC-0006, with dllhost.exe ranking
> highest, followed by onedrivesetup.exe and runtimebroker.exe..."

It described the **anomaly ranking** and never mentioned `invoice_scan.exe` —
the 99/critical entity the rules actually detected. It also credited the anomaly
layer with detecting, inverting the two-panel rule this pipeline is built on.

Two separate defects, and neither was the model's fault:

1. **The fact slice led with the ranking.** `_facts()` put `top_anomalies` in
   front of a flat list of rule ids and never said which entity was the verdict.
   The anomaly layer's own measured behaviour is that it *ranks* and leads with
   benign OS binaries (see the OD-01 work) — so handing it to a model first
   guarantees the model narrates benign noise. Fixed: `_facts()` is built from
   `entities` (the scored verdict panel) with severity/score/rule_ids per entity,
   worst-severity first; the ranking follows under the key
   `prioritisation_ranking_not_detections`.
2. **The validator checked precision, not recall.** It verified that everything
   cited *existed*. It never checked that the thing that mattered *was cited*, so
   an omission passed. Fixed: `required_mentions` — every `critical` verdict
   entity (or the top-scoring one if none is critical) must appear in the prose
   or the narration is **rejected** with `missing:<entity>`.

Re-validating that exact narration under the new rules returns
`validated: false`, `missing_mentions: ["invoice_scan.exe"]`,
`describes_ranking_as_detection: true`. Prompt bumped to v2 (verdict-first
instructions), and the failed text is frozen as a test fixture in
`tests/test_narration.py::TestCompleteness`.

**The generalisable point:** a citation validator measures *faithfulness to the
facts it was given*. It cannot measure whether those were the right facts, and a
narration can be perfectly faithful and still describe the wrong thing. Emphasis
is a second axis and needs its own check — here, a deterministic recall test
against the same closed vocabulary.

### Second live run: prompt v2, the rank error, and the correction

Same collection, same model, prompt v2. Every check passed — `accepted`,
`unresolvable: []`, `missing_mentions: []` — and the narration led with the
verdict as intended. It also said:

> "`invoice_scan.exe` ... **This file is ranked first in the anomaly scorer
> moda_g prioritisation ranking** ... `dllhost.exe` and `onedrivesetup.exe` with
> a percentile of 0.0, indicating they are considered **less suspicious**"

Three errors, none of which the validator caught at the time:

1. **"ranked first"** — the record says **rank 14 of 443**.
2. **"percentile 0.0 ... less suspicious"** — inverted. `anomalies.meaning` in
   run.json states *"0 is the most unusual row of its kind"*. dllhost.exe at 0.0
   is the MOST unusual, not the least.
3. **"critical severity score of 99"** — merges two fields. 99 is the **triage
   score**; critical is the **severity band**.

**Root cause: a withheld fact, not a model failure.** `_facts()` passed only
`scored[:10]` of the ranking. invoice_scan.exe sits at rank 14, so it was not in
the slice — the model had no rank for the entity it was describing and supplied
one. *A fact withheld is a fact hallucinated.*

**An earlier version of this document drew the wrong conclusion from it.** It
claimed the entity was "not in the ranking at all" and that a closed-vocabulary
validator was *structurally unable* to check such a claim. Both were wrong.
Person A (viewer side) wrote a stdlib reference checker that rejected this exact
text on all three errors, and accepted a corrected summary — the check that was
said to be impossible, in about 80 lines.

**What shipped in response (prompt v3):**

- `_facts()` attaches each verdict entity's **real** `anomaly_rank`
  (`rank`, `of`, `family`, `percentile_in_family`) instead of a truncated top-N.
- **Code writes every ranking sentence** (`_ranking_sentences`), from the record,
  in a fixed template. Prompt v3 forbids the model from ranking prose entirely.
  A template cannot misstate a rank, and it keeps rules-detect/anomalies-rank
  true by construction.
- The validator gained **relation checks**, ported from Person A's checker: rank
  claims against the record (carrying the subject across sentences, so "This
  file is ranked first" is caught), comparative-suspicion vocabulary, and the
  merged `severity score` phrasing. All fatal, reported in `relation_errors`.
- Prompt v3 also fixes the wording: **triage score** for the number, **severity
  / band** for the label, entity named in every sentence, no intent claims.

**The boundary, stated correctly this time:**

> A citation validator measures faithfulness to the facts it was given. Relation
> claims over **enumerable structured fields** — rank, score, band, count — are
> checkable by construction, because the record names the one true value.
> Claims over **open semantics** — intent, motive, causation, "sophisticated" —
> are not, because there is no field to compare them against.

That is a narrower and more useful claim than "relations are unreachable", and
both sides measured it. `test_open_semantic_claims_remain_uncheckable` pins the
part that genuinely cannot be checked, which is why narration remains
`is_verdict: false`, labelled AI-generated, and separated from the verdict panel.

### Third to fifth runs: too short, then a copied example

**v3** fixed all three errors and came back **two sentences of rule codes**:
*"invoice_scan.exe has triage score 99 (critical), from three corpus-validated
rules: R-ATOMIC-0006, R-CORR-0003, and R-CORR-0006. vboxuser has triage score 88
(high), from R-ATOMIC-0002 and R-ATOMIC-0006."* True, and useless to a reader. An
earlier v3 attempt was longer and wrong in a new way: *"vboxuser ... This entity
was executed"* (vboxuser is a user account) and it attached R-ATOMIC-0006 to a
description of a different rule. Same root cause as the rank error: **the model
had rule ids and not what they mean**, so it either listed codes or guessed.

**v4** gives the model `verdict_findings`: one entry per corpus-validated
finding on a verdict entity, with its rule, **title** (what it found), the
entities, and `time_utc` — given only for observed times; a presence-only time
is a registry key's last-write time and is withheld. Entities carry a `kind`
(program / user account). Findings are ordered by rule id, not time, so the list
does not invite a story. Validator additions, all fatal:

| Check | Catches |
|---|---|
| score superlative **verified** against the scores | "onedrive.exe has the highest triage score" (v3 had *banned* the phrase and so rejected true statements — 99 is the highest) |
| order words (then, after, before, followed by …) | "downloaded, then deleted" — the record has the deletion at 10:30, *before* the download at 10:44 |
| clock times and dates must be in the record | an invented "09:14 UTC" |
| a user account is never "executed" | "vboxuser ... This entity was executed" |
| a rule cited in a sentence must belong to its subject | R-CORR-0001 cited for invoice_scan.exe |

Checked against five texts: the shipped v2 text and the v3 "vboxuser executed"
text are **rejected**; v3's bare text, Person A's hand-corrected summary and the
prompt's example are **accepted**.

v4's output was correct in every clause — and nearly **verbatim the prompt's
worked example**, which had been written from this same run. A correct output
that proves nothing: the answer was in the question. **v5** replaces the example
with invented names, scores and times (`updater_x.exe`, `alice`, `host-7`), and
`test_prompt_example_carries_no_evidence` keeps real corpus names out of it.

### Sixth and seventh runs: every concrete example leaks

The invented example leaked too — just different details. **v5** wrote *"the
System event log"* for a clear recorded in `Security.evtx`, copying "System"
from the example. The facts had never said *which* log was cleared (the rule
title is only "Windows event log cleared"); v4 had only been right because it
was copying. **v6** added each finding's `evidence` paths (so the log name is
in the record) and a log-name check (reading the `.evtx` file name, not the
path — every log path contains `System32`). It then wrote *"an event log on
host-7"*: the example's host. The record says `winvm`.

| Prompt | Example | What leaked |
|---|---|---|
| v4 | written from this run | the whole answer — correct, and proves nothing |
| v5 | invented instance | "System event log" |
| v6 | invented instance, no log name | host "host-7" |
| v7 | **template with `<blanks>`** | nothing |

**A 7B model copies whatever concrete detail its example contains.** Swapping
which fake details appear only swaps which ones leak. v7's example is a
template — `<program>`, `<score>`, `<log name>`, `<host>` — so there is nothing
to copy, and an unfilled `<blank>` in the output is rejected. Host names in
"log on X" are now checked against the findings' entities.

**v7 output** (accepted at the time — and **not** correct in every clause, as
was first written here; see the correction below):

> invoice_scan.exe has the highest triage score in this run (99, critical),
> from 3 corpus-validated rules. invoice_scan.exe was executed (last run 11:50
> UTC) and is registered to run at logon (R-ATOMIC-0006). For the user account
> vboxuser (triage score 88, high), the Security event log on the host was
> cleared at 12:15 UTC (R-ATOMIC-0002).

"Security" came from the evidence path this time, not an example. The
validator's first verdict on this text was a false reject — it read "on the
host **was**" as a host named "was"; fixed with a stop-list and a test.

**Correction (prompt v8).** v7 was reported as correct in every clause. It
was not. *"invoice_scan.exe was executed (last run 11:50 UTC) and is
registered to run at logon (R-ATOMIC-0006)"* — 11:50 is the prefetch time of
**R-CORR-0003**; R-ATOMIC-0006 is the autorun value and carries no time and
no execution. The pairing check passed because R-ATOMIC-0006 does belong to
invoice_scan.exe — it is the wrong rule for what the sentence says. In the
viewer, that citation opens a record with no 11:50 in it. v7 also left out
the Recycle Bin deletion (R-CORR-0006) entirely.

v8 adds three fatal checks: **a clock time must sit in the same sentence as
the rule it belongs to**; **every corpus-validated finding on the critical
entity must be cited** by rule id; and **at least 3 sentences** (Person A's
floor — without it the per-finding rule is met by a list of codes, which is
what v3 was). Regression over every real text: v2, v3a, v3b, v6 and v7 are
rejected, each for its own fault; Person A's corrected summary is accepted.

**Method note:** iterate on prompts with a narration-only call against an
existing run.json (~3 min on CPU), not the full pipeline (~6 min+). And test
the validator against every past output after each change — several fixes
here each introduced a false reject that only showed up on a real text.

## Benching models (this module IS the harness)

To compare candidates, run the same pipeline once per model tag and read the
validation block from each run.json — no separate script:

    for M in qwen2.5:7b qwen2.5:3b ; do
      DFIR_NARRATION=ollama:$M DFIR_NARRATION_ENDPOINT=http://192.168.1.50:11434 \
        python -m dfir_triage_pipeline <collection> --output /tmp/tl.csv \
        --run-json /tmp/run_$M.json --baseline <clean_same_host>
      echo "== $M =="
      python -c "import json;d=json.load(open('/tmp/run_${M}.json'));v=d['narration']['validation'];print('unresolvable',v['unresolvable'],'scorer',v['mentions_scorer'],'status',d['narration']['status'])"
    done

**Pick the smallest model with `unresolvable: []` (which now includes
`missing:`, `missing_finding:` and `too_short:` — it must name the verdict and
every finding on it), `describes_ranking_as_detection: false`, and acceptable
latency.** `mentions_scorer` is informational only: since prompt v3 the model
is forbidden ranking prose, and the code-written ranking sentences name the
scorer. Zero fabrications AND the
verdict named is the bar. That is the same measure-don't-assert rule the scorer
choice used — a number, not a model table.

If a model still buries the verdict when the facts hand it over plainly, that is
the model, and it fails the bench. That is what the bench is for.

## Removal

Delete `core/narration.py`, `core/citations.py`, the `narration` hook in
`__main__.py`, `_narration_panel` in `report_html.py`, and revert
`RUN_JSON_VERSION`. The default path imports none of it, so removal cannot affect
scoring or the rest of the pipeline.
