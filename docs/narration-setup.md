# LLM narration — setup and model bench

Narration is **off by default**. Everything below is opt-in; with `DFIR_NARRATION`
unset the pipeline behaves exactly as before and needs no LLM.

## Topology

Ollama runs on a **separate Linux Mint laptop**, not on the pipeline machine. The
pipeline only makes an HTTP call to it. Nothing about Ollama is installed on the
Windows/pipeline host.

    [ pipeline host ]  --HTTP-->  [ Mint laptop running Ollama :11434 ]

## On the Mint laptop (one time)

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
      "prompt_version": "1", "prompt_sha256": "...",
      "generated_at": "2026-09-22T...Z",
      "status": "accepted",              // or "rejected" / "error"
      "validation": {
        "validated": true,
        "citations": {"rule_ids": [...], "exes": [...]},
        "unresolvable": [],
        "mentions_scorer": true,
        "missing_mentions": [],                    // verdict entities not named
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

### Second live run: prompt v2, and a residual error the validator cannot catch

Same collection, same model, prompt v2. Every check passes — `accepted`,
`unresolvable: []`, `missing_mentions: []`,
`describes_ranking_as_detection: false`, `mentions_scorer: true` — and the
narration now leads with the verdict:

> "`invoice_scan.exe` has been detected with a critical severity score of 99,
> triggered by rules R-ATOMIC-0006, R-CORR-0003, and R-CORR-0006. **This file is
> ranked first in the anomaly scorer moda_g prioritisation ranking**, which
> orders entities based on their percentile within their family. The ranking
> includes entities like `dllhost.exe` and `onedrivesetup.exe` with a percentile
> of 0.0, indicating they are considered less suspicious compared to
> `invoice_scan.exe`."

The bolded clause is **false**. `invoice_scan.exe` is not ranked first in the
prioritisation ranking — `dllhost.exe` is. `invoice_scan.exe` does not appear in
the top-10 ranking slice **at all**; the model was never shown a rank for it. It
inferred one, presumably because an entity that is the critical verdict "ought
to" also top the ranking.

That inference is exactly the conflation the two-panel architecture exists to
prevent, and the disagreement it papers over is this project's own OD-01
finding: the rules detect `invoice_scan.exe`, while the anomaly layer ranks
benign OS binaries first. The narration asserts the two agree. They do not.

The last sentence is wrong in the same direction: a *lower* percentile is *more*
anomalous under this scorer, so "percentile of 0.0 ... less suspicious" inverts
the meaning. The number 0.0 is real and resolves, so it validates.

**Why no check catches this, and why that is the finding.** The claim fabricates
nothing (every rule id, exe and number resolves), omits nothing (the critical
entity is named), and attributes correctly (it says the ranking *orders*, not
detects). It is a **false relational claim between two facts that were each
supplied correctly** — a third failure mode, beyond precision and recall, and
one a closed-vocabulary validator is structurally unable to reach: validating it
would mean checking an assertion *about the relationship between* facts, not the
facts themselves, and the space of such assertions is not enumerable.

This is left in deliberately rather than patched away with a prompt rule. It is
the honest boundary of the approach:

> Citation validation bounds what a narration can *invent*. It cannot bound what
> a narration can *imply*. A narration that cites only real facts, omits nothing
> required, and attributes each panel correctly can still assert a relationship
> between those facts that is false — and no amount of vocabulary checking will
> see it.

Which is why the narration is `is_verdict: false`, rendered behind an
AI-generated label, separated from the verdict panel, and never substituted for
the findings it describes. The architecture already assumed the prose could be
wrong. This run is the measurement showing that assumption was correct.

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
`missing:` — it must name the verdict), `describes_ranking_as_detection: false`,
`mentions_scorer: true`, and acceptable latency.** Zero fabrications AND the
verdict named is the bar. That is the same measure-don't-assert rule the scorer
choice used — a number, not a model table.

If a model still buries the verdict when the facts hand it over plainly, that is
the model, and it fails the bench. That is what the bench is for.

## Removal

Delete `core/narration.py`, `core/citations.py`, the `narration` hook in
`__main__.py`, `_narration_panel` in `report_html.py`, and revert
`RUN_JSON_VERSION`. The default path imports none of it, so removal cannot affect
scoring or the rest of the pipeline.
