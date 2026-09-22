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
        "mentions_scorer": true
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

**Pick the smallest model with `unresolvable: []`, `mentions_scorer: true`, and
acceptable latency.** Zero fabricated citations is the bar. That is the same
measure-don't-assert rule the scorer choice used — a number, not a model table.

## Removal

Delete `core/narration.py`, `core/citations.py`, the `narration` hook in
`__main__.py`, `_narration_panel` in `report_html.py`, and revert
`RUN_JSON_VERSION`. The default path imports none of it, so removal cannot affect
scoring or the rest of the pipeline.
