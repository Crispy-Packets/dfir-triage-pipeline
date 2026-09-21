from dfir_triage_pipeline.__main__ import main
from dfir_triage_pipeline.core import manifest


def test_rejects_non_directory(tmp_path, capsys):
    bad = tmp_path / "nope"
    assert main([str(bad), "--output", str(tmp_path / "t.csv")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_empty_collection_still_writes_header(tmp_path):
    out = tmp_path / "out" / "timeline.csv"
    assert main([str(tmp_path), "--output", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("timestamp_utc,")


def test_run_json_report_chain_covers_every_artifact_in_the_manifest(tmp_path):
    """The whole point of the manifest is that a report can prove which run
    produced it -- so every artifact the run writes must be inside the hash.

    This asserts the COUPLING, not the pieces: the manifest must name all four
    files AND every recorded hash must match the bytes on disk. The pieces are
    tested in test_run_json; nothing else tests that `_write_run_artifacts`
    writes the report BEFORE the manifest. Move `report_html_mod.write` below
    `write_manifest` and this fails with three names, not four -- the
    "verification that cannot fail on the thing it checks" pattern, caught here.

    An empty collection is enough: 0 events -> 0 findings, but every writer
    still fires (the verdict, context and prioritisation panels each have an
    empty branch, and run.json.build takes scores=[]). No corpus needed.
    """
    out = tmp_path / "run" / "run.json"
    assert (
        main(
            [
                str(tmp_path),
                "--output", str(tmp_path / "timeline.csv"),
                "--run-json", str(out),
                "--report",
            ]
        )
        == 0
    )

    manifest_path = out.with_name("manifest.sha256")
    names = {
        line.partition("  ")[2]
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert names == {"run.json", "findings.csv", "anomalies.csv", "report.html"}
    # Recompute every hash from the bytes on disk: catches a writer whose
    # returned hash drifts from what it wrote, and a report left outside the set.
    assert manifest.verify_manifest(manifest_path) == []