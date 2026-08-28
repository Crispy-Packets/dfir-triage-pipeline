import csv

SP = (r"%USERPROFILE%\AppData\Local\Temp\claude"
      r"\C--Users-user\937f32cb-7885-429e-9af8-92b6e05820fa\scratchpad")

rows = list(csv.DictReader(open(rf"{SP}\w2_s1_v2.csv", encoding="utf-8")))

chain = [r for r in rows if "invoice" in (r["path"] or "").lower()]
chain += [r for r in rows if r["event_type"] == "log_cleared"]
chain.sort(key=lambda r: r["timestamp_utc"])

print("=== SCENARIO 1 CHAIN, reconstructed by the pipeline ===\n")
for r in chain:
    print(f"{r['timestamp_utc']}  {r['timestamp_type']:9} "
          f"{r['source_artifact']:14} {r['event_type']:20} {r['path'][:50]}")

print(f"\ntotal rows in chain: {len(chain)}")

print("\n=== browser downloads in s1_v2, all of them ===")
dl = [r for r in rows if r["source_artifact"] == "browser"]
dl.sort(key=lambda r: r["timestamp_utc"])
for r in dl:
    print(f"  {r['timestamp_utc']}  {r['source_locator']:20} {r['path'][:56]}")
print(f"  count: {len(dl)}")
