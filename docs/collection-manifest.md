# Collection manifest (Day 2)

KAPE target for all three: `KapeTriage`. No `--vhdx`. Source `C:`, dest on guest `Z:\collection_*`, then USB to host repo root.

| ID | Host folder | Snapshot | Guest session | KAPE logs in dest | Notes |
|----|-------------|----------|---------------|-------------------|-------|
| clean_a | `collection_clean_a` | `BASELINE-CLEAN+TOOLS` | `youssef`, idle | `2026-08-19T19_27_26_*` **and** `2026-08-20T14_31_43_*` | Merged dest — later run is 20 Aug 14:31 UTC-ish |
| clean_b | `collection_clean_b` | `BASELINE-CLEAN+TOOLS` again | `admin_local` for KAPE | `2026-08-20T14_47_52_*` | Lab asked `janed` for benign work |
| s1 | `collection_s1` | same snapshot, dirty, no restore before KAPE | `janed` then `admin_local` | `2026-08-21T01_40_18_*` | USB decoy; NAT; log clear |

## Path shapes (actual)

See `groundtruth/scenario1.md`. Prefetch decoy: `INVOICE_SCAN.EXE-A345C2FE.pf`.

## What enters git

- Yes: `groundtruth/scenario1.md`, `groundtruth/person-b-day2-metadata.md`, `groundtruth/person-b-day2-send.md`, this file, `scripts/day2.md`
- No: `collection_clean_*`, `collection_s1` trees, `invoice_scan.exe` (see `.gitignore`)
- Day 3: SHA-256 CSV manifests under `groundtruth/`, still not the evtx/pf blobs
