"""Establish that the re-collected scenario used no USB device.

Two measurements, both cited in docs/lab-setup.md and the CD-013 addendum:

  1. Which collections enumerate a USBSTOR mass-storage device at all. A device
     active during the collection round would appear in more than one.
  2. Every recorded path for the delivered binary across the scenario artefact
     set. A USB delivery would leave a removable-drive path; an HTTP delivery
     leaves the browser download directory.

    python tools/usb_scope_check.py
"""

from __future__ import annotations

import re
from pathlib import Path

BASE = Path.home() / "dfir-evidence"
SERIAL = "E0D55E6CBD23E6A1F83A003B"
COLLECTIONS = ("collection_clean_a", "collection_clean_b", "collection_s1_v2")

PATH_PATTERN = re.compile(
    r"[A-Za-z]:\\[^\x00\r\n\"]{0,80}invoice_scan[^\x00\r\n\"]{0,20}",
    re.IGNORECASE,
)
USBSTOR_PATTERN = re.compile(r"USBSTOR\\Disk&Ven_[A-Za-z0-9_&.\-]{2,60}")

MAX_FILE_BYTES = 40_000_000


def check_hives() -> None:
    print("=== USBSTOR enumeration per collection ===")
    for coll in COLLECTIONS:
        hive = BASE / coll / "C/Windows/System32/config/SYSTEM"
        if not hive.exists():
            print(f"  {coll}: SYSTEM hive absent")
            continue
        text = hive.read_bytes().decode("utf-16-le", errors="ignore")
        devices = len(set(USBSTOR_PATTERN.findall(text)))
        print(
            f"  {coll}: Kingston serial present={SERIAL in text}  "
            f"distinct USBSTOR devices={devices}"
        )


def check_paths(limit: int = 25) -> None:
    print("\n=== recorded paths for the delivered binary (s1_v2) ===")
    root = BASE / "collection_s1_v2"
    hits = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        for encoding in ("utf-16-le", "latin-1"):
            text = raw.decode(encoding, errors="ignore")
            match = PATH_PATTERN.search(text)
            if match and len(match.group(0)) < 200:
                safe = match.group(0).encode("ascii", "replace").decode("ascii")
                print(f"  [{path.name}] {safe}")
                hits += 1
                break
        if hits >= limit:
            print("  ... truncated")
            return


if __name__ == "__main__":
    check_hives()
    check_paths()
