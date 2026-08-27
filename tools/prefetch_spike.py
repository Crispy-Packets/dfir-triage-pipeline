"""Prefetch library spike -- throwaway diagnostic, NOT part of the package.

    python tools\\prefetch_spike.py "<path to a real .pf>"
"""

from __future__ import annotations

import sys
from datetime import datetime
from importlib import metadata


def main(path: str) -> None:
    from windowsprefetch import Prefetch

    print("=" * 70)
    print("P1  LIBRARY")
    print(f"    pin string:  windowsprefetch=={metadata.version('windowsprefetch')}")
    print(f"    interpreter: {sys.version.split()[0]}")
    print(f"    file:        {path}")

    with open(path, "rb") as fh:
        magic = fh.read(4)
    print("=" * 70)
    print("P2  HEADER")
    print(f"    first 4 bytes: {magic!r}")

    pf = Prefetch(path)

    print("=" * 70)
    print("P3  ATTRIBUTES ON THE RECORD OBJECT")
    for name in sorted(a for a in dir(pf) if not a.startswith("_")):
        value = getattr(pf, name)
        if callable(value):
            continue
        text = repr(value)
        print(f"    {name}: {type(value).__name__} = {text[:120]}")

    print("=" * 70)
    print("P4  EXECUTABLE NAME AND RUN COUNT")
    print(f"    executableName: {getattr(pf, 'executableName', None)!r}")
    print(f"    runCount:       {getattr(pf, 'runCount', None)!r}")

    print("=" * 70)
    print("P5  RUN TIMESTAMPS  <-- decides the parser")
    stamps = getattr(pf, "timestamps", None)
    print(f"    container type: {type(stamps).__name__}")
    if stamps:
        print(f"    count:          {len(stamps)}")
        for i, ts in enumerate(stamps):
            kind = type(ts).__name__
            if isinstance(ts, datetime):
                aware = "AWARE" if ts.tzinfo and ts.utcoffset() is not None else "NAIVE"
                epoch = "  <-- EPOCH/UNUSED SLOT" if ts.year <= 1601 else ""
                print(f"      slot {i}: {kind} {aware}  {ts.isoformat()}{epoch}")
            else:
                print(f"      slot {i}: {kind}  {ts!r}")
        print("    VERDICT NAIVE -> parser must ATTACH UTC, never astimezone()")
        print("    VERDICT AWARE -> parser must CONVERT with astimezone(UTC)")
    else:
        print("    none")

    print("=" * 70)
    print("P6  VOLUME INFORMATION")
    for name in ("volumesInformationArray", "volumeSerialNumber", "volumesCount"):
        print(f"    {name}: {getattr(pf, name, None)!r}"[:200])

    print("=" * 70)
    print("P7  REFERENCED PATH SHAPE  (CD-010 join key)")
    refs = getattr(pf, "resources", None) or getattr(pf, "filenames", None) or []
    for r in list(refs)[:5]:
        print(f"    {r!r}")
    print(f"    total referenced entries: {len(list(refs))}")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])