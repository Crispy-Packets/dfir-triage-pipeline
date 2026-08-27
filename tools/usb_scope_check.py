"""Is the Kingston in all three collections, or only some? And is invoice_scan
sourced from a removable drive anywhere in the re-collected evidence?"""

import re
from pathlib import Path

BASE = Path(r"%USERPROFILE%\dfir-evidence")
SERIAL = "E0D55E6CBD23E6A1F83A003B"

for coll in ("collection_clean_a", "collection_clean_b", "collection_s1_v2"):
    hive = BASE / coll / "C/Windows/System32/config/SYSTEM"
    if not hive.exists():
        print(f"{coll}: SYSTEM hive absent")
        continue
    text = hive.read_bytes().decode("utf-16-le", errors="ignore")
    kingston = SERIAL in text
    usbstor = len(set(re.findall(r"USBSTOR\\Disk&Ven_[A-Za-z0-9_&.\-]{2,60}", text)))
    print(f"{coll}: Kingston serial present={kingston}  distinct USBSTOR Disk&Ven={usbstor}")

# Where does the binary live in the re-collected scenario? E: would mean removable.
print("\n--- invoice_scan references in s1_v2 (path context) ---")
s1 = BASE / "collection_s1_v2"
hits = 0
for p in s1.rglob("*"):
    if not p.is_file() or p.stat().st_size > 40_000_000:
        continue
    try:
        raw = p.read_bytes()
    except OSError:
        continue
    for enc in ("utf-16-le", "latin-1"):
        try:
            t = raw.decode(enc, errors="ignore")
        except Exception:
            continue
        for m in re.finditer(r"[A-Za-z]:\\[^\x00\r\n\"]{0,80}invoice_scan[^\x00\r\n\"]{0,20}", t, re.I):
            s = m.group(0)
            if len(s) < 200:
                print(f"  [{p.name}] {s}")
                hits += 1
                break
    if hits > 25:
        print("  ... truncated")
        break
