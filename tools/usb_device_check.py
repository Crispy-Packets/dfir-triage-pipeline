"""What device backed Z:? Read the SYSTEM hive strings for storage enumeration.

USBSTOR entries mean a USB mass-storage device was attached. VBOX HARDDISK
entries under Disk&Ven mean a virtual disk was attached to the VM. The two
imply different transfer routes off the guest.
"""

import re
from pathlib import Path

HIVE = Path(
    r"C:\Users\SK_FA\dfir-evidence\collection_s1_v2"
    r"\C\Windows\System32\config\SYSTEM"
)

raw = HIVE.read_bytes()
# hive strings are UTF-16LE
text = raw.decode("utf-16-le", errors="ignore")

patterns = {
    "USBSTOR device ids": r"USBSTOR\\[A-Za-z0-9_&.\-]{4,80}",
    "USB VID/PID": r"USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}[^\x00]{0,30}",
    "Disk&Ven (attached disks)": r"Disk&Ven_[A-Za-z0-9_&.\-]{2,60}",
    "VBOX HARDDISK": r"VBOX[ _]HARDDISK[^\x00]{0,40}",
    "New Volume label": r"New Volume",
}

for label, pat in patterns.items():
    hits = sorted(set(re.findall(pat, text)))
    print(f"=== {label}: {len(hits)} distinct ===")
    for h in hits[:12]:
        print(f"    {h.strip()}")
    if not hits:
        print("    (none)")
    print()
