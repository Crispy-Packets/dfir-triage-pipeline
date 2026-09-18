"""Every EID a curated channel actually contains is either mapped or declared.

D-057 found EIDs 1 and 2 present in `Microsoft-Windows-Winlogon/Operational`
and absent from `WINLOGON_EIDS`, discarded without ever being seen. The generic
`evtx.x.*` fallback does NOT protect a curated channel: `_artifact_for()`
resolves the channel to its curated family first, and an unmapped EID inside it
is dropped.

Nothing measured that. D-055 (ps_classic dropping `HostApplication`) and D-057
are the same class of defect found three weeks apart, which is the argument for
a test rather than another read-through.

**This test does not require every EID to be parsed.** A curated map is a
deliberate selection and most EIDs in a channel are noise. It requires every
EID to be a DECISION: either in the map, or named in `UNMAPPED_BY_DESIGN`
below with the reason. An EID that is in neither is one nobody has looked at.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers import evtx_windows

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")

#: Curated channels drop 34,556 of 70,873 records across the five collections
#: (D-059). Selectivity is correct -- CD-007 declines to invent semantics for
#: EIDs this project has not studied -- so the audit does NOT require every EID
#: to be parsed. It requires every SIGNIFICANT one to be a decision rather than
#: an accident.
#:
#: "Significant" is defined by volume, below. Declaring all 189 individually
#: would produce 189 lines reading "unsurveyed", which is bureaucracy rather
#: than information; the threshold makes the policy explicit and keeps the
#: declarations meaningful.
#:
#: Raising a channel's threshold to silence a failure is the one edit this file
#: forbids. Lower it, or add the EID with a reason.
SIGNIFICANT_ROWS = 500

#: EIDs above the threshold, or notable regardless of volume. Each is a
#: decision with the reason stated -- that is the whole point of the file.
UNMAPPED_BY_DESIGN: dict[str, dict[int, str]] = {
    "evtx.winlogon": {
        1: "D-057: 117 rows. Winlogon notification subscribe/unsubscribe "
           "lifecycle, not a logon. Found by the audit, not yet studied.",
        2: "D-057: 117 rows, as EID 1.",
    },
    "evtx.powershell": {
        40961: "282 rows. Console startup -- ubiquitous, says nothing about "
               "what ran.",
        40962: "282 rows. Console ready for input; as 40961.",
        53504: "288 rows. Named-pipe/IPC lifecycle, not execution evidence.",
        4103: "30 rows. Module/pipeline logging. Would be worth mapping on a "
              "corpus where it is enabled; 30 rows cannot calibrate a rule.",
        4100: "135 rows. Engine error -- a failure, not an execution.",
    },
    "evtx.ps_classic": {
        800: "30 rows. **A STATED GAP IN THE ATTESTATION MATRIX**, recorded "
             "there as 'legacy PowerShell EID 800' with the not-parsed marker "
             "-- written when this channel was unparsed. The channel is parsed "
             "now and the EID is dropped inside it. 800 is pipeline execution "
             "detail carrying the command line; mapping it needs a CD-007 "
             "entry and a details key. See D-059.",
    },
    "evtx.security": {
        5379: "6,117 rows, the largest dropped EID in the corpus. Credential "
              "Manager read. A burst is a documented credential-access "
              "indicator; a single read is ordinary. Needs a base rate before "
              "a rule, and the volume here is why it has not been taken "
              "casually.",
        4907: "2,751 rows. Audit policy change on an object -- SACL churn, "
              "written constantly by Windows itself.",
        4672: "2,360 rows. Special privileges assigned to a new logon. ON BY "
              "DEFAULT and abundant, contrary to an earlier claim in the "
              "technique grid that has been corrected. The natural "
              "corroboration for lsa_policy, whose rule is blocked on the "
              "SID/name join -- see D-059.",
        4799: "560 rows. Group membership enumerated; ordinary service "
              "behaviour.",
        5058: "526 rows. Key file operation, cryptographic; not user activity.",
        5061: "522 rows. Cryptographic operation; as 5058.",
    },
    "evtx.system": {
        16: "1,386 rows. Kernel-General registry hive flush -- housekeeping.",
        44: "1,279 rows. WindowsUpdateClient download progress.",
        6: "854 rows. Kernel-General, resource lifecycle.",
        7040: "561 rows. Service start-type changed. Forensically relevant in "
              "principle -- a service set to auto-start is persistence -- but "
              "561 rows on this corpus is Windows retuning its own services. "
              "Needs a shape predicate before it can be a rule.",
    },
    "evtx.wmi": {
        5858: "2,856 rows. WMI query error. Volume is diagnostic noise; 5861 "
              "(the binding) is the persistence-relevant record and is mapped.",
        5857: "1,139 rows. Provider started -- lifecycle, not subscription.",
    },
    "evtx.firewall": {
        2097: "2,916 rows. Settings-restore notice, explicitly rejected in "
              "CD-007: it fires on ordinary profile switches.",
    },
    "evtx.bits": {
        16403: "576 rows. Service-internal state; carries no transfer detail.",
    },
    "evtx.rdp": {},
    "evtx.defender": {},
}

needs_evidence = pytest.mark.skipif(
    not EVIDENCE.is_dir() or not os.environ.get("DFIR_TEST_COLLECTION"),
    reason="collection-backed: set DFIR_TEST_COLLECTION",
)

_EID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")


def _curated_channels() -> dict[str, str]:
    """filename fragment -> curated family, from the parser's own table."""
    return dict(evtx_windows._CHANNELS)


def _eids_in(path: Path) -> Counter:
    from evtx import PyEvtxParser

    found: Counter = Counter()
    for record in PyEvtxParser(str(path)).records():
        xml = record.get("data") if isinstance(record, dict) else None
        if not xml:
            continue
        match = _EID.search(xml)
        if match:
            found[int(match.group(1))] += 1
    return found


def _mapped_eids(family: str) -> set[int]:
    for attr in dir(evtx_windows):
        if not attr.endswith("_EIDS"):
            continue
        value = getattr(evtx_windows, attr)
        if not isinstance(value, dict):
            continue
    # The dispatch table the parser itself uses, rather than a second guess.
    table = {
        "evtx.ps_classic": evtx_windows.PS_CLASSIC_EIDS,
        "evtx.defender": evtx_windows.DEFENDER_EIDS,
        "evtx.winlogon": evtx_windows.WINLOGON_EIDS,
        "evtx.firewall": evtx_windows.FIREWALL_EIDS,
        "evtx.bits": evtx_windows.BITS_EIDS,
    }
    if family in table:
        return set(table[family])
    # The four original channels resolve their EIDs inside record_to_event
    # rather than through a map; list them from the contract.
    original = {
        "evtx.security": {4624, 4625, 4688, 4720, 1102},
        "evtx.system": {7045},
        "evtx.powershell": {4104},
        "evtx.wmi": {5861},
        "evtx.rdp": {21, 25},
    }
    return original.get(family, set())


@needs_evidence
def test_every_eid_in_a_curated_channel_is_mapped_or_declared():
    """The audit D-057 showed was missing."""
    root = Path(os.environ["DFIR_TEST_COLLECTION"])
    if not root.is_dir():
        pytest.skip(f"{root} is not a directory")

    channels = _curated_channels()
    undeclared: list[str] = []
    audited = 0

    for path in root.rglob("*.evtx"):
        # The fragments in _CHANNELS begin with "/" because the parser matches
        # them against a POSIX RELATIVE PATH, not against a bare filename.
        # Comparing them to path.name matches nothing and the audit silently
        # examines zero files -- which is what the first version of this test
        # did, passing in 0.10s.
        lowered = path.as_posix().lower()
        family = None
        for fragment, fam in channels.items():
            if fragment.lower() in lowered:
                family = fam
                break
        if family is None:
            continue  # generic evtx.x.*, read uniformly, nothing to audit
        audited += 1

        mapped = _mapped_eids(family)
        declared = set(UNMAPPED_BY_DESIGN.get(family, {}))
        for eid, count in sorted(_eids_in(path).items()):
            if eid in mapped or eid in declared:
                continue
            if count < SIGNIFICANT_ROWS:
                # Below the threshold: dropped, and the policy says so. The
                # per-collection count is what is checked here, so an EID that
                # is significant only in aggregate across all five will not
                # trip this -- the aggregate audit lives in D-059's write-up.
                continue
            undeclared.append(
                f"{family}: EID {eid} present {count}x in {path.name} — "
                f"over the {SIGNIFICANT_ROWS}-row significance threshold and "
                "neither mapped nor declared in UNMAPPED_BY_DESIGN"
            )

    # A green result means nothing if no file was examined. The first version
    # of this test matched _CHANNELS fragments against path.name, found no
    # curated channel at all, and passed.
    assert audited >= 5, (
        f"only {audited} curated channel file(s) found under {root}; the audit "
        "cannot pass vacuously"
    )

    assert undeclared == [], (
        "an EID inside a CURATED channel is being discarded without a decision; "
        "the generic evtx.x.* fallback does not catch these (D-057). Either map "
        "it or declare it with a reason:\n  " + "\n  ".join(undeclared)
    )


def test_the_audit_knows_about_the_defect_that_motivated_it():
    """Pins D-057's specific finding so a future edit cannot quietly drop it."""
    winlogon = UNMAPPED_BY_DESIGN["evtx.winlogon"]
    assert 1 in winlogon and 2 in winlogon, (
        "EIDs 1 and 2 were the D-057 finding; removing them from the declared "
        "set would hide it again"
    )
    assert set(evtx_windows.WINLOGON_EIDS) == {811, 812}


def test_every_curated_family_has_an_entry():
    """A new curated channel must state its unmapped EIDs, even as empty."""
    families = set(_curated_channels().values())
    missing = sorted(families - set(UNMAPPED_BY_DESIGN))
    assert missing == [], (
        f"curated channel(s) with no UNMAPPED_BY_DESIGN entry: {missing}. "
        "Add one, empty if every EID present is mapped."
    )
