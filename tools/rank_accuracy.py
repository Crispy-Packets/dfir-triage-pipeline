"""Ranking accuracy, MODA*-G vs Isolation Forest.

Labels are FIXED from docs/evidence/srv22-analysis.md before any score is read:
  broad  = every attacker tool or payload the analysis names (and the nmap suite)
  strict = the payload pair and PsExec only
Everything else ranked is treated as not-attack (unlabelled, not proven benign).

Metrics, all computed from the rank order only:
  ROC AUC   chance that a random attack entity outranks a random other one (0.5 = coin flip)
  AP        average precision over the ranking (chance level = share of attack entities)
  P@10      attack entities among the top 10
  first     rank of the first attack entity
"""

import json
from pathlib import Path

ROOT = str(Path(__file__).resolve().parent.parent / "outputs")
BROAD = {"rename.exe", "dir.exe", "psexec.exe", "psexec64.exe", "nmap-7.93-setup.exe",
         "nmap.exe", "ncat.exe", "zenmap.exe", "nping.exe", "npcap-1.71.exe"}
STRICT = {"rename.exe", "dir.exe", "psexec.exe", "psexec64.exe"}


def order(run):
    doc = json.load(open(f"{ROOT}\\{run}\\run.json", encoding="utf-8"))
    ents = doc["anomalies"]["scored_entities"]
    seen, out = set(), []
    for e in ents:  # an entity may appear once per family; keep its best rank
        n = e["entity"].lower()
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def metrics(ranked, labels):
    pos = [i for i, n in enumerate(ranked, 1) if n in labels]
    n, p = len(ranked), len(pos)
    neg = n - p
    # AUC via ranks: for each positive, the negatives ranked below it
    auc = sum((n - r) - (p - k - 1) for k, r in enumerate(pos)) / (p * neg)
    ap = sum((k + 1) / r for k, r in enumerate(pos)) / p
    return {"n": n, "attack ranked": p, "AUC": auc, "AP": ap, "chance AP": p / n,
            "P@10": sum(1 for r in pos if r <= 10), "first": pos[0], "ranks": pos}


for label_name, labels in (("broad", BROAD), ("strict", STRICT)):
    print(f"== {label_name} labels ({len(labels)} named) ==")
    for run, scorer in (("srv22_crosshost", "MODA*-G"), ("srv22_crosshost_if", "IF")):
        m = metrics(order(run), labels)
        print(f"  {scorer:8s} AUC {m['AUC']:.3f} | AP {m['AP']:.3f} (chance {m['chance AP']:.3f})"
              f" | attack in top 10: {m['P@10']}/{m['attack ranked']} | first at {m['first']}"
              f" | ranks {m['ranks']} of {m['n']}")

# s1_v3: ONE labelled attack entity, so AUC is its rank position and nothing more
print("== s1_v3 (one labelled attack entity, documented ranks) ==")
for scorer, rank in (("MODA*-G", 14), ("IF", 40)):
    print(f"  {scorer:8s} rank {rank}/443 -> AUC {(443 - rank) / 442:.3f}")
