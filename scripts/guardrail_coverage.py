"""
How many poison alerts do the input-only guardrails catch? (No model needed.)

  python scripts/guardrail_coverage.py

This only checks whether the guardrail REMOVES the injected text before the
agent sees it. Whether the attack then succeeds still depends on the agent,
which the full experiment (Phase 6) measures. Also reports false alarms on the
normal and legit-memory alerts.
"""

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import guardrails  # noqa: E402


def load(name):
    return json.loads((ROOT / "data" / name).read_text(encoding="utf-8"))


def main():
    attacks = load("attack_sequences.json")
    normal = load("normal_alerts.json")
    legit = load("legit_memory_sequences.json")

    caught, total = Counter(), Counter()
    fam_caught, fam_total = Counter(), Counter()
    for s in attacks:
        blocked = guardrails.apply(s["alerts"][0])[1]["blocked"]
        total[s["injection_style"]] += 1
        caught[s["injection_style"]] += blocked
        fam_total[s["injection_family"]] += 1
        fam_caught[s["injection_family"]] += blocked

    print("Poison alerts caught by the input-only guardrails\n")
    print(f"{'injection style':18s} caught")
    for style in sorted(total):
        print(f"{style:18s} {caught[style]:2d} / {total[style]}")
    print(f"\n{'family':18s} caught")
    for fam in sorted(fam_total):
        print(f"{fam:18s} {fam_caught[fam]:2d} / {fam_total[fam]}")
    print(f"{'ALL':18s} {sum(caught.values()):2d} / {len(attacks)}")

    fp_normal = sum(guardrails.apply(a)[1]["blocked"] for a in normal)
    fp_legit = sum(guardrails.apply(a)[1]["blocked"] for s in legit for a in s["alerts"])
    fp_fill = sum(guardrails.apply(a)[1]["blocked"] for s in attacks for a in s["alerts"][1:])
    print(f"\nFalse alarms: normal alerts {fp_normal}/{len(normal)}, "
          f"legit-memory alerts {fp_legit}/{len(legit)}, filler + trigger alerts {fp_fill}")


if __name__ == "__main__":
    main()
