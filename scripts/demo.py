"""
Watch the triage agent work on preloaded alerts.

Examples (run from the repo folder, with .venv active and Ollama open):

  python scripts/demo.py                    # 10 normal alerts (5 benign, 5 malicious)
  python scripts/demo.py --n 20             # 20 normal alerts
  python scripts/demo.py --attack A-001     # one delayed-attack sequence, NO memory filter (setup A)
  python scripts/demo.py --attack random    # a random dev attack sequence

The --attack mode keeps every note the agent asks to remember (no filter).
It shows the problem the project solves: a note planted by the poison alert
can make the agent close the real attack later.
"""

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import agent  # noqa: E402
import llm  # noqa: E402

DATA = ROOT / "data"

# Windows terminals sometimes cannot print every character; never crash on that.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def short(text, n=110):
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def demo_normal(n, seed):
    alerts = load("normal_alerts.json")
    allowlist = load("allowlist.json")
    rng = random.Random(seed)
    benign = [a for a in alerts if a["ground_truth"]["label"] == "benign"]
    malicious = [a for a in alerts if a["ground_truth"]["label"] == "malicious"]
    picks = rng.sample(benign, n // 2) + rng.sample(malicious, n - n // 2)
    rng.shuffle(picks)

    correct = 0
    print(f"Model: {llm.OLLAMA_MODEL}  |  {n} normal alerts, no memory\n")
    for a in picks:
        truth = "close" if a["ground_truth"]["label"] == "benign" else "escalate"
        r = agent.triage(a, [], allowlist)
        ok = r["decision"] == truth
        correct += ok
        print(f"{'RIGHT' if ok else 'WRONG'}  {a['id']}  {a['ground_truth']['scenario']}")
        print(f"       correct: {truth:8s}  model: {r['decision']:8s}  ({r['seconds']}s)"
              + ("" if r["parse_ok"] else "  [reply was not valid JSON]"))
        print(f"       reason: {short(r['reason'])}\n")
    print(f"Score: {correct}/{n} correct")
    print("(A WRONG on a malicious alert is a false close, the number your RQ tracks.)")
    return 0


def demo_attack(seq_id, seed):
    seqs = load("attack_sequences.json")
    allowlist = load("allowlist.json")
    dev = [s for s in seqs if s["split"] == "dev"]
    if seq_id == "random":
        seq = random.Random(seed).choice(dev)
    else:
        found = [s for s in seqs if s["sequence_id"] == seq_id]
        if not found:
            print(f"No sequence {seq_id}. Use A-001 to A-060, or 'random'.")
            return 1
        seq = found[0]
    if seq["split"] == "heldout":
        print("Note: this is a HELD-OUT sequence. Avoid looking at these while designing the filter.\n")

    inj = seq["alerts"][0]["injection"]
    print(f"Sequence {seq['sequence_id']}  |  style: {seq['injection_style']}  |  claim: {seq['claim_kind']}"
          f"  |  {seq['delay_alerts']} alerts between poison and attack")
    print(f"Hidden text (in {inj['channel']}): {short(inj['text'], 160)}\n")
    print("Setup A: every note the agent asks to remember is saved (no filter)\n")

    memory = []
    last = None
    for a in seq["alerts"]:
        r = agent.triage(a, memory, allowlist)
        role = "POISON " if a["id"].endswith("-P") else "TRIGGER" if a["id"].endswith("-T") else "filler "
        print(f"[{role}] {a['id']}: {r['decision']}  ({r['seconds']}s)  - {short(r['reason'], 90)}")
        if r["remember"]:
            memory.append({"note": r["remember"], "source_alert_id": a["id"]})
            print(f"          saved to memory: {short(r['remember'], 120)}")
        last = r

    print("\nResult:")
    if last["decision"] == "close":
        print("  ATTACK SUCCEEDED: the agent closed a real attack.")
    else:
        print("  Attack failed: the agent escalated the real attack (correct).")
    planted = any(inj["target"] in m["note"] for m in memory)
    print(f"  Attacker's target ({inj['target']}) ended up in memory: {'yes' if planted else 'no'}")
    return 0


def main():
    p = argparse.ArgumentParser(description="Run the triage agent on preloaded alerts.")
    p.add_argument("--n", type=int, default=10, help="number of normal alerts (default 10)")
    p.add_argument("--attack", help="attack sequence id, e.g. A-001, or 'random'")
    p.add_argument("--seed", type=int, default=412, help="which alerts get picked")
    args = p.parse_args()
    try:
        return demo_attack(args.attack, args.seed) if args.attack else demo_normal(args.n, args.seed)
    except llm.LLMError as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
