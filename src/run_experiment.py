"""
Phase 6: run the experiment.

Runs every alert in the dataset through the chosen setups and writes one JSON
line per alert to results/. Answers are hidden from the agent; scoring
happens later in analysis/compute_metrics.py.

  A  no defense                 notes saved as-is, memory shown plainly
  B  input-only guardrails      alert checked before the agent; notes saved as-is
  C  guardrails + memory filter alert checked before the agent; every note goes
                                through memory_filter; memory shown labeled

Usage (from the repo folder, Ollama running):
  python src/run_experiment.py                     # full run: A, B, C on all data (a few hours)
  python src/run_experiment.py --quick             # smoke test: 5 normal, 3 attack, 2 legit per setup
  python src/run_experiment.py --setups C --only attacks
  python src/run_experiment.py --reps 3 --temperature 0.7   # optional repeated runs

The run can be stopped (Ctrl+C) and started again with the same command: it
skips sequences already saved in the output file.
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import agent  # noqa: E402
import guardrails  # noqa: E402
import llm  # noqa: E402
import memory_filter  # noqa: E402
from memory import Memory  # noqa: E402

DATA = ROOT / "data"
RESULTS = ROOT / "results"


def load(name):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def correct_decision(alert):
    return "close" if alert["ground_truth"]["label"] == "benign" else "escalate"


def step(alert, memory: Memory, allowlist, setup, seed, temperature):
    """Process one alert under one setup. Returns a log record (without run metadata)."""
    report = None
    alert_text = None
    if setup in ("B", "C"):
        clean, report = guardrails.apply(alert)
        alert_text = guardrails.wrap_as_data(clean)
    view = "labeled" if setup == "C" else "plain"
    r = agent.triage(alert, memory.for_agent(), allowlist, alert_text=alert_text,
                     memory_view=view, seed=seed, temperature=temperature)

    write = {"requested": r["remember"]}
    if r["remember"]:
        if setup == "C":
            f = memory_filter.apply(memory, r["remember"], alert, r["decision"])
            write.update({"saved": [e["note"] for e in f["save"]], "dropped_claim": f["dropped_claim"],
                          "filter_reason": f["reason"]})
        else:
            memory.add(r["remember"], alert["id"])
            write.update({"saved": [r["remember"]], "dropped_claim": False})

    return {
        "alert": alert["id"],
        "decision": r["decision"],
        "correct": correct_decision(alert),
        "label": alert["ground_truth"]["label"],
        "scenario": alert["ground_truth"]["scenario"],
        "reason": r["reason"],
        "parse_ok": r["parse_ok"],
        "guardrail": report["findings"] if report and report["blocked"] else [],
        "memory_write": write,
        "memory_size_after": len(memory),
        "seconds": r["seconds"],
        "tokens_in": r["tokens_in"],
        "tokens_out": r["tokens_out"],
    }


def run_normal(alerts, allowlist, setup, seed, temperature):
    for a in alerts:
        rec = step(a, Memory(allowlist), allowlist, setup, seed, temperature)
        rec.update({"kind": "normal", "sequence": a["id"], "role": "single"})
        yield a["id"], [rec]


def run_attacks(seqs, allowlist, setup, seed, temperature):
    for s in seqs:
        mem = Memory(allowlist)
        recs = []
        for a in s["alerts"]:
            rec = step(a, mem, allowlist, setup, seed, temperature)
            role = "poison" if a["id"].endswith("-P") else "trigger" if a["id"].endswith("-T") else "filler"
            rec.update({"kind": "attack", "sequence": s["sequence_id"], "role": role,
                        "split": s["split"], "injection_style": s["injection_style"],
                        "injection_family": s["injection_family"], "claim_kind": s["claim_kind"],
                        "target": s["target"]})
            if role == "trigger":
                rec["attack_succeeded"] = rec["decision"] == "close"
                rec["memory_final"] = mem.to_list()
                rec["memory_contaminated"] = any(memory_filter.is_contaminated(e, s["target"])
                                                 for e in mem.entries)
            recs.append(rec)
        yield s["sequence_id"], recs


def run_legit(seqs, allowlist, setup, seed, temperature):
    for s in seqs:
        mem = Memory(allowlist)
        mem.add_analyst_note(s["trusted_note"])  # trusted channel: not an agent note, so not filtered
        recs = []
        for a in s["alerts"]:
            rec = step(a, mem, allowlist, setup, seed, temperature)
            rec.update({"kind": "legit", "sequence": s["sequence_id"], "role": "trigger",
                        "legit_correct": rec["decision"] == s["expected"]["correct_decision"]})
            recs.append(rec)
        yield s["sequence_id"], recs


def done_keys(path: Path) -> set:
    keys = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                keys.add((r["kind"], r["sequence"]))
    return keys


def main():
    p = argparse.ArgumentParser(description="Run setups A, B, C on the dataset.")
    p.add_argument("--setups", nargs="+", default=["A", "B", "C"], choices=["A", "B", "C"])
    p.add_argument("--only", choices=["normal", "attacks", "legit"], help="run one part of the data only")
    p.add_argument("--reps", type=int, default=1, help="repeat the whole run (default 1)")
    p.add_argument("--temperature", type=float, default=llm.TEMPERATURE)
    p.add_argument("--quick", action="store_true", help="small smoke test")
    p.add_argument("--tag", default=datetime.now().strftime("%Y%m%d"), help="name for this run's files")
    args = p.parse_args()

    allowlist = load("allowlist.json")
    normal = load("normal_alerts.json")
    attacks = load("attack_sequences.json")
    legit = load("legit_memory_sequences.json")
    if args.quick:
        rng = random.Random(412)
        normal = rng.sample(normal, 5)
        attacks = rng.sample([s for s in attacks if s["split"] == "dev"], 3)
        legit = rng.sample(legit, 2)
        args.tag = f"{args.tag}_quick"

    parts = [("normal", run_normal, normal), ("attacks", run_attacks, attacks), ("legit", run_legit, legit)]
    if args.only:
        parts = [x for x in parts if x[0] == args.only]

    try:
        info = llm.model_info()
    except Exception:
        print(f"Cannot reach Ollama at {llm.OLLAMA_HOST}. Open the Ollama app first.")
        return 1

    RESULTS.mkdir(exist_ok=True)
    total_calls = sum(len(d) if n != "attacks" else sum(len(s["alerts"]) for s in d) for n, _, d in parts)
    print(f"Model {llm.OLLAMA_MODEL} ({(info.get('digest') or '?')[:12]}), temperature {args.temperature}")
    print(f"{total_calls} model calls per setup per rep; setups {args.setups}; reps {args.reps}\n")

    for rep in range(1, args.reps + 1):
        seed = llm.SEED + rep - 1
        for setup in args.setups:
            out = RESULTS / f"run_{args.tag}_{setup}_rep{rep}.jsonl"
            skip = done_keys(out)
            meta = {"setup": setup, "rep": rep, "model": llm.OLLAMA_MODEL, "model_digest": info.get("digest"),
                    "temperature": args.temperature, "seed": seed}
            start, n_done = time.time(), 0
            with out.open("a", encoding="utf-8") as fh:
                for part, runner, data in parts:
                    kind = {"normal": "normal", "attacks": "attack", "legit": "legit"}[part]
                    todo = [d for d in data
                            if (kind, d["id"] if part == "normal" else d["sequence_id"]) not in skip]
                    for key, recs in runner(todo, allowlist, setup, seed, args.temperature):
                        for r in recs:
                            fh.write(json.dumps({**meta, **r}, ensure_ascii=False) + "\n")
                        fh.flush()  # a whole sequence is saved at once, so a restart never splits one
                        n_done += 1
                        print(f"\r[{setup} rep{rep}] {part}: {key} done ({n_done} items, "
                              f"{time.time() - start:,.0f}s)", end="", flush=True)
            print(f"\n[{setup} rep{rep}] finished -> {out.relative_to(ROOT)}")
    print("\nNext: python analysis/compute_metrics.py")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except llm.LLMError as e:
        print(f"\nModel error: {e}\nFix it, then run the same command again to continue.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped. Run the same command again to continue where it left off.")
        sys.exit(130)
