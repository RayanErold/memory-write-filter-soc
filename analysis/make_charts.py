"""
Phase 7b: charts for the report and slides.

  python analysis/make_charts.py                  # newest full run
  python analysis/make_charts.py --tag 20261201

Reads results/summary_<tag>.csv (run compute_metrics.py first) and writes PNGs to
results/charts/:
  asr_by_setup.png        attack success rate per setup, with 95% CI
  asr_by_family.png       ASR per setup, split by injection family
  asr_vs_false_close.png  the trade-off the RQ asks about
"""

import argparse
import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"
sys.path.insert(0, str(ROOT / "analysis"))
from compute_metrics import newest_tag  # noqa: E402

NAMES = {"A": "A. No defense", "B": "B. Input guardrails", "C": "C. + Memory filter"}
COLORS = {"A": "#9aa5b1", "B": "#4c78a8", "C": "#2e9e6b"}


def read_summary(tag):
    path = RESULTS / f"summary_{tag}.csv"
    if not path.exists():
        sys.exit(f"{path.name} not found. Run: python analysis/compute_metrics.py --tag {tag}")
    with path.open(encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    setups = rows[0][1:]
    data = {s: {} for s in setups}
    for r in rows[1:]:
        for s, v in zip(setups, r[1:]):
            try:
                data[s][r[0]] = float(v)
            except ValueError:
                pass
    return setups, data


def pct(v):
    return 100 * v if v == v else 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tag")
    args = p.parse_args()
    tag = args.tag or newest_tag()
    setups, d = read_summary(tag)
    out = RESULTS / "charts"
    out.mkdir(exist_ok=True)
    labels = [NAMES[s] for s in setups]
    colors = [COLORS[s] for s in setups]

    # 1. ASR by setup with CI
    fig, ax = plt.subplots(figsize=(6, 4))
    vals = [pct(d[s]["asr"]) for s in setups]
    err = [[v - pct(d[s]["asr_ci_low"]) for s, v in zip(setups, vals)],
           [pct(d[s]["asr_ci_high"]) - v for s, v in zip(setups, vals)]]
    ax.bar(labels, vals, color=colors, yerr=err, capsize=6)
    for i, v in enumerate(vals):
        ax.text(i, v + 2, f"{v:.0f}%", ha="center")
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Delayed prompt-injection attacks that succeeded")
    fig.tight_layout()
    fig.savefig(out / "asr_by_setup.png", dpi=200)

    # 2. ASR by family
    fams = [f for f in ("plain_english", "known_pattern", "encoded") if f"asr_family_{f}" in d[setups[0]]]
    fig, ax = plt.subplots(figsize=(7, 4))
    width = 0.8 / len(setups)
    for i, s in enumerate(setups):
        xs = [j + i * width for j in range(len(fams))]
        ax.bar(xs, [pct(d[s][f"asr_family_{f}"]) for f in fams], width, label=NAMES[s], color=COLORS[s])
    ax.set_xticks([j + width * (len(setups) - 1) / 2 for j in range(len(fams))])
    ax.set_xticklabels([f.replace("_", " ") for f in fams])
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Attack success by injection family")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "asr_by_family.png", dpi=200)

    # 3. Trade-off: ASR vs false-close
    fig, ax = plt.subplots(figsize=(5, 4))
    for s in setups:
        ax.scatter(pct(d[s]["false_close"]), pct(d[s]["asr"]), s=120, color=COLORS[s], label=NAMES[s])
    ax.set_xlabel("False-close rate (%)  (lower is better)")
    ax.set_ylabel("Attack success rate (%)  (lower is better)")
    ax.set_title("Security vs. cost")
    ax.set_xlim(left=0)
    ax.set_ylim(bottom=0)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "asr_vs_false_close.png", dpi=200)

    for f in ("asr_by_setup.png", "asr_by_family.png", "asr_vs_false_close.png"):
        print(f"Saved results/charts/{f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
