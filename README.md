# memory-write-filter-soc

A memory-write filter that stops delayed prompt-injection attacks in an AI SOC triage agent, compared with input-only guardrails.

CSCI 412 research project.

## Research question

By what percentage does a memory-write filter reduce the attack success rate of delayed prompt-injection attacks in a SOC triage agent, compared with input-only guardrails, and at what cost to the false-close rate?

## The three setups

| Setup | What it does |
| --- | --- |
| A. No filter | The agent saves anything it wants to memory |
| B. Input-only guardrails (baseline) | CAI-style checks on each alert before the agent reads it |
| C. Memory-write filter (ours) | B, plus a filter that decides what is saved to memory and how much it is trusted |

## Repository layout

```
data/        test dataset (JSON) and its README  <- start here
scripts/     generate_dataset.py (rebuilds data/ exactly, seed 412)
src/         agent, memory, guardrails, memory filter, experiment runner
results/     raw run logs (not committed by default)
analysis/    metrics (ASR, false-close rate, 95% CI) and charts
```

## Getting started (Phase 0)

1. **Install Python 3.11 or newer** from https://www.python.org/downloads/ (on Windows, tick "Add Python to PATH").
2. **Install Ollama** from https://ollama.com/download and open the app. It runs in the background.
3. **Download the model** (about 4.9 GB, one time), in a terminal:
   ```
   ollama pull llama3.1:8b
   ```
4. **Get the code and install the Python packages:**
   ```
   git clone https://github.com/RayanErold/memory-write-filter-soc.git
   cd memory-write-filter-soc
   python -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
5. **Create your settings file:** copy `.env.example` to `.env` (on Windows: `copy .env.example .env`). The defaults already point to Ollama. **Never commit `.env`.**
6. **Check everything works:**
   ```
   python scripts/check_setup.py
   ```
   Every line should say `[ OK ]`. The last check sends one real alert to the model. Write down the model name and digest it prints, because they go in the report's Methodology.

Optional: `python scripts/generate_dataset.py` rebuilds `data/` exactly (seed 412).

### Model settings used in all experiments

| Setting | Value | Why |
| --- | --- | --- |
| Model | `llama3.1:8b` via Ollama | Free, local, citable, version-pinned by digest |
| Temperature | 0 | Most repeatable answers |
| Seed | 412 | Repeatable runs |
| Output | JSON mode | Answers are easy to parse |

## Try the agent (Phase 2)

```
python scripts/demo.py                  # 10 normal alerts: model answer vs correct answer
python scripts/demo.py --n 20           # more alerts
python scripts/demo.py --attack A-007   # one delayed-attack sequence with NO memory filter
python scripts/demo.py --attack random  # a random dev attack sequence
python scripts/demo.py --attack A-007 --setup B   # same attack with input-only guardrails
python scripts/demo.py --attack A-007 --setup C   # same attack with guardrails + memory-write filter
python scripts/guardrail_coverage.py    # which poison alerts the guardrails catch (no model needed)
```

Each call takes a few seconds on a laptop. The `--attack` mode saves every note the agent asks to remember, so you can watch a planted note change the decision on the real attack.

## Run the experiment (Phases 6 and 7)

```
python src/run_experiment.py --quick     # 2-minute smoke test (10 items per setup)
python src/run_experiment.py             # full run: setups A, B, C on all data (~1,600 model calls, a few hours)
python analysis/compute_metrics.py       # results table -> results/summary_<date>.md and .csv
python analysis/make_charts.py           # charts -> results/charts/
```

- The full run can be stopped with Ctrl+C and resumed by running the same command again.
- Every alert is logged to `results/run_<date>_<setup>_rep1.jsonl`: decision, correct answer, guardrail findings, memory writes (requested, saved, dropped), time and tokens.
- 95% confidence intervals are bootstrapped over sequences, so one run is enough. `--reps 3 --temperature 0.7` adds repeated runs if you want them.
- `results/` is not committed by default. To keep the final run in the repo: `git add -f results/summary_* results/charts results/run_<date>_*`.

## Build progress

- [ ] Phase 0: Setup: code ready (`src/llm.py`, `scripts/check_setup.py`); done when `check_setup.py` passes on your laptop
- [x] Phase 1: Dataset (`data/`)
- [ ] Phase 2: Triage agent: code ready (`src/agent.py`); try it with `scripts/demo.py`
- [x] Phase 3: Memory, setup A (`src/memory.py`)
- [x] Phase 4: Input guardrails, setup B (`src/guardrails.py`, coverage check: `scripts/guardrail_coverage.py`)
- [x] Phase 5: Memory-write filter, setup C (`src/memory_filter.py`)
- [ ] Phase 6: Run the experiment: code ready (`src/run_experiment.py`); done when the full run finishes on your laptop
- [ ] Phase 7: Analysis: code ready (`analysis/compute_metrics.py`, `analysis/make_charts.py`)

## Team rules

- Work on a branch and open a pull request; don't push straight to `main`.
- Do not look at `heldout` attack sequences while designing the filter.
- Keep a short decision log in pull request descriptions (what you chose and why).
