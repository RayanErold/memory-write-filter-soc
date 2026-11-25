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

## Getting started

1. Install Python 3.11 or newer.
2. Create a virtual environment and install the requirements:
   ```
   python -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and choose a model (Ollama or an API key). **Never commit `.env`.**
4. (Optional) Rebuild the dataset: `python scripts/generate_dataset.py`

## Build progress

- [x] Phase 1: Dataset (`data/`)
- [ ] Phase 0: Setup (model reachable from Python)
- [ ] Phase 2: Triage agent (`src/agent.py`)
- [ ] Phase 3: Memory, setup A (`src/memory.py`)
- [ ] Phase 4: Input guardrails, setup B (`src/guardrails.py`)
- [ ] Phase 5: Memory-write filter, setup C (`src/memory_filter.py`)
- [ ] Phase 6: Run the experiment (`src/run_experiment.py`)
- [ ] Phase 7: Analysis (`analysis/`)

## Team rules

- Work on a branch and open a pull request; don't push straight to `main`.
- Do not look at `heldout` attack sequences while designing the filter.
- Keep a short decision log in pull request descriptions (what you chose and why).
