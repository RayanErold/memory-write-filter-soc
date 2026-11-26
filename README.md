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

## Build progress

- [ ] Phase 0: Setup: code ready (`src/llm.py`, `scripts/check_setup.py`); done when `check_setup.py` passes on your laptop
- [x] Phase 1: Dataset (`data/`)
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
