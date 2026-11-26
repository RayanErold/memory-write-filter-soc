"""
Phase 0 check: is everything ready?

Run from the repo folder:  python scripts/check_setup.py

It checks, in order:
  1. Python version
  2. .env file exists
  3. Ollama is running
  4. The model is downloaded
  5. The model answers a real alert from the dataset in valid JSON
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

OK, FAIL = "[ OK ]", "[FAIL]"


def main() -> int:
    # 1. Python
    if sys.version_info < (3, 10):
        print(f"{FAIL} Python 3.10+ needed, you have {sys.version.split()[0]}")
        return 1
    print(f"{OK} Python {sys.version.split()[0]}")

    # 2. .env
    if not (ROOT / ".env").exists():
        print(f"{FAIL} No .env file. Copy .env.example to .env first.")
        return 1
    print(f"{OK} .env found")

    try:
        import llm
    except ImportError as e:
        print(f"{FAIL} Missing package: {e}. Run: pip install -r requirements.txt")
        return 1

    # 3 + 4. Ollama running, model present
    try:
        info = llm.model_info()
    except Exception:
        print(f"{FAIL} Cannot reach Ollama at {llm.OLLAMA_HOST}. Open the Ollama app (or run: ollama serve).")
        return 1
    print(f"{OK} Ollama is running at {llm.OLLAMA_HOST}")
    if not info:
        print(f"{FAIL} Model '{llm.OLLAMA_MODEL}' not downloaded. Run: ollama pull {llm.OLLAMA_MODEL}")
        return 1
    print(f"{OK} Model {info['name']} ({info['size_gb']} GB, digest {info['digest'][:12]})")

    # 5. Real test: one malicious alert from the dataset, answers removed
    alerts = json.loads((ROOT / "data" / "normal_alerts.json").read_text())
    sample = next(a for a in alerts if a["ground_truth"]["label"] == "malicious")
    visible = {k: v for k, v in sample.items() if k != "ground_truth"}
    system = ("You are a SOC triage assistant. Read the alert and answer ONLY with JSON: "
              '{"decision": "close" or "escalate", "reason": "<one sentence>"}')
    print("... asking the model to triage one alert (the first call can take a minute while the model loads)")
    try:
        out = llm.chat(system, json.dumps(visible, indent=2))
    except llm.LLMError as e:
        print(f"{FAIL} {e}")
        return 1
    if not out["json"] or out["json"].get("decision") not in ("close", "escalate"):
        print(f"{FAIL} Reply was not the expected JSON: {out['text'][:200]}")
        return 1
    print(f"{OK} Model replied in {out['seconds']}s ({out['tokens_in']} tokens in, {out['tokens_out']} out)")
    print(f"       alert {sample['id']} ({sample['ground_truth']['scenario']}), correct answer: escalate")
    print(f"       model said: {out['json']['decision']} - {out['json'].get('reason', '')}")
    print("\nPhase 0 complete. Write down the model name and digest above for your Methodology.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
