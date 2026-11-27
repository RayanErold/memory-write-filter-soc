"""
Connection to the language model.

Every other part of the project (agent, LLM-based checks) calls the model through
`chat()` here, so switching models only means changing .env.

Settings come from .env (copy .env.example to .env):
  LLM_PROVIDER=ollama
  OLLAMA_MODEL=llama3.1:8b
  OLLAMA_HOST=http://localhost:11434
"""

import json
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

PROVIDER = os.getenv("LLM_PROVIDER", "ollama")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")

# Fixed settings so results are repeatable. Record these in the report's Methodology.
TEMPERATURE = 0
SEED = 412
TIMEOUT_SECONDS = 300


class LLMError(RuntimeError):
    pass


def chat(system: str, user: str, json_mode: bool = True, seed: int = SEED,
         temperature: float = TEMPERATURE) -> dict:
    """Send one system + user message to the model.

    Returns a dict:
      text       the model's raw reply
      json       the reply parsed as JSON (only when json_mode=True and parsing worked, else None)
      seconds    how long the call took
      tokens_in  prompt tokens (as reported by the model server)
      tokens_out reply tokens
      model      model name used
    """
    if PROVIDER != "ollama":
        raise LLMError(f"Provider '{PROVIDER}' is not set up yet. Use LLM_PROVIDER=ollama.")

    body = {
        "model": OLLAMA_MODEL,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "stream": False,
        "options": {"temperature": temperature, "seed": seed},
    }
    if json_mode:
        body["format"] = "json"

    start = time.time()
    try:
        resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=body, timeout=TIMEOUT_SECONDS)
    except requests.ConnectionError as e:
        raise LLMError(f"Cannot reach Ollama at {OLLAMA_HOST}. Is the Ollama app running?") from e
    if resp.status_code != 200:
        raise LLMError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    text = data.get("message", {}).get("content", "")

    parsed = None
    if json_mode:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None

    return {
        "text": text,
        "json": parsed,
        "seconds": round(time.time() - start, 2),
        "tokens_in": data.get("prompt_eval_count"),
        "tokens_out": data.get("eval_count"),
        "model": data.get("model", OLLAMA_MODEL),
    }


def model_info() -> dict:
    """Name and exact version (digest) of the model, for the report."""
    resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=10)
    resp.raise_for_status()
    for m in resp.json().get("models", []):
        if m.get("name") == OLLAMA_MODEL or m.get("model") == OLLAMA_MODEL:
            return {"name": m.get("name"), "digest": m.get("digest"), "size_gb": round(m.get("size", 0) / 1e9, 2)}
    return {}
