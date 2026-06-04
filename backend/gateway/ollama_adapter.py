"""Sovereign Shield v2 — Ollama (Local) Adapter"""
import os
from typing import Dict, Any

try:
    from langchain_ollama import OllamaLLM
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    _REQUESTS_AVAILABLE = False

OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_REQUEST_TIMEOUT_SECONDS", "12"))
OLLAMA_NUM_PREDICT = int(os.getenv("OLLAMA_NUM_PREDICT", "128"))


class OllamaAdapter:
    def __init__(self):
        if not (_AVAILABLE or _REQUESTS_AVAILABLE):
            raise ImportError("Ollama client dependencies not installed")
        self._models: Dict[str, Any] = {}

    def _get_model(self, model_name: str) -> OllamaLLM:
        if model_name not in self._models:
            self._models[model_name] = OllamaLLM(model=model_name, base_url=OLLAMA_BASE)
        return self._models[model_name]

    def complete(self, prompt: str, context: str = "", system_prompt: str = "",
                 model: str = "ollama/llama3.1", **kwargs) -> Dict[str, Any]:
        _, model_name = model.split("/", 1) if "/" in model else ("ollama", model)

        full_prompt = f"{system_prompt}\n\nContext:\n{context}\n\nQuestion: {prompt}" if context else \
                      f"{system_prompt}\n\nQuestion: {prompt}"

        if _REQUESTS_AVAILABLE:
            response = requests.post(
                f"{OLLAMA_BASE.rstrip('/')}/api/generate",
                json={
                    "model": model_name,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {"num_predict": OLLAMA_NUM_PREDICT},
                },
                timeout=OLLAMA_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
            return {
                "answer": payload.get("response", ""),
                "tokens_used": payload.get("eval_count", 0),
                "total_duration_ns": payload.get("total_duration"),
            }

        if not _AVAILABLE:
            raise ImportError("langchain-ollama not installed")
        llm = self._get_model(model_name)
        answer = llm.invoke(full_prompt)
        return {"answer": answer, "tokens_used": 0}
