import os
import requests
import json
import logging

logger = logging.getLogger("sentinel.gateway")

class OpenRouterAdapter:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"

    def complete(self, prompt, context="", system_prompt="", model="google/gemini-2.0-flash-001") -> dict:
        if not self.api_key:
            return {"answer": "⚠️ OpenRouter API Key missing. Please set OPENROUTER_API_KEY in .env", "tokens_used": 0}

        # Stability: Ensure we don't send the 'openrouter/' prefix if it accidentally doubled up
        model_id = model.split("/")[-1] if "/" in model and not model.startswith("google/") and not model.startswith("anthropic/") and not model.startswith("openai/") else model
        if model.startswith("openrouter/"):
             model_id = model.replace("openrouter/", "")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://sovereign-shield.local", # Local gateway referer
            "X-Title": "Sovereign Shield Xavira Tech Labs",
            "Content-Type": "application/json"
        }

        # Combine context and prompt
        full_prompt = f"Context: {context}\n\nUser Question: {prompt}" if context else prompt

        data = {
            "model": model_id, 
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": full_prompt}
            ]
        }

        try:
            resp = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            
            # FAIL-SAFE: If specifically 400/404, try a guaranteed free model
            if resp.status_code in (400, 404):
                data["model"] = "google/gemini-2.0-flash-001"
                resp = requests.post(self.api_url, headers=headers, json=data, timeout=30)

            resp.raise_for_status()
            res_json = resp.json()
            
            answer = res_json['choices'][0]['message']['content']
            tokens = res_json.get('usage', {}).get('total_tokens', 0)
            
            return {
                "answer": answer,
                "tokens_used": tokens,
            }
        except Exception as e:
            logger.error(f"OpenRouter Error: {e}")
            return {"answer": f"Cloud model adapter is offline under governed fallback: {str(e)}", "tokens_used": 0}
