"""
Sovereign Shield v2 — Multi-Model Gateway (Router)
Routes governed prompts to any AI model backend transparently.
Deployment modes:
  - AIRGAP: Ollama local models only
  - CLOUD/HYBRID: Still default to the local Ollama model unless cloud adapters are explicitly enabled.
"""
import os
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("sentinel.gateway")

DEPLOYMENT_MODE = os.getenv("DEPLOYMENT_MODE", "airgap").lower()  # airgap | cloud | hybrid
CLOUD_ADAPTERS_ENABLED = os.getenv("CLOUD_ADAPTERS_ENABLED", "false").lower() == "true"


class ModelRouter:
    """
    Unified model gateway. Accepts a governed (already-redacted) prompt
    and routes it to the appropriate backend.
    """

    LOCAL_MODEL = f"ollama/{os.getenv('OLLAMA_MODEL', 'llama3.1')}"

    DEFAULT_MODEL_MAP = {
        "airgap": LOCAL_MODEL,
        "cloud": LOCAL_MODEL,
        "hybrid": LOCAL_MODEL,
    }

    def __init__(self):
        self.mode = DEPLOYMENT_MODE
        self._adapters: Dict[str, Any] = {}
        self._loaded = False

    def _load_adapters(self):
        """Lazily load adapters based on deployment mode."""
        if self._loaded:
            return
        if self.mode in ("airgap", "hybrid"):
            try:
                from .ollama_adapter import OllamaAdapter
                self._adapters["ollama"] = OllamaAdapter()
            except ImportError:
                logger.warning("Ollama adapter unavailable")

        if self.mode in ("cloud", "hybrid") and CLOUD_ADAPTERS_ENABLED:
            if os.getenv("OPENAI_API_KEY"):
                try:
                    from .openai_adapter import OpenAIAdapter
                    self._adapters["openai"] = OpenAIAdapter()
                except ImportError:
                    logger.warning("OpenAI adapter unavailable")

            if os.getenv("ANTHROPIC_API_KEY"):
                try:
                    from .anthropic_adapter import AnthropicAdapter
                    self._adapters["anthropic"] = AnthropicAdapter()
                except ImportError:
                    logger.warning("Anthropic adapter unavailable")

            if os.getenv("GEMINI_API_KEY"):
                try:
                    from .gemini_adapter import GeminiAdapter
                    self._adapters["gemini"] = GeminiAdapter()
                except ImportError:
                    logger.warning("Gemini adapter unavailable")

            if os.getenv("OPENROUTER_API_KEY"):
                try:
                    from .openrouter_adapter import OpenRouterAdapter
                    self._adapters["openrouter"] = OpenRouterAdapter()
                except ImportError:
                    logger.warning("OpenRouter adapter unavailable")
        elif self.mode in ("cloud", "hybrid"):
            logger.info("Cloud adapters disabled; Sovereign Shield will use local AI only.")
        self._loaded = True

    def route(
        self,
        prompt: str,
        preferred_model: Optional[str] = None,
        department: Optional[str] = None,
        context: Optional[str] = None,
        system_prompt: Optional[str] = None,
        sensitivity_score: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Route a governed prompt to the best available model.
        Returns: {answer, model_used, tokens_used, fallback_used}
        """
        force_airgap = sensitivity_score is not None and sensitivity_score > 7.0
        self._load_adapters()
        target = preferred_model or self.DEFAULT_MODEL_MAP.get(self.mode, self.LOCAL_MODEL)
        if force_airgap:
            target = self.LOCAL_MODEL
        provider, model_name = self._parse_model(target)

        if force_airgap and provider != "ollama":
            provider = "ollama"
            target = self.LOCAL_MODEL

        # Attempt primary
        adapter = self._adapters.get(provider)
        if adapter:
            try:
                result = adapter.complete(
                    prompt=prompt,
                    context=context or "",
                    system_prompt=system_prompt or self._default_system_prompt(),
                    model=target,
                )
                result["model_used"] = target
                result["fallback_used"] = False
                result["airgap_forced"] = force_airgap
                return result
            except Exception as e:
                logger.error(f"Primary adapter '{provider}' failed: {e}")

        # Fallback to Ollama in hybrid mode
        if self.mode == "hybrid" and "ollama" in self._adapters:
            try:
                logger.warning(f"Falling back to Ollama from {provider}")
                result = self._adapters["ollama"].complete(
                    prompt=prompt,
                    context=context or "",
                    system_prompt=system_prompt or self._default_system_prompt(),
                    model=self.LOCAL_MODEL,
                )
                result["model_used"] = self.LOCAL_MODEL
                result["fallback_used"] = True
                result["airgap_forced"] = force_airgap
                return result
            except Exception as e:
                logger.error(f"Fallback Ollama also failed: {e}")

        return {
            "answer": "Local Sentinel AI is unavailable. Start Ollama and pull the configured local model.",
            "model_used": "none",
            "fallback_used": False,
            "airgap_forced": force_airgap,
            "tokens_used": 0,
        }

    @staticmethod
    def _parse_model(model_str: str):
        """Parse 'provider/model-name' into (provider, model)."""
        parts = model_str.split("/", 1)
        if len(parts) == 2:
            return parts[0].lower(), parts[1]
        return "ollama", model_str

    @staticmethod
    def _default_system_prompt() -> str:
        return (
            "You are Vault AI, the private local assistant inside Sovereign Shield by Xavira Tech Labs. "
            "Answer like a capable general-purpose AI assistant: explain, plan, draft, reason, summarize, "
            "write code, analyze business/security questions, and help the user get work done. "
            "You run through the local governed security gateway, so never claim to be an external cloud model. "
            "All user data has already been scanned and sensitive values may be replaced "
            "with pseudonym tokens such as [Aadhaar_1] or [PAN_1]. Treat those as protected placeholders. "
            "Do not ask for, infer, reveal, reconstruct, or bypass masked personal/secret data. "
            "Be direct, useful, and professional."
        )

    def list_available(self) -> Dict[str, bool]:
        """Return which adapters are currently available."""
        self._load_adapters()
        return {name: True for name in self._adapters}


# Singleton
model_router = ModelRouter()
