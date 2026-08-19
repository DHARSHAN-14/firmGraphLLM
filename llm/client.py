"""
FirmGraph-LLM — Ollama LLM Client
===================================
Thin wrapper around the Ollama Python client for local LLM inference.
Primary model  : qwen3-coder  (Qwen3 Coder Next — state-of-the-art code reasoning)
Fallback model : qwen2.5-coder:7b-instruct (lighter fallback if RAM constrained)

Install Ollama : curl -fsSL https://ollama.com/install.sh | sh
Pull models    : ollama pull qwen3-coder
                 ollama pull qwen2.5-coder:7b-instruct
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


class OllamaNotAvailableError(RuntimeError):
    """Raised when the Ollama server is unreachable."""
    def __init__(self, base_url: str):
        super().__init__(
            f"Ollama server not reachable at {base_url}.\n"
            "Install:  curl -fsSL https://ollama.com/install.sh | sh\n"
            "Start:    ollama serve\n"
            "Pull:     ollama pull qwen3-coder"
        )


@dataclass
class OllamaClient:
    """
    Wrapper around the Ollama Python client for multi-turn and
    single-turn LLM inference with automatic fallback support.
    """
    model: str = "qwen2.5-coder:7b"
    fallback_model: str = "qwen2.5-coder:7b-instruct"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.4
    max_tokens: int = 2048
    top_p: float = 0.9
    repeat_penalty: float = 1.1
    timeout: int = 120
    _client: object = field(default=None, init=False, repr=False)

    def __post_init__(self):
        try:
            import ollama
            self._client = ollama.Client(host=self.base_url)
        except ImportError:
            raise ImportError(
                "ollama package not installed. Run: pip install ollama"
            )

    # ── Core API ──────────────────────────────────────────────────────────

    def chat(self, messages: list[dict], model: Optional[str] = None) -> str:
        """
        Multi-turn chat completion.

        Args:
            messages: List of {"role": "user"|"assistant"|"system", "content": str}
            model:    Override model name (uses self.model if None)

        Returns:
            The assistant's response as a plain string.

        Raises:
            OllamaNotAvailableError: if the server is down
            RuntimeError: on all other Ollama errors
        """
        target = model or self.model
        options = {
            "temperature":    self.temperature,
            "num_predict":    self.max_tokens,
            "top_p":          self.top_p,
            "repeat_penalty": self.repeat_penalty,
        }
        try:
            response = self._client.chat(
                model=target,
                messages=messages,
                options=options,
            )
            return response["message"]["content"].strip()
        except Exception as e:
            err = str(e).lower()
            if "connection" in err or "refused" in err or "not found" in err:
                raise OllamaNotAvailableError(self.base_url)
            # Model not found → try fallback
            if "not found" in err and target != self.fallback_model:
                log.warning(
                    f"Model '{target}' not found. Retrying with fallback "
                    f"'{self.fallback_model}'."
                )
                return self.chat(messages, model=self.fallback_model)
            raise RuntimeError(f"Ollama chat error: {e}") from e

    def generate(self, prompt: str, model: Optional[str] = None) -> str:
        """
        Single-turn text generation (wraps as a user message).

        Args:
            prompt: The instruction/question string
            model:  Optional model override

        Returns:
            Generated text as a plain string.
        """
        return self.chat(
            messages=[{"role": "user", "content": prompt}],
            model=model,
        )

    # ── Utility ───────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if the Ollama server is reachable and the model is loaded."""
        try:
            models = self._client.list()
            available = [m["model"] for m in models.get("models", [])]
            return self.model in available or self.fallback_model in available
        except Exception:
            return False

    def switch_model(self, model_name: str) -> None:
        """Switch the active model (e.g. to fallback when RAM is low)."""
        log.info(f"Switching model: {self.model} → {model_name}")
        self.model = model_name

    def list_models(self) -> list[str]:
        """Return names of all locally available Ollama models."""
        try:
            models = self._client.list()
            return [m["model"] for m in models.get("models", [])]
        except Exception as e:
            log.error(f"Could not list models: {e}")
            return []

    def timed_generate(self, prompt: str) -> tuple[str, float]:
        """Generate and return (response, elapsed_seconds)."""
        t0 = time.time()
        result = self.generate(prompt)
        return result, time.time() - t0
