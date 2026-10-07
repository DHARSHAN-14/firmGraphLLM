"""
FirmGraph-LLM — Adaptive Hybrid LLM Client (Cloud API + Local Ollama Failover)
==============================================================================
Intelligent dual-tier LLM inference client:
  1. Primary Tier  : High-intelligence Cloud API (Groq Llama-3.3-70B / Gemini / OpenAI)
                     when an API key is present.
  2. Fallback Tier : 100% Local Ollama (qwen2.5:1.5b / 3b / 7b)
                     automatically activated when:
                       - No API key is provided, OR
                       - Cloud token/rate limit is reached (HTTP 429), OR
                       - Cloud quota is exhausted, OR
                       - Network connectivity drops.

Supported Environment Variables (in .env or system env):
  - GROQ_API_KEY    (Default model: llama-3.3-70b-versatile or qwen-2.5-coder-32b)
  - GEMINI_API_KEY  (Default model: gemini-1.5-flash or gemini-1.5-pro)
  - OPENAI_API_KEY  (Default model: gpt-4o or gpt-4o-mini)
  - OLLAMA_MODEL    (Default local model: qwen2.5:1.5b or qwen2.5:3b)
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    # Load .env from project root if present
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    else:
        load_dotenv()
except ImportError:
    pass

import httpx

log = logging.getLogger(__name__)


class OllamaNotAvailableError(RuntimeError):
    """Raised when local Ollama is unreachable."""
    def __init__(self, base_url: str):
        super().__init__(
            f"Ollama server not reachable at {base_url}.\n"
            "Ensure Ollama is running: 'ollama serve'"
        )


@dataclass
class HybridLLMClient:
    """
    Adaptive LLM client with automatic failover between Cloud APIs and Local Ollama.
    """
    # Cloud settings
    api_key: Optional[str] = None
    cloud_provider: Optional[str] = None  # 'groq', 'gemini', 'openai', or None (auto-detect)
    cloud_model: Optional[str] = None

    # Local Ollama settings
    model: str = "qwen2.5:1.5b"
    fallback_model: str = "qwen2.5:3b"
    base_url: str = "http://localhost:11434"

    # Inference settings
    temperature: float = 0.2
    max_tokens: int = 2048
    timeout: int = 60

    _ollama_client: object = field(default=None, init=False, repr=False)
    _active_mode: str = field(default="local", init=False)

    def __post_init__(self):
        # Auto-detect Cloud API Key if not explicitly passed
        self.api_key = (
            self.api_key
            or os.getenv("GROQ_API_KEY")
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("OPENAI_API_KEY")
        )

        if not self.cloud_provider:
            if os.getenv("GROQ_API_KEY") or (self.api_key and self.api_key.startswith("gsk_")):
                self.cloud_provider = "groq"
                self.cloud_model = self.cloud_model or "llama-3.3-70b-versatile"
            elif os.getenv("GEMINI_API_KEY") or (self.api_key and self.api_key.startswith("AIza")):
                self.cloud_provider = "gemini"
                self.cloud_model = self.cloud_model or "gemini-1.5-flash"
            elif os.getenv("OPENAI_API_KEY") or (self.api_key and self.api_key.startswith("sk-")):
                self.cloud_provider = "openai"
                self.cloud_model = self.cloud_model or "gpt-4o-mini"

        # Initialize local Ollama client
        try:
            import ollama
            self._ollama_client = ollama.Client(host=self.base_url)
        except Exception as e:
            log.warning(f"Ollama client init warning: {e}")

        # Choose initial active mode
        if self.api_key and self.cloud_provider:
            self._active_mode = "cloud"
            log.info(f"✨ Cloud API active ({self.cloud_provider}: {self.cloud_model}). Local Ollama ({self.model}) configured as fallback.")
        else:
            self._active_mode = "local"
            log.info(f"💻 No Cloud API key detected. Running in 100% offline mode via Local Ollama ({self.model}).")

    # ── Main Chat Interface ──────────────────────────────────────────────────

    def chat(self, messages: list[dict], model: Optional[str] = None) -> str:
        """
        Execute multi-turn chat completion with automatic failover.
        """
        # Try Cloud API first if configured and in cloud mode
        if self._active_mode == "cloud" and self.api_key:
            try:
                response = self._call_cloud_api(messages)
                return response
            except Exception as e:
                err_str = str(e).lower()
                is_quota_or_rate = any(k in err_str for k in ["429", "quota", "rate limit", "resource_exhausted", "token"])
                if is_quota_or_rate:
                    log.warning(f"⚠️ Cloud API rate/token limit reached: {e}. Seamlessly failing over to Local Ollama ({self.model})...")
                else:
                    log.warning(f"⚠️ Cloud API error: {e}. Failing over to Local Ollama ({self.model})...")

                # Temporarily or permanently switch to local mode
                return self._call_local_ollama(messages, model=model)

        # Default to Local Ollama
        return self._call_local_ollama(messages, model=model)

    def generate(self, prompt: str, model: Optional[str] = None) -> str:
        """Single-turn generation."""
        return self.chat(
            messages=[{"role": "user", "content": prompt}],
            model=model,
        )

    # ── Cloud API Provider Calls ─────────────────────────────────────────────

    def _call_cloud_api(self, messages: list[dict]) -> str:
        """Route to appropriate Cloud API provider."""
        if self.cloud_provider == "groq":
            return self._call_openai_compatible(
                base_url="https://api.groq.com/openai/v1/chat/completions",
                api_key=self.api_key,
                model=self.cloud_model or "llama-3.3-70b-versatile",
                messages=messages,
            )
        elif self.cloud_provider == "openai":
            return self._call_openai_compatible(
                base_url="https://api.openai.com/v1/chat/completions",
                api_key=self.api_key,
                model=self.cloud_model or "gpt-4o-mini",
                messages=messages,
            )
        elif self.cloud_provider == "gemini":
            return self._call_gemini_api(messages)
        else:
            raise ValueError(f"Unsupported cloud provider: {self.cloud_provider}")

    def _call_openai_compatible(self, base_url: str, api_key: str, model: str, messages: list[dict]) -> str:
        """Call standard OpenAI-compatible completions endpoint (Groq / OpenAI)."""
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        wants_json = any("json" in m.get("content", "").lower() for m in messages)
        payload = {
            "model": model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if wants_json:
            payload["response_format"] = {"type": "json_object"}

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(base_url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Cloud API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()

    def _call_gemini_api(self, messages: list[dict]) -> str:
        """Call Google Gemini REST API."""
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.cloud_model}:generateContent?key={self.api_key}"
        # Convert OpenAI-style messages to Gemini contents format
        contents = []
        for m in messages:
            role = "user" if m["role"] in ["user", "system"] else "model"
            contents.append({"role": role, "parts": [{"text": m["content"]}]})

        wants_json = any("json" in m.get("content", "").lower() for m in messages)
        gen_config = {
            "temperature": self.temperature,
            "maxOutputTokens": self.max_tokens,
        }
        if wants_json:
            gen_config["responseMimeType"] = "application/json"

        payload = {
            "contents": contents,
            "generationConfig": gen_config,
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(endpoint, json=payload)
            if resp.status_code != 200:
                raise RuntimeError(f"Gemini API returned HTTP {resp.status_code}: {resp.text}")
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()

    # ── Local Ollama Calls ───────────────────────────────────────────────────

    def _call_local_ollama(self, messages: list[dict], model: Optional[str] = None) -> str:
        """Execute chat completion via local Ollama instance."""
        target = model or self.model
        options = {
            "temperature": self.temperature,
            "num_predict": self.max_tokens,
        }
        try:
            response = self._ollama_client.chat(
                model=target,
                messages=messages,
                options=options,
            )
            return response["message"]["content"].strip()
        except Exception as e:
            err = str(e).lower()
            if "connection" in err or "refused" in err:
                raise OllamaNotAvailableError(self.base_url)
            # Try fallback model if target not found
            if "not found" in err and target != self.fallback_model:
                log.warning(f"Local model '{target}' not found. Retrying with '{self.fallback_model}'...")
                return self._call_local_ollama(messages, model=self.fallback_model)
            raise RuntimeError(f"Local Ollama error: {e}") from e

    # ── Utilities ────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if either Cloud API or Local Ollama is available."""
        if self._active_mode == "cloud" and self.api_key:
            return True
        try:
            models = self._ollama_client.list()
            return len(models.get("models", [])) > 0
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return locally available Ollama models."""
        try:
            models = self._ollama_client.list()
            return [m["model"] for m in models.get("models", [])]
        except Exception:
            return []

    def switch_model(self, model_name: str) -> None:
        """Switch active local model."""
        log.info(f"Switching local model: {self.model} → {model_name}")
        self.model = model_name

    def set_api_key(self, api_key: str, provider: Optional[str] = None, model: Optional[str] = None):
        """Dynamically set or update Cloud API key at runtime."""
        self.api_key = api_key.strip()
        if provider:
            self.cloud_provider = provider
        elif self.api_key.startswith("gsk_"):
            self.cloud_provider = "groq"
            self.cloud_model = model or "llama-3.3-70b-versatile"
        elif self.api_key.startswith("AIza"):
            self.cloud_provider = "gemini"
            self.cloud_model = model or "gemini-1.5-flash"
        elif self.api_key.startswith("sk-"):
            self.cloud_provider = "openai"
            self.cloud_model = model or "gpt-4o-mini"

        if model:
            self.cloud_model = model

        self._active_mode = "cloud"
        log.info(f"🚀 Cloud API configured successfully: {self.cloud_provider} ({self.cloud_model})")


# Backward compatibility alias
OllamaClient = HybridLLMClient
