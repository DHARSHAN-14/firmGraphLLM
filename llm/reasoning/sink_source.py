"""
FirmGraph-LLM — Sink/Source Identifier
========================================
Uses the LLM (via Ollama) to identify taint sinks and sources from
external function names, exactly as described in the LATTE paper.

Key design from LATTE:
  - One-shot prompting with a canonical example
  - Results are CACHEABLE — the same function name always yields the
    same classification regardless of binary (since it depends only on
    the function's semantic meaning, not context)
  - Batch processing with cache hit/miss logging
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from llm.prompts.templates import TEMPLATES

log = logging.getLogger(__name__)


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class SinkInfo:
    """Classification of an external function as a potential taint sink."""
    name: str
    is_sink: bool
    vulnerable_params: list[int] = field(default_factory=list)
    cwe_types: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "name":              self.name,
            "is_sink":           self.is_sink,
            "vulnerable_params": self.vulnerable_params,
            "cwe_types":         self.cwe_types,
            "reason":            self.reason,
        }


@dataclass
class SourceInfo:
    """Classification of an external function as a potential taint source."""
    name: str
    is_source: bool
    output_params: list[int] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "name":          self.name,
            "is_source":     self.is_source,
            "output_params": self.output_params,
            "reason":        self.reason,
        }


# ── Identifier class ───────────────────────────────────────────────────────────

class SinkSourceIdentifier:
    """
    Identifies taint sinks and sources from external function names using LLM.

    Results are cached to disk so repeated analyses of binaries using the
    same dynamic libraries don't re-query the LLM.
    """

    def __init__(self, client, cache_path: Optional[Path] = None):
        """
        Args:
            client:     OllamaClient instance
            cache_path: Optional path to a JSON cache file.
                        Defaults to data/juliet/sink_source_cache.json
        """
        self.client = client
        self._sink_cache:   dict[str, SinkInfo]   = {}
        self._source_cache: dict[str, SourceInfo] = {}

        if cache_path is None:
            cache_path = Path(__file__).resolve().parents[2] / "data" / "juliet" / "sink_source_cache.json"
        self.cache_path = Path(cache_path)

        # Load existing cache on init
        if self.cache_path.exists():
            self.load_cache(self.cache_path)

    # ── Core identification ────────────────────────────────────────────────

    def identify_sink(self, func_name: str) -> SinkInfo:
        """
        Classify a function as a taint sink using the LLM.
        Returns cached result if available.
        """
        if func_name in self._sink_cache:
            log.debug(f"Sink cache hit: {func_name}")
            return self._sink_cache[func_name]

        prompt = TEMPLATES.sink_identification(func_name)
        try:
            response = self.client.generate(prompt)
            parsed = self._parse_json(response)
            info = SinkInfo(
                name=func_name,
                is_sink=bool(parsed.get("is_sink", False)),
                vulnerable_params=parsed.get("vulnerable_params", []),
                cwe_types=parsed.get("cwe_types", []),
                reason=parsed.get("reason", ""),
            )
        except Exception as e:
            log.warning(f"Sink identification failed for '{func_name}': {e}. Defaulting to not-a-sink.")
            info = SinkInfo(name=func_name, is_sink=False, reason=f"Error: {e}")

        self._sink_cache[func_name] = info
        log.info(f"Sink: {func_name} → is_sink={info.is_sink}, cwes={info.cwe_types}")
        return info

    def identify_source(self, func_name: str) -> SourceInfo:
        """
        Classify a function as a taint source using the LLM.
        Returns cached result if available.
        """
        if func_name in self._source_cache:
            log.debug(f"Source cache hit: {func_name}")
            return self._source_cache[func_name]

        prompt = TEMPLATES.source_identification(func_name)
        try:
            response = self.client.generate(prompt)
            parsed = self._parse_json(response)
            info = SourceInfo(
                name=func_name,
                is_source=bool(parsed.get("is_source", False)),
                output_params=parsed.get("output_params", []),
                reason=parsed.get("reason", ""),
            )
        except Exception as e:
            log.warning(f"Source identification failed for '{func_name}': {e}. Defaulting to not-a-source.")
            info = SourceInfo(name=func_name, is_source=False, reason=f"Error: {e}")

        self._source_cache[func_name] = info
        log.info(f"Source: {func_name} → is_source={info.is_source}, params={info.output_params}")
        return info

    # ── Batch operations ───────────────────────────────────────────────────

    def identify_sinks_batch(self, func_names: list[str]) -> dict[str, SinkInfo]:
        """Classify a list of function names as sinks. Returns dict name→SinkInfo."""
        results = {}
        hits = misses = 0
        for name in func_names:
            in_cache = name in self._sink_cache
            results[name] = self.identify_sink(name)
            if in_cache:
                hits += 1
            else:
                misses += 1
        log.info(f"Sink batch: {len(func_names)} functions — {hits} cache hits, {misses} LLM calls")
        return results

    def identify_sources_batch(self, func_names: list[str]) -> dict[str, SourceInfo]:
        """Classify a list of function names as sources. Returns dict name→SourceInfo."""
        results = {}
        hits = misses = 0
        for name in func_names:
            in_cache = name in self._source_cache
            results[name] = self.identify_source(name)
            if in_cache:
                hits += 1
            else:
                misses += 1
        log.info(f"Source batch: {len(func_names)} functions — {hits} cache hits, {misses} LLM calls")
        return results

    def get_sinks(self, func_names: list[str]) -> list[SinkInfo]:
        """Return only the functions identified as sinks."""
        return [info for info in self.identify_sinks_batch(func_names).values() if info.is_sink]

    def get_sources(self, func_names: list[str]) -> list[SourceInfo]:
        """Return only the functions identified as sources."""
        return [info for info in self.identify_sources_batch(func_names).values() if info.is_source]

    # ── Cache persistence ──────────────────────────────────────────────────

    def save_cache(self, path: Optional[Path] = None) -> None:
        """Persist the sink/source cache to a JSON file."""
        target = Path(path) if path else self.cache_path
        target.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "sinks":   {k: v.to_dict() for k, v in self._sink_cache.items()},
            "sources": {k: v.to_dict() for k, v in self._source_cache.items()},
        }
        target.write_text(json.dumps(data, indent=2))
        log.info(f"Cache saved: {len(self._sink_cache)} sinks, {len(self._source_cache)} sources → {target}")

    def load_cache(self, path: Optional[Path] = None) -> None:
        """Load sink/source cache from a JSON file."""
        target = Path(path) if path else self.cache_path
        if not target.exists():
            return
        try:
            data = json.loads(target.read_text())
            for name, d in data.get("sinks", {}).items():
                self._sink_cache[name] = SinkInfo(**{k: v for k, v in d.items()})
            for name, d in data.get("sources", {}).items():
                self._source_cache[name] = SourceInfo(**{k: v for k, v in d.items()})
            log.info(f"Cache loaded: {len(self._sink_cache)} sinks, {len(self._source_cache)} sources from {target}")
        except Exception as e:
            log.warning(f"Failed to load cache from {target}: {e}")

    @property
    def cache_size(self) -> tuple[int, int]:
        """Return (n_sinks_cached, n_sources_cached)."""
        return len(self._sink_cache), len(self._source_cache)

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _parse_json(text: str) -> dict:
        """
        Robustly parse JSON from LLM response.
        Handles markdown code fences (```json ... ```) and leading/trailing text.
        """
        # Strip markdown code fences
        text = re.sub(r"```(?:json)?\s*", "", text)
        text = re.sub(r"```", "", text)
        text = text.strip()

        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Find the first JSON object in the text
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not parse JSON from LLM response: {text[:200]}")
