"""
FirmGraph-LLM — LLM Module
===========================
Implements the LATTE paper pipeline:
  - Ollama client (local open-source LLM inference)
  - Prompt templates (Start / Middle / End + Sink/Source identification)
  - Sink/Source identifier (LLM-based, cacheable)
  - Multi-turn vulnerability analyzer (LATTE conversation flow)
  - Vulnerability ranker
"""
from llm.client import OllamaClient, OllamaNotAvailableError
from llm.reasoning.sink_source import SinkSourceIdentifier, SinkInfo, SourceInfo
from llm.reasoning.conversation import (
    VulnerabilityAnalyzer,
    DangerousFlow,
    FunctionRecord,
    VulnerabilityResult,
)
from llm.ranking.scorer import VulnerabilityRanker, RankedVulnerability

__all__ = [
    "OllamaClient",
    "OllamaNotAvailableError",
    "SinkSourceIdentifier",
    "SinkInfo",
    "SourceInfo",
    "VulnerabilityAnalyzer",
    "DangerousFlow",
    "FunctionRecord",
    "VulnerabilityResult",
    "VulnerabilityRanker",
    "RankedVulnerability",
]
