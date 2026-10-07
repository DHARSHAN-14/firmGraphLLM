"""
evaluation.baselines.latte_baseline
==================================
LATTE Baseline Execution Module (ACM TOSEM 2025).

Executes multi-turn LLM taint analysis in isolated mode (without Knowledge Graph grounding).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from llm.reasoning.conversation import DangerousFlow, VulnerabilityAnalyzer
from llm.ranking.scorer import VulnerabilityRanker, RankedVulnerability

log = logging.getLogger(__name__)


class LatteBaselineRunner:
    """Runs ungrounded LLM taint analysis matching LATTE paper."""

    def __init__(self, llm_client):
        self.analyzer = VulnerabilityAnalyzer(llm_client)
        self.ranker = VulnerabilityRanker(llm_weight=1.0, kg_weight=0.0, cwe_weight=0.0)

    def run(self, flows: list[DangerousFlow], binary_name: str) -> list[RankedVulnerability]:
        log.info(f"[LATTE Baseline] Analyzing {len(flows)} flows for '{binary_name}' without KG grounding")
        # No KG evidence provided
        results = self.analyzer.analyze_batch(flows=flows, kg_evidence_map=None)
        func_names = {df.flow_id: (df.function_chain[-1].name if df.function_chain else "unknown") for df in flows}
        return self.ranker.rank(results, function_names=func_names)
