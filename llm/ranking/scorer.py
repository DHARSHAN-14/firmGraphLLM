"""
FirmGraph-LLM — Vulnerability Ranker
======================================
Ranks vulnerability analysis results by combining:
  - LLM confidence score (from the End prompt verdict)
  - KG evidence score   (from GraphRAG retrieval — 0.0 if no KG used)

The weighted combination produces a final_score that determines triage order.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from llm.reasoning.conversation import VulnerabilityResult

log = logging.getLogger(__name__)


# ── CWE severity weights (higher = more critical) ─────────────────────────────
CWE_SEVERITY: dict[str, float] = {
    "CWE-78":  1.0,   # OS Command Injection — Critical
    "CWE-120": 0.9,   # Buffer Overflow — High
    "CWE-134": 0.85,  # Format String — High
    "CWE-190": 0.75,  # Integer Overflow — Medium-High
    "CWE-606": 0.6,   # Unchecked Loop Condition — Medium
    "Unknown": 0.5,
    "None":    0.0,
    "Error":   0.0,
}


@dataclass
class RankedVulnerability:
    """A vulnerability result with its computed rank and scores."""
    rank:             int
    flow_id:          str
    binary_name:      str
    function_name:    str          # last function in the chain (sink location)
    cwe:              str
    llm_confidence:   float        # raw confidence from LLM (0–1)
    kg_evidence_score: float       # evidence score from KG retrieval (0–1)
    cwe_severity:     float        # severity weight from CWE_SEVERITY
    final_score:      float        # weighted combination
    result:           VulnerabilityResult = field(repr=False)

    def to_dict(self) -> dict:
        return {
            "rank":               self.rank,
            "flow_id":            self.flow_id,
            "binary_name":        self.binary_name,
            "function_name":      self.function_name,
            "cwe":                self.cwe,
            "llm_confidence":     round(self.llm_confidence, 4),
            "kg_evidence_score":  round(self.kg_evidence_score, 4),
            "cwe_severity":       round(self.cwe_severity, 4),
            "final_score":        round(self.final_score, 4),
            "vulnerable":         self.result.vulnerable,
            "explanation":        self.result.explanation,
            "taint_trace":        self.result.taint_trace,
            "patch_suggestion":   self.result.patch_suggestion,
            "analysis_time_sec":  self.result.analysis_time_sec,
            "kg_evidence_used":   self.result.kg_evidence_used,
        }


class VulnerabilityRanker:
    """
    Ranks a list of VulnerabilityResult objects by a composite score.

    Score formula:
        final_score = (llm_weight  × llm_confidence)
                    + (kg_weight   × kg_evidence_score)
                    + (cwe_weight  × cwe_severity)

    Non-vulnerable results are ranked below all vulnerable results.
    """

    def __init__(
        self,
        llm_weight: float = 0.5,
        kg_weight:  float = 0.3,
        cwe_weight: float = 0.2,
    ):
        """
        Args:
            llm_weight:  Weight for LLM confidence (default 0.5)
            kg_weight:   Weight for KG evidence score (default 0.3)
            cwe_weight:  Weight for CWE severity (default 0.2)
        """
        assert abs(llm_weight + kg_weight + cwe_weight - 1.0) < 1e-6, \
            "Weights must sum to 1.0"
        self.llm_weight = llm_weight
        self.kg_weight  = kg_weight
        self.cwe_weight = cwe_weight

    def rank(
        self,
        results: list[VulnerabilityResult],
        kg_scores: Optional[dict[str, float]] = None,
        function_names: Optional[dict[str, str]] = None,
    ) -> list[RankedVulnerability]:
        """
        Rank a list of VulnerabilityResult objects.

        Args:
            results:        List of VulnerabilityResult from the analyzer
            kg_scores:      Optional dict flow_id → KG evidence score (0–1)
            function_names: Optional dict flow_id → sink function name

        Returns:
            Sorted list of RankedVulnerability (highest final_score first).
        """
        if kg_scores is None:
            kg_scores = {}
        if function_names is None:
            function_names = {}

        ranked: list[RankedVulnerability] = []

        for result in results:
            kg_ev     = float(kg_scores.get(result.flow_id, 0.0))
            cwe_sev   = CWE_SEVERITY.get(result.cwe, 0.5)
            llm_conf  = result.confidence if result.vulnerable else 0.0

            score = (
                self.llm_weight * llm_conf
                + self.kg_weight  * kg_ev
                + self.cwe_weight * cwe_sev
            )
            # Non-vulnerable results get a strictly negative score so they sort after all vulnerable results
            if not result.vulnerable:
                score = -abs(score) - 1.0

            ranked.append(RankedVulnerability(
                rank=0,  # filled after sort
                flow_id=result.flow_id,
                binary_name=result.binary_name,
                function_name=function_names.get(result.flow_id, "unknown"),
                cwe=result.cwe,
                llm_confidence=result.confidence,
                kg_evidence_score=kg_ev,
                cwe_severity=cwe_sev,
                final_score=score,
                result=result,
            ))

        # Sort descending by final_score
        ranked.sort(key=lambda r: r.final_score, reverse=True)

        # Assign ranks
        for i, r in enumerate(ranked):
            r.rank = i + 1

        vuln_count = sum(1 for r in ranked if r.result.vulnerable)
        log.info(
            f"Ranked {len(ranked)} results: {vuln_count} vulnerable "
            f"(weights: llm={self.llm_weight}, kg={self.kg_weight}, cwe={self.cwe_weight})"
        )
        return ranked

    def to_report(self, ranked: list[RankedVulnerability]) -> dict:
        """Produce a structured report dict ready for JSON serialization."""
        vulnerable   = [r for r in ranked if r.result.vulnerable]
        not_vuln     = [r for r in ranked if not r.result.vulnerable]

        cwe_summary: dict[str, int] = {}
        for r in vulnerable:
            cwe_summary[r.cwe] = cwe_summary.get(r.cwe, 0) + 1

        return {
            "total_analyzed":    len(ranked),
            "vulnerable_count":  len(vulnerable),
            "cwe_distribution":  cwe_summary,
            "rankings": [r.to_dict() for r in ranked],
        }


