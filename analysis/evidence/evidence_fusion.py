"""
analysis.evidence.evidence_fusion
=================================
Evidence Fusion & Grounding Synthesis.
Merges structured graph traversals and dense vector matches into a consolidated evidence context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from retrieval.graphrag.retriever import EvidenceItem, RetrievalContext, VectorResult


class EvidenceFusion:
    """Fuses multi-modal evidence from Knowledge Graph and Vector store."""

    @staticmethod
    def fuse(context: RetrievalContext) -> dict:
        return {
            "evidence_score": context.evidence_score,
            "evidence_summary": context.evidence_summary,
            "api_associations": [e.description for e in context.graph_evidence if e.entity_type == "api_cwe"],
            "vulnerability_patterns": [e.description for e in context.graph_evidence if e.entity_type == "vuln_pattern"],
            "similar_functions": [f"{v.binary}:{v.function_id} (sim={v.similarity_score:.2f})" for v in context.vector_results],
        }
