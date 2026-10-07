"""
retrieval.graphrag.retriever
============================
Hybrid GraphRAG Retriever: Fuses Vector Search & Graph Traversal.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from ..vector.vector_search import VectorSearcher, VectorResult
from ..graph.graph_traversal import GraphTraversal, EvidenceItem

log = logging.getLogger(__name__)


@dataclass
class RetrievalContext:
    function_id: str
    vector_results: list[VectorResult] = field(default_factory=list)
    graph_evidence: list[EvidenceItem] = field(default_factory=list)
    evidence_score: float = 0.0
    evidence_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "function_id": self.function_id,
            "evidence_score": self.evidence_score,
            "evidence_summary": self.evidence_summary,
            "vector_count": len(self.vector_results),
            "graph_count": len(self.graph_evidence),
        }


class GraphRAGRetriever:
    """Fuses FAISS vector similarity and Neo4j graph traversals."""

    def __init__(self, vector_searcher: VectorSearcher, graph_traversal: GraphTraversal):
        self.vector_searcher = vector_searcher
        self.graph_traversal = graph_traversal

    def retrieve(
        self,
        function_id: str,
        pseudocode: str,
        api_calls: list[str],
        top_k: int = 5,
    ) -> RetrievalContext:
        """Run hybrid retrieval: vector search + graph traversal."""
        # 1. Graph evidence
        graph_evidence = self.graph_traversal.traverse(function_id, api_calls, top_k=top_k)

        # 2. Vector search (token bag-of-words normalized embedding)
        vector_results = []
        if self.vector_searcher and pseudocode:
            q_vec = self._embed_pseudocode(pseudocode)
            if q_vec is not None:
                vector_results = self.vector_searcher.search(q_vec, top_k=top_k)

        # 3. Compute composite evidence score
        evidence_score = self._compute_evidence_score(graph_evidence, vector_results)

        # 4. Synthesize natural language evidence summary for prompts
        evidence_summary = self._synthesize_summary(graph_evidence, vector_results)

        return RetrievalContext(
            function_id=function_id,
            vector_results=vector_results,
            graph_evidence=graph_evidence,
            evidence_score=evidence_score,
            evidence_summary=evidence_summary,
        )

    def _embed_pseudocode(self, pseudocode: str) -> Optional[np.ndarray]:
        """Produce a normalized token frequency vector matching index dimensions."""
        if not self.vector_searcher or not self.vector_searcher.index:
            return None

        dim = self.vector_searcher.index.d
        vec = np.zeros((1, dim), dtype=np.float32)

        tokens = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", pseudocode.lower())
        if not tokens:
            return None

        for tok in tokens:
            idx = abs(hash(tok)) % dim
            vec[0, idx] += 1.0

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def _compute_evidence_score(self, graph_ev: list[EvidenceItem], vec_res: list[VectorResult]) -> float:
        """Score between 0.0 and 1.0 representing strength of grounded evidence."""
        score = 0.0

        # Graph API-CWE associations
        api_cwe_items = [e for e in graph_ev if e.entity_type == "api_cwe"]
        if api_cwe_items:
            score += min(0.4, len(api_cwe_items) * 0.15)

        # Graph patterns
        pattern_items = [e for e in graph_ev if e.entity_type == "vuln_pattern"]
        if pattern_items:
            score += min(0.3, len(pattern_items) * 0.1)

        # Vector results
        vuln_vecs = [v for v in vec_res if v.is_vulnerable]
        if vuln_vecs:
            top_sim = max(v.similarity_score for v in vuln_vecs)
            score += min(0.3, max(0.0, top_sim) * 0.3)

        return min(1.0, score)

    def _synthesize_summary(self, graph_ev: list[EvidenceItem], vec_res: list[VectorResult]) -> str:
        """Synthesize concise evidence block for LLM prompts."""
        lines = []

        api_cwes = [e for e in graph_ev if e.entity_type == "api_cwe"]
        if api_cwes:
            pairs = [f"{e.entity_id} → {e.target_cwe}" for e in api_cwes]
            lines.append(f"Dangerous API associations: {', '.join(pairs)}")

        patterns = [e for e in graph_ev if e.entity_type == "vuln_pattern"]
        if patterns:
            lines.append(f"Known vulnerability patterns: {patterns[0].description} ({patterns[0].target_cwe})")

        vuln_vec = [v for v in vec_res if v.is_vulnerable]
        if vuln_vec:
            top = vuln_vec[0]
            lines.append(f"Similar historical binary '{top.binary}' was vulnerable to {top.cwe} (similarity: {top.similarity_score:.2f})")

        return " | ".join(lines) if lines else "No prior vulnerability pattern matches found in Knowledge Graph."
