"""
FirmGraph-LLM — Retrieval Module
Combines vector similarity (FAISS) + graph traversal (Neo4j) → GraphRAG.
"""
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False
    np = None  # type: ignore

log = logging.getLogger(__name__)

# ── Vector Searcher ───────────────────────────────────────────────────────────

@dataclass
class VectorSearchResult:
    function_id:     str
    function_name:   str
    binary:          str
    similarity_score: float
    metadata:        dict


class VectorSearcher:
    """FAISS-based function similarity search using UniXcoder embeddings."""

    def __init__(self, index_path: Path, metadata_path: Path):
        self.index    = None
        self.metadata: list[dict] = []
        index_path    = Path(index_path)
        metadata_path = Path(metadata_path)

        try:
            import faiss
            if index_path.exists():
                self.index = faiss.read_index(str(index_path))
                log.info(f"Loaded FAISS index: {self.index.ntotal} vectors")
            if metadata_path.exists():
                self.metadata = json.loads(metadata_path.read_text())
                log.info(f"Loaded {len(self.metadata)} metadata entries")
        except ImportError:
            log.warning("faiss-cpu not installed — vector search disabled")
        except Exception as e:
            log.error(f"VectorSearcher init failed: {e}")

    def search(self, query_embedding: list[float], top_k: int = 10) -> list[VectorSearchResult]:
        if not self.is_loaded():
            return []
        if not _NUMPY_AVAILABLE:
            log.warning("numpy not installed — vector search disabled. Run: pip install numpy faiss-cpu")
            return []
        try:
            import faiss
            emb = np.array([query_embedding], dtype=np.float32)
            scores, indices = self.index.search(emb, top_k)
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < 0 or idx >= len(self.metadata):
                    continue
                meta = self.metadata[idx]
                results.append(VectorSearchResult(
                    function_id=meta.get("function_id", str(idx)),
                    function_name=meta.get("name", "unknown"),
                    binary=meta.get("binary", "unknown"),
                    similarity_score=float(score),
                    metadata=meta,
                ))
            return results
        except Exception as e:
            log.error(f"Vector search failed: {e}")
            return []

    def is_loaded(self) -> bool:
        return self.index is not None and len(self.metadata) > 0


# ── Graph Evidence ────────────────────────────────────────────────────────────

@dataclass
class GraphEvidence:
    entity_type:  str
    entity_id:    str
    entity_data:  dict
    relationship: str
    hop_distance: int


class GraphTraversal:
    """Retrieves structured evidence from the KG via multi-hop graph traversal."""

    def __init__(self, kg_retrieval):
        self.kg = kg_retrieval

    def get_evidence_for_function(self, function_id: str, api_calls: list[str]) -> list[GraphEvidence]:
        evidence: list[GraphEvidence] = []
        if not self.kg:
            return evidence

        # 1. Similar functions → their vulnerability patterns and CWEs
        try:
            for row in self.kg.get_similar_functions(function_id, limit=5):
                evidence.append(GraphEvidence("Function", row["id"],
                                              row, "SIMILAR_TO", 1))
        except Exception as e:
            log.debug(f"Similar function query failed: {e}")

        # 2. API → CWE associations
        evidence.extend(self.get_api_evidence(api_calls))

        # Deduplicate by (type, id)
        seen = {}
        for ev in evidence:
            seen[(ev.entity_type, ev.entity_id)] = ev
        return sorted(seen.values(), key=lambda x: x.hop_distance)

    def get_api_evidence(self, api_names: list[str]) -> list[GraphEvidence]:
        if not api_names or not self.kg:
            return []
        evidence = []
        try:
            assoc = self.kg.get_api_cwe_associations(api_names)
            for api_name, cwes in assoc.items():
                evidence.append(GraphEvidence("API", api_name,
                                              {"name": api_name, "cwes": cwes},
                                              "USES", 1))
                for cwe_id in cwes:
                    evidence.append(GraphEvidence("CWE", cwe_id,
                                                  {"id": cwe_id}, "ASSOCIATED_WITH", 2))
        except Exception as e:
            log.debug(f"API evidence query failed: {e}")
        return evidence

    def format_evidence_for_prompt(self, evidence: list[GraphEvidence]) -> str:
        if not evidence:
            return "No relevant evidence found in Knowledge Graph."
        lines = ["--- Knowledge Graph Evidence ---"]
        for ev in evidence:
            lines.append(f"[{ev.entity_type}] {ev.entity_id} (via {ev.relationship})")
            if ev.entity_type == "CWE":
                lines.append(f"  → Known weakness pattern: {ev.entity_id}")
            elif ev.entity_type == "Function":
                lines.append(f"  → Similar function in {ev.entity_data.get('binary','?')}: similarity={ev.entity_data.get('similarity_score',0):.3f}")
        return "\n".join(lines)


# ── GraphRAG Retriever ────────────────────────────────────────────────────────

@dataclass
class RetrievalContext:
    function_id:      str
    vector_results:   list[VectorSearchResult]
    graph_evidence:   list[GraphEvidence]
    evidence_summary: str
    evidence_score:   float


class GraphRAGRetriever:
    """Combines vector similarity + graph traversal for grounded LLM evidence."""

    def __init__(self, vector_searcher: VectorSearcher,
                 graph_traversal: GraphTraversal,
                 vector_weight: float = 0.5,
                 graph_weight:  float = 0.5):
        self.vs = vector_searcher
        self.gt = graph_traversal
        self.vw = vector_weight
        self.gw = graph_weight

    def retrieve(self, function_id: str, pseudocode: str,
                 api_calls: list[str], top_k: int = 5) -> RetrievalContext:
        """Run full GraphRAG pipeline and return structured RetrievalContext."""
        # Vector search (skipped if no embedding available at this stage)
        vec_results: list[VectorSearchResult] = []

        # Graph traversal
        graph_ev = self.gt.get_evidence_for_function(function_id, api_calls)

        # Evidence summary for LLM
        summary = self.gt.format_evidence_for_prompt(graph_ev)

        # Evidence score
        v_score = min(1.0, len(vec_results) * 0.2)
        g_score = min(1.0, len(graph_ev) * 0.1)
        score   = self.vw * v_score + self.gw * g_score

        return RetrievalContext(
            function_id=function_id,
            vector_results=vec_results,
            graph_evidence=graph_ev,
            evidence_summary=summary,
            evidence_score=score,
        )

    def is_available(self) -> bool:
        return self.gt.kg is not None
