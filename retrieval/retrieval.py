"""
FirmGraph-LLM — Retrieval Module
=================================
Combines vector similarity (FAISS) + graph traversal (Neo4j) → GraphRAG.
Fully wired to ground LLM reasoning with both semantic function similarity
and multi-hop Knowledge Graph relationships.
"""
import json
import logging
import re
from collections import Counter
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
    function_id:      str
    function_name:    str
    binary:           str
    similarity_score: float
    cwe:              str
    metadata:         dict


class VectorSearcher:
    """FAISS-based function similarity search using normalized token embeddings."""

    def __init__(self, index_path: Path, metadata_path: Path):
        self.index = None
        self.metadata: list[dict] = []
        self._vocab: dict[str, int] = {}
        index_path = Path(index_path)
        metadata_path = Path(metadata_path)

        try:
            import faiss
            if index_path.exists():
                self.index = faiss.read_index(str(index_path))
                log.info(f"Loaded FAISS index: {self.index.ntotal} vectors (dim={self.index.d})")
            if metadata_path.exists():
                self.metadata = json.loads(metadata_path.read_text())
                log.info(f"Loaded {len(self.metadata)} metadata entries")
                self._build_vocab()
        except ImportError:
            log.warning("faiss-cpu not installed — vector search disabled")
        except Exception as e:
            log.error(f"VectorSearcher init failed: {e}")

    def _build_vocab(self):
        """Construct token vocabulary from loaded metadata to embed query pseudocode."""
        if not self.metadata or not self.index:
            return
        all_tokens = []
        for fn in self.metadata:
            code = fn.get("pseudocode", "") + " " + " ".join(fn.get("api_calls", []))
            tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[+\-*/=<>!&|^~]+', code)
            all_tokens.extend([t.lower() for t in tokens if len(t) > 1])

        counter = Counter(all_tokens)
        top_tokens = [tok for tok, _ in counter.most_common(self.index.d)]
        self._vocab = {tok: i for i, tok in enumerate(top_tokens)}

    def embed_text(self, text: str) -> Optional["np.ndarray"]:
        """Convert query code into a normalized unit vector matching the index dimension."""
        if not _NUMPY_AVAILABLE or not self.index or not self._vocab:
            return None
        dim = self.index.d
        vec = np.zeros(dim, dtype=np.float32)

        tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[+\-*/=<>!&|^~]+', text)
        t_lower = [t.lower() for t in tokens if len(t) > 1]
        t_counts = Counter(t_lower)

        for tok, count in t_counts.items():
            if tok in self._vocab:
                vec[self._vocab[tok]] = count

        norm = np.linalg.norm(vec)
        if norm > 1e-9:
            vec /= norm
        return vec

    def search(self, query_embedding: list[float], top_k: int = 5) -> list[VectorSearchResult]:
        """Search FAISS index with raw vector."""
        if not self.is_loaded() or not _NUMPY_AVAILABLE:
            return []
        try:
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
                    cwe=str(meta.get("cwe", "Unknown")),
                    metadata=meta,
                ))
            return results
        except Exception as e:
            log.error(f"Vector search failed: {e}")
            return []

    def search_by_code(self, pseudocode: str, top_k: int = 5) -> list[VectorSearchResult]:
        """Embed code and search index in one step."""
        if not self.is_loaded() or not pseudocode:
            return []
        emb = self.embed_text(pseudocode)
        if emb is None:
            return []
        return self.search(emb.tolist(), top_k=top_k)

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

        # 1. API → CWE associations
        evidence.extend(self.get_api_evidence(api_calls))

        # 2. Cross-firmware historical evidence via shared API sequences
        try:
            if hasattr(self.kg, "get_cross_firmware_evidence"):
                cross_ev = self.kg.get_cross_firmware_evidence(api_calls)
                for row in cross_ev[:5]:
                    evidence.append(GraphEvidence(
                        "VulnPattern",
                        row.get("pattern", "Historical Pattern"),
                        row,
                        "HISTORICAL_CROSS_FIRMWARE",
                        2
                    ))
        except Exception as e:
            log.debug(f"Cross firmware query: {e}")

        # 3. Known VulnPatterns for associated CWEs
        try:
            if hasattr(self.kg, "get_known_vulnerable_patterns"):
                patterns = self.kg.get_known_vulnerable_patterns()
                for p in patterns[:3]:
                    evidence.append(GraphEvidence(
                        "VulnPattern",
                        p.get("id", "pattern"),
                        p,
                        "MAPS_TO_CWE",
                        2
                    ))
        except Exception as e:
            log.debug(f"Known pattern query: {e}")

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
                evidence.append(GraphEvidence(
                    "API", api_name,
                    {"name": api_name, "cwes": cwes},
                    "USES", 1
                ))
                for cwe_id in cwes:
                    evidence.append(GraphEvidence(
                        "CWE", cwe_id,
                        {"id": cwe_id},
                        "ASSOCIATED_WITH", 2
                    ))
        except Exception as e:
            log.debug(f"API evidence query failed: {e}")
        return evidence

    def format_evidence_for_prompt(
        self,
        graph_evidence: list[GraphEvidence],
        vector_results: list[VectorSearchResult],
    ) -> str:
        """Render consolidated GraphRAG evidence for the LLM prompt."""
        if not graph_evidence and not vector_results:
            return "No prior relevant evidence found in Knowledge Graph."

        lines = ["--- Knowledge Graph & Vector Grounding Evidence ---"]

        # 1. Vector similarity matches (historical similar code)
        if vector_results:
            lines.append("## Similar Code Patterns in Knowledge Base:")
            for vr in vector_results[:3]:
                lines.append(
                    f"  &bull; Found similar function `{vr.function_name}` in binary `{vr.binary}` "
                    f"(Similarity: {vr.similarity_score:.3f}, Known CWE: {vr.cwe})"
                )

        # 2. Graph relationships
        if graph_evidence:
            lines.append("## Structured Security Knowledge Graph Relationships:")
            for ev in graph_evidence:
                if ev.entity_type == "API":
                    cwes_str = ", ".join(ev.entity_data.get("cwes", []))
                    lines.append(f"  &bull; API `{ev.entity_id}` is a known vulnerability sink/source mapping to: {cwes_str}")
                elif ev.entity_type == "CWE":
                    lines.append(f"  &bull; Weakness Category: {ev.entity_id}")
                elif ev.entity_type == "VulnPattern":
                    desc = ev.entity_data.get("pattern") or ev.entity_data.get("description", "")
                    cwe = ev.entity_data.get("cwe", "")
                    lines.append(f"  &bull; Prior Vulnerability Pattern: {desc} (affects {cwe})")

        lines.append("--- End Evidence ---")
        return "\n".join(lines)


# ── GraphRAG Retriever (Combined) ─────────────────────────────────────────────

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
        # 1. Vector Search (FAISS)
        vec_results: list[VectorSearchResult] = []
        if self.vs and self.vs.is_loaded() and pseudocode:
            vec_results = self.vs.search_by_code(pseudocode, top_k=top_k)

        # 2. Graph Traversal (Neo4j)
        graph_ev = self.gt.get_evidence_for_function(function_id, api_calls)

        # 3. Format Combined Evidence for LLM Prompt
        summary = self.gt.format_evidence_for_prompt(graph_ev, vec_results)

        # 4. Evidence Grounding Score (0.0 to 1.0)
        v_score = 0.0
        if vec_results:
            top_sim = max(r.similarity_score for r in vec_results)
            v_score = min(1.0, max(0.0, top_sim))

        g_score = min(1.0, len(graph_ev) * 0.15)
        score   = self.vw * v_score + self.gw * g_score

        log.debug(f"GraphRAG [{function_id}]: vec={len(vec_results)} (v_score={v_score:.3f}), "
                  f"graph={len(graph_ev)} (g_score={g_score:.3f}) -> total={score:.3f}")

        return RetrievalContext(
            function_id=function_id,
            vector_results=vec_results,
            graph_evidence=graph_ev,
            evidence_summary=summary,
            evidence_score=score,
        )

    def is_available(self) -> bool:
        return self.gt.kg is not None or (self.vs is not None and self.vs.is_loaded())
