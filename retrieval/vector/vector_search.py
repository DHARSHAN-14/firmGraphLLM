"""
retrieval.vector.vector_search
==============================
Vector Searcher using FAISS (IndexFlatIP / Cosine Similarity).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np

log = logging.getLogger(__name__)


@dataclass
class VectorResult:
    function_id: str
    binary: str
    similarity_score: float
    cwe: str = ""
    is_vulnerable: bool = False
    pseudocode: str = ""


class VectorSearcher:
    """Queries a FAISS vector index of function embeddings."""

    def __init__(self, index_path: Path, metadata_path: Path):
        self.index_path = Path(index_path)
        self.metadata_path = Path(metadata_path)
        self.index = None
        self.metadata: list[dict] = []
        self._load()

    def _load(self):
        if not self.index_path.exists() or not self.metadata_path.exists():
            log.info("Vector index or metadata not found; vector retrieval disabled.")
            return

        try:
            import faiss
            self.index = faiss.read_index(str(self.index_path))
            self.metadata = json.loads(self.metadata_path.read_text())
            log.info(f"Loaded FAISS index: {self.index.ntotal} vectors (dim={self.index.d})")
            log.info(f"Loaded {len(self.metadata)} metadata entries")
        except Exception as e:
            log.warning(f"Failed to load FAISS index: {e}")
            self.index = None

    def search(self, query_vector: np.ndarray, top_k: int = 5) -> list[VectorResult]:
        """Search FAISS index by dense embedding vector."""
        if self.index is None or self.index.ntotal == 0 or len(self.metadata) == 0:
            return []

        try:
            if query_vector.ndim == 1:
                query_vector = query_vector.reshape(1, -1)
            query_vector = query_vector.astype(np.float32)

            # L2 normalize for cosine similarity
            faiss_norm = np.linalg.norm(query_vector, axis=1, keepdims=True)
            faiss_norm[faiss_norm == 0] = 1.0
            query_vector = query_vector / faiss_norm

            scores, indices = self.index.search(query_vector, min(top_k, self.index.ntotal))

            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < 0 or idx >= len(self.metadata):
                    continue
                meta = self.metadata[idx]
                results.append(
                    VectorResult(
                        function_id=meta.get("id", meta.get("name", str(idx))),
                        binary=meta.get("binary", "unknown"),
                        similarity_score=float(score),
                        cwe=meta.get("cwe", "Unknown"),
                        is_vulnerable=bool(meta.get("is_vulnerable", False)),
                        pseudocode=meta.get("pseudocode", "")[:300],
                    )
                )
            return results
        except Exception as e:
            log.warning(f"Vector search failed: {e}")
            return []
