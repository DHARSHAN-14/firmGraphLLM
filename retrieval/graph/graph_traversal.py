"""
retrieval.graph.graph_traversal
===============================
Graph Traversal Engine for structured Neo4j evidence collection.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    entity_type: str      # "similar_function", "api_cwe", "vuln_pattern", "cross_firmware"
    entity_id: str
    relationship: str
    target_cwe: str
    confidence: float
    description: str


class GraphTraversal:
    """Traverses the Knowledge Graph via Neo4j Cypher queries."""

    def __init__(self, kg_retrieval):
        self.kg = kg_retrieval

    def traverse(self, function_id: str, api_calls: list[str], top_k: int = 5) -> list[EvidenceItem]:
        """Collect structured evidence across all relationship types."""
        evidence: list[EvidenceItem] = []

        # 1. API-CWE associations
        if api_calls:
            try:
                associations = self.kg.get_api_cwe_associations(api_calls)
                for api, cwes in associations.items():
                    for cwe in cwes:
                        evidence.append(
                            EvidenceItem(
                                entity_type="api_cwe",
                                entity_id=api,
                                relationship="ASSOCIATED_WITH",
                                target_cwe=cwe,
                                confidence=0.8,
                                description=f"API '{api}' is associated with {cwe}",
                            )
                        )
            except Exception as e:
                log.warning(f"Error fetching API-CWE associations: {e}")

        # 2. Similar functions in the graph
        try:
            similar = self.kg.get_similar_functions(function_id, limit=top_k)
            for sim in similar:
                evidence.append(
                    EvidenceItem(
                        entity_type="similar_function",
                        entity_id=sim.get("id", ""),
                        relationship="SIMILAR_TO",
                        target_cwe=sim.get("cwe", "Unknown"),
                        confidence=float(sim.get("similarity_score", 0.5)),
                        description=f"Function '{sim.get('name')}' in binary '{sim.get('binary')}'",
                    )
                )
        except Exception as e:
            log.warning(f"Error fetching similar functions: {e}")

        # 3. Known vulnerable patterns
        try:
            patterns = self.kg.get_known_vulnerable_patterns()
            for p in patterns[:top_k]:
                evidence.append(
                    EvidenceItem(
                        entity_type="vuln_pattern",
                        entity_id=p.get("id", ""),
                        relationship="MAPS_TO_CWE",
                        target_cwe=p.get("cwe", "Unknown"),
                        confidence=min(1.0, float(p.get("occurrences", 1)) * 0.2),
                        description=p.get("description", ""),
                    )
                )
        except Exception as e:
            log.warning(f"Error fetching vuln patterns: {e}")

        return evidence
