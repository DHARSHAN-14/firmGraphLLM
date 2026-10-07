"""
FirmGraph-LLM — Knowledge Graph Builder
=========================================
Builds and maintains the Neo4j Knowledge Graph.
All writes use MERGE for idempotency — safe to re-run.
"""
import logging
from typing import Optional

from knowledge_graph.schema.nodes import (
    FirmwareNode, BinaryNode, FunctionNode,
    APINode, CWENode, VulnPatternNode, CVENode,
)
from knowledge_graph.schema.relationships import Relationship, RelType

log = logging.getLogger(__name__)


class GraphBuilder:
    """Creates and updates nodes and relationships in the Neo4j KG."""

    def __init__(self, uri: str = "bolt://localhost:7687",
                 user: str = "neo4j", password: str = "firmgraph"):
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(uri, auth=(user, password))
            self._driver.verify_connectivity()
            log.info(f"Connected to Neo4j at {uri}")
        except Exception as e:
            log.error(f"Neo4j connection failed: {e}")
            raise

    # ── Node creation (MERGE = idempotent) ───────────────────────────────

    def add_firmware(self, node: FirmwareNode) -> None:
        with self._driver.session() as s:
            s.run("MERGE (n:Firmware {id:$id}) SET n += $props",
                  id=node.id, props={"vendor": node.vendor, "product": node.product,
                                      "version": node.version, "architecture": node.architecture,
                                      "source": node.source})

    def add_binary(self, node: BinaryNode) -> None:
        with self._driver.session() as s:
            s.run("MERGE (n:Binary {id:$id}) SET n += $props",
                  id=node.id, props={"name": node.name, "firmware_id": node.firmware_id,
                                      "arch": node.arch, "size_bytes": node.size_bytes,
                                      "sha256": node.sha256})

    def add_function(self, node: FunctionNode) -> None:
        with self._driver.session() as s:
            s.run("""MERGE (n:Function {id:$id})
                     SET n.name=$name, n.binary_id=$bid, n.address=$addr,
                         n.is_source=$src, n.is_sink=$snk""",
                  id=node.id, name=node.name, bid=node.binary_id,
                  addr=node.address, src=node.is_source, snk=node.is_sink)

    def add_api(self, node: APINode) -> None:
        with self._driver.session() as s:
            s.run("""MERGE (n:API {id:$id})
                     SET n.name=$name, n.library=$lib,
                         n.is_sink=$snk, n.is_source=$src""",
                  id=node.id, name=node.name, lib=node.library,
                  snk=node.is_sink, src=node.is_source)

    def add_cwe(self, node: CWENode) -> None:
        with self._driver.session() as s:
            s.run("""MERGE (n:CWE {id:$id})
                     SET n.name=$name, n.severity=$sev, n.description=$desc""",
                  id=node.id, name=node.name, sev=node.severity, desc=node.description)

    def add_vuln_pattern(self, node: VulnPatternNode) -> None:
        with self._driver.session() as s:
            s.run("""MERGE (n:VulnPattern {id:$id})
                     ON CREATE SET n.occurrence_count = 1,
                                   n.description=$desc, n.cwe_id=$cwe,
                                   n.api_sequence=$apis
                     ON MATCH SET n.occurrence_count = coalesce(n.occurrence_count, 1) + 1""",
                  id=node.id, desc=node.description, cwe=node.cwe_id,
                  apis=node.api_sequence)

    # ── Relationship creation ──────────────────────────────────────────────

    def add_relationship(self, rel: Relationship) -> None:
        props_str = ", ".join(f"r.{k}=${k}" for k in rel.properties)
        set_clause = f"SET {props_str}" if props_str else ""
        # Sequential MATCH avoids Cartesian product warning in Neo4j DBMS
        cypher = (
            f"MATCH (a {{id:$from_id}}) "
            f"MATCH (b {{id:$to_id}}) "
            f"MERGE (a)-[r:{rel.rel_type.value}]->(b) {set_clause}"
        )
        with self._driver.session() as s:
            s.run(cypher, from_id=rel.from_id, to_id=rel.to_id, **rel.properties)

    def add_similar_relationship(self, func_a_id: str, func_b_id: str, score: float) -> None:
        """Create a weighted SIMILAR_TO edge between two functions."""
        cypher = """
        MATCH (a:Function {id:$fa})
        MATCH (b:Function {id:$fb})
        MERGE (a)-[r:SIMILAR_TO]->(b)
        SET r.score = $score
        """
        with self._driver.session() as s:
            s.run(cypher, fa=func_a_id, fb=func_b_id, score=score)

    # ── Batch operations ───────────────────────────────────────────────────

    def add_functions_batch(self, nodes: list[FunctionNode]) -> None:
        for n in nodes:
            self.add_function(n)
        log.info(f"Added {len(nodes)} Function nodes")

    def add_relationships_batch(self, rels: list[Relationship]) -> None:
        for r in rels:
            self.add_relationship(r)
        log.info(f"Added {len(rels)} relationships")

    # ── High-level ingestion ───────────────────────────────────────────────

    def ingest_vulnerability_result(self, result, binary_node: BinaryNode) -> None:
        """
        Ingest a VulnerabilityResult into the KG:
        - Ensure Binary node exists
        - Create/update Function node for the sink function
        - Create VulnPattern (api_sequence derived from flow)
        - Wire: Function -[VULNERABLE_TO]-> VulnPattern -[MAPS_TO_CWE]-> CWE
        - Wire: Function -[ASSOCIATED_WITH]-> CWE
        """
        if not result.vulnerable:
            return

        self.add_binary(binary_node)

        # Function node (sink location)
        func_id = f"{binary_node.id}::{result.flow_id}"
        func_node = FunctionNode(
            id=func_id, name=result.flow_id,
            binary_id=binary_node.id, is_sink=True,
        )
        self.add_function(func_node)

        # VulnPattern node
        pattern_id = f"pattern::{result.cwe}::{result.flow_id}"
        pattern = VulnPatternNode(
            id=pattern_id, description=result.explanation[:200],
            cwe_id=result.cwe, api_sequence=[],
        )
        self.add_vuln_pattern(pattern)

        # Relationships
        self.add_relationship(Relationship(func_id, pattern_id, RelType.VULNERABLE_TO))
        self.add_relationship(Relationship(pattern_id, result.cwe, RelType.MAPS_TO_CWE))
        self.add_relationship(Relationship(func_id, result.cwe, RelType.ASSOCIATED_WITH))
        self.add_relationship(Relationship(binary_node.id, func_id, RelType.HAS_FUNCTION))

        log.info(f"Ingested vulnerability: {result.flow_id} → {result.cwe}")

    def run_query(self, cypher: str, params: dict = None) -> list[dict]:
        """Run an arbitrary read Cypher query and return results as list of dicts."""
        with self._driver.session() as s:
            result = s.run(cypher, **(params or {}))
            return [dict(r) for r in result]

    def close(self) -> None:
        self._driver.close()
        log.info("Neo4j connection closed")
