"""
FirmGraph-LLM — KG Retrieval Queries
======================================
Cypher-based queries for structured evidence retrieval from Neo4j.
"""
import logging
log = logging.getLogger(__name__)


class KGRetrieval:
    """Query the Knowledge Graph for structured evidence."""

    def __init__(self, driver):
        self._driver = driver

    def run_query(self, cypher: str, params: dict = None) -> list[dict]:
        with self._driver.session() as s:
            result = s.run(cypher, **(params or {}))
            return [dict(r) for r in result]

    def get_similar_functions(self, function_id: str, limit: int = 10) -> list[dict]:
        """Find functions similar to the given function via SIMILAR_TO edges."""
        cypher = """
        MATCH (f:Function {id:$fid})-[r:SIMILAR_TO]->(sim:Function)
        RETURN sim.id AS id, sim.name AS name, sim.binary_id AS binary,
               r.score AS similarity_score
        ORDER BY r.score DESC LIMIT $limit
        """
        return self.run_query(cypher, {"fid": function_id, "limit": limit})

    def get_vulnerability_patterns_for_cwe(self, cwe_id: str) -> list[dict]:
        """Get all VulnPattern nodes for a given CWE, ordered by occurrence count."""
        cypher = """
        MATCH (vp:VulnPattern)-[:MAPS_TO_CWE]->(c:CWE {id:$cwe})
        RETURN vp.id AS id, vp.description AS description,
               vp.api_sequence AS api_sequence,
               vp.occurrence_count AS occurrences
        ORDER BY vp.occurrence_count DESC
        """
        return self.run_query(cypher, {"cwe": cwe_id})

    def get_api_cwe_associations(self, api_names: list[str]) -> dict[str, list[str]]:
        """For each API name, return a list of associated CWE IDs."""
        cypher = """
        MATCH (api:API)-[:ASSOCIATED_WITH]->(cwe:CWE)
        WHERE api.name IN $names
        RETURN api.name AS api, collect(cwe.id) AS cwes
        """
        rows = self.run_query(cypher, {"names": api_names})
        return {r["api"]: r["cwes"] for r in rows}

    def get_cross_firmware_evidence(self, api_sequence: list[str]) -> list[dict]:
        """Find functions in the KG that use a similar API sequence."""
        cypher = """
        MATCH (f:Function)-[:USES]->(api:API)
        WHERE api.name IN $apis
        WITH f, count(api) AS overlap
        WHERE overlap >= 2
        MATCH (f)-[:VULNERABLE_TO]->(vp:VulnPattern)-[:MAPS_TO_CWE]->(cwe:CWE)
        RETURN f.id AS function_id, f.name AS function_name,
               f.binary_id AS binary, cwe.id AS cwe,
               vp.description AS pattern, overlap
        ORDER BY overlap DESC LIMIT 10
        """
        return self.run_query(cypher, {"apis": api_sequence})

    def get_function_context(self, function_id: str) -> dict:
        """Return full context: function + its APIs + CWE associations + similar functions."""
        cypher = """
        MATCH (f:Function {id:$fid})
        OPTIONAL MATCH (f)-[:USES]->(api:API)
        OPTIONAL MATCH (f)-[:ASSOCIATED_WITH]->(cwe:CWE)
        OPTIONAL MATCH (f)-[:SIMILAR_TO]->(sim:Function)
        RETURN f,
               collect(DISTINCT api.name) AS apis,
               collect(DISTINCT cwe.id)   AS cwes,
               collect(DISTINCT sim.id)   AS similar
        """
        rows = self.run_query(cypher, {"fid": function_id})
        return rows[0] if rows else {}

    def get_known_vulnerable_patterns(self) -> list[dict]:
        """Return all VulnPattern nodes ordered by occurrence count."""
        cypher = """
        MATCH (vp:VulnPattern)
        RETURN vp.id AS id, vp.description AS description,
               vp.cwe_id AS cwe, vp.occurrence_count AS occurrences,
               vp.api_sequence AS api_sequence
        ORDER BY vp.occurrence_count DESC
        """
        return self.run_query(cypher)

    def close(self) -> None:
        self._driver.close()
