"""
FirmGraph-LLM — Neo4j Schema Setup
====================================
Creates all constraints, indexes, and seeds base CWE data.
"""
import logging
log = logging.getLogger(__name__)

# ── Cypher: Constraints (uniqueness) ──────────────────────────────────────────
CONSTRAINTS = [
    "CREATE CONSTRAINT firmware_id IF NOT EXISTS FOR (n:Firmware)      REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT binary_id   IF NOT EXISTS FOR (n:Binary)        REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT function_id IF NOT EXISTS FOR (n:Function)      REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT api_id      IF NOT EXISTS FOR (n:API)           REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT cwe_id      IF NOT EXISTS FOR (n:CWE)           REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT pattern_id  IF NOT EXISTS FOR (n:VulnPattern)   REQUIRE n.id IS UNIQUE",
    "CREATE CONSTRAINT cve_id      IF NOT EXISTS FOR (n:CVE)           REQUIRE n.id IS UNIQUE",
]

# ── Cypher: Indexes ────────────────────────────────────────────────────────────
INDEXES = [
    "CREATE INDEX func_name   IF NOT EXISTS FOR (n:Function) ON (n.name)",
    "CREATE INDEX func_binary IF NOT EXISTS FOR (n:Function) ON (n.binary_id)",
    "CREATE INDEX api_name    IF NOT EXISTS FOR (n:API)      ON (n.name)",
    "CREATE INDEX cwe_name    IF NOT EXISTS FOR (n:CWE)      ON (n.name)",
]

# ── Base CWE data ──────────────────────────────────────────────────────────────
CWE_SEED = [
    {"id": "CWE-77",  "name": "Command Injection",          "severity": "Critical", "parent_id": ""},
    {"id": "CWE-78",  "name": "OS Command Injection",       "severity": "Critical", "parent_id": "CWE-77",
     "description": "The software constructs OS commands using externally-influenced input."},
    {"id": "CWE-119", "name": "Buffer Errors",              "severity": "High",     "parent_id": ""},
    {"id": "CWE-120", "name": "Buffer Copy Without Checking Size", "severity": "High", "parent_id": "CWE-119",
     "description": "The program copies an input buffer to an output buffer without verifying size."},
    {"id": "CWE-134", "name": "Uncontrolled Format String", "severity": "High",     "parent_id": "CWE-133",
     "description": "The software uses externally-controlled format strings in printf-style functions."},
    {"id": "CWE-189", "name": "Numeric Errors",             "severity": "Medium",   "parent_id": ""},
    {"id": "CWE-190", "name": "Integer Overflow",           "severity": "High",     "parent_id": "CWE-189",
     "description": "The software performs a calculation that can produce an integer overflow."},
    {"id": "CWE-605", "name": "Multiple Binds to Same Port","severity": "Medium",   "parent_id": ""},
    {"id": "CWE-606", "name": "Unchecked Input for Loop Condition", "severity": "Medium", "parent_id": "CWE-605",
     "description": "The product does not properly check inputs used as loop conditions."},
]


def setup_schema(driver) -> None:
    """Create all Neo4j constraints and indexes."""
    with driver.session() as session:
        for stmt in CONSTRAINTS:
            try:
                session.run(stmt)
            except Exception as e:
                log.warning(f"Constraint may already exist: {e}")
        for stmt in INDEXES:
            try:
                session.run(stmt)
            except Exception as e:
                log.warning(f"Index may already exist: {e}")
    log.info(f"Schema setup: {len(CONSTRAINTS)} constraints, {len(INDEXES)} indexes")


def seed_cwe_data(driver) -> None:
    """Insert base CWE nodes and PARENT_OF relationships."""
    with driver.session() as session:
        for cwe in CWE_SEED:
            session.run(
                """MERGE (c:CWE {id: $id})
                   SET c.name = $name, c.severity = $severity,
                       c.description = $description, c.parent_id = $parent_id""",
                id=cwe["id"], name=cwe["name"], severity=cwe["severity"],
                description=cwe.get("description", ""), parent_id=cwe["parent_id"],
            )
        # Create PARENT_OF hierarchy edges
        for cwe in CWE_SEED:
            if cwe["parent_id"]:
                session.run(
                    """MATCH (parent:CWE {id: $pid})
                       MATCH (child:CWE {id: $cid})
                       MERGE (parent)-[:PARENT_OF]->(child)""",
                    pid=cwe["parent_id"], cid=cwe["id"],
                )
    log.info(f"Seeded {len(CWE_SEED)} CWE nodes")
