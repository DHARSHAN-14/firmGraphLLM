#!/usr/bin/env python3
"""
FirmGraph-LLM — Multi-Paradigm Training Pipeline
=================================================
Executes the training phase on the 80% training partition (4,986 test cases,
9,972 ELF binaries) from `data/research_split_80_20/train/`.

Training in FirmGraph-LLM operates on two synergistic levels:

1. Level 1: Neuro-Symbolic Knowledge Graph Memory Training (Core Architecture)
   - Ingests training binaries, functions, taint sources, dangerous sinks,
     and vulnerability patterns into the Neo4j graph database.
   - Computes empirical occurrence frequencies across the 4 target CWEs:
     CWE-78, CWE-134, CWE-190, CWE-606.
   - Wires structural relationships: `VULNERABLE_TO`, `MAPS_TO_CWE`,
     `HAS_FUNCTION`, `CALLS`, and `ASSOCIATED_WITH`.
   - Populates the persistent "Security Memory" that powers GraphRAG retrieval
     when evaluating unseen binaries from the 20% test set.

2. Level 2: Supervised Fine-Tuning (SFT) Dataset Preparation
   - Generates instruction-tuning datasets in standard JSONL format
     (Alpaca / ShareGPT compatible) for optional Parameter-Efficient Fine-Tuning
     (PEFT / LoRA) of code LLMs (e.g., Qwen2.5-Coder, Llama-3).

Usage:
  # Ingest 80% training set into Neo4j Knowledge Graph:
  python3 scripts/train_firmgraph.py --mode kg

  # Export instruction-tuning SFT dataset:
  python3 scripts/train_firmgraph.py --mode sft

  # Run both:
  python3 scripts/train_firmgraph.py --mode all
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("train_firmgraph")

SPLIT_DIR = ROOT / "data" / "research_split_80_20"
TRAIN_GT = SPLIT_DIR / "train_ground_truth.json"
TRAIN_MANIFEST = SPLIT_DIR / "train_manifest.json"
SFT_OUT = SPLIT_DIR / "train_sft_dataset.jsonl"


def extract_source_sink_from_name(source_file: str) -> tuple[str, str]:
    """Extract taint source and dangerous sink from Juliet naming convention."""
    stem = source_file[:-2] if source_file.endswith(".c") else source_file
    parts = stem.split("__")
    if len(parts) == 2:
        tokens = parts[1].split("_")
        if len(tokens) >= 3:
            return tokens[1], tokens[2]
    return "unknown_source", "unknown_sink"


def train_knowledge_graph(
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_pass: str = "firmgraph",
    batch_size: int = 500,
) -> dict:
    """
    Ingest the 80% training set into the Neo4j Knowledge Graph.
    Uses batched UNWIND Cypher transactions for high performance.
    """
    from neo4j import GraphDatabase

    if not TRAIN_GT.exists():
        raise FileNotFoundError(f"Train ground truth not found: {TRAIN_GT}")

    with open(TRAIN_GT, "r", encoding="utf-8") as f:
        train_data = json.load(f)

    entries = train_data.get("entries", [])
    log.info(f"Loaded {len(entries)} training cases from {TRAIN_GT}")

    log.info(f"Connecting to Neo4j at {neo4j_uri}...")
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
    driver.verify_connectivity()

    # 1. Initialize CWE Master Nodes
    cwe_defs = [
        {"id": "CWE-78", "name": "OS Command Injection", "sev": "CRITICAL", "desc": "Improper neutralization of special elements in OS command"},
        {"id": "CWE-134", "name": "Uncontrolled Format String", "sev": "HIGH", "desc": "Externally-controlled format string in printf/syslog"},
        {"id": "CWE-190", "name": "Integer Overflow", "sev": "HIGH", "desc": "Integer overflow or wraparound leading to memory corruption"},
        {"id": "CWE-606", "name": "Unchecked Loop Condition", "sev": "MEDIUM", "desc": "Unchecked input used in loop condition leading to DoS"},
    ]

    with driver.session() as s:
        s.run("""
        UNWIND $cwes AS c
        MERGE (n:CWE {id: c.id})
        SET n.name = c.name, n.severity = c.sev, n.description = c.desc
        """, cwes=cwe_defs)
    log.info("✓ Master CWE taxonomy nodes registered")

    # 2. Extract and Prepare Batch Ingestion Records
    records = []
    pattern_freq = Counter()

    for idx, e in enumerate(entries):
        sf = e["source_file"]
        cwe_id = f"CWE-{e['cwe_id']}"
        src_api, snk_api = extract_source_sink_from_name(sf)
        pat_key = f"pattern::{cwe_id}::{src_api}::{snk_api}"
        pattern_freq[pat_key] += 1

        bad_path = e["binary_bad"]["path"]
        good_path = e["binary_good"]["path"]
        bad_name = Path(bad_path).name
        good_name = Path(good_path).name

        rec = {
            "case_id": f"case_{idx}_{sf}",
            "cwe_id": cwe_id,
            "cwe_name": e.get("cwe_name", ""),
            "source_file": sf,
            "source_api": src_api,
            "sink_api": snk_api,
            "pattern_id": pat_key,
            "pattern_desc": f"Taint propagation from {src_api} to dangerous sink {snk_api} ({e.get('cwe_name', '')})",
            "bad_bin_id": bad_name,
            "bad_func_id": f"{bad_name}::sink_{snk_api}",
            "good_bin_id": good_name,
            "good_func_id": f"{good_name}::sink_{snk_api}",
        }
        records.append(rec)

    # 3. Batch Ingest API nodes and VulnPattern nodes
    log.info(f"Ingesting {len(pattern_freq)} distinct vulnerability pattern archetypes...")
    pattern_payload = [
        {
            "id": pat_id,
            "cwe_id": pat_id.split("::")[1],
            "src": pat_id.split("::")[2],
            "snk": pat_id.split("::")[3],
            "freq": count,
            "desc": f"Taint flow pattern: {pat_id.split('::')[2]} -> {pat_id.split('::')[3]}",
        }
        for pat_id, count in pattern_freq.items()
    ]

    with driver.session() as s:
        # Create APIs
        s.run("""
        UNWIND $patterns AS p
        MERGE (src:API {id: p.src}) SET src.is_source = true
        MERGE (snk:API {id: p.snk}) SET snk.is_sink = true
        MERGE (pat:VulnPattern {id: p.id})
        SET pat.description = p.desc,
            pat.cwe_id = p.cwe_id,
            pat.occurrence_count = p.freq
        WITH pat, p
        MATCH (c:CWE {id: p.cwe_id})
        MERGE (pat)-[:MAPS_TO_CWE]->(c)
        """, patterns=pattern_payload)
    log.info("✓ APINode and VulnPatternNode ingestion complete")

    # 4. Batch Ingest Binaries, Functions, and Taint Relationships
    log.info(f"Ingesting {len(records)} training binaries and taint flows in batches of {batch_size}...")
    for i in range(0, len(records), batch_size):
        chunk = records[i:i + batch_size]
        with driver.session() as s:
            s.run("""
            UNWIND $batch AS r
            // Bad Binary and Sink Function
            MERGE (b:Binary {id: r.bad_bin_id})
            SET b.name = r.bad_bin_id, b.split = 'train', b.is_vulnerable = true
            MERGE (f:Function {id: r.bad_func_id})
            SET f.name = r.sink_api, f.is_sink = true, f.binary_id = r.bad_bin_id
            MERGE (b)-[:HAS_FUNCTION]->(f)

            // Dangerous Taint Edge to Pattern
            WITH r, b, f
            MATCH (pat:VulnPattern {id: r.pattern_id})
            MERGE (f)-[:VULNERABLE_TO]->(pat)
            MERGE (f)-[:ASSOCIATED_WITH]->(pat)

            // API calls
            WITH r, f
            MATCH (snk:API {id: r.sink_api})
            MERGE (f)-[:CALLS]->(snk)
            """, batch=chunk)
        log.info(f"  Ingested batch {i + 1} to {min(i + batch_size, len(records))} / {len(records)}")

    # 5. Graph Verification Stats
    with driver.session() as s:
        node_count = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
        edge_count = s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
        pat_count = s.run("MATCH (p:VulnPattern) RETURN count(p) AS c").single()["c"]
        top_patterns = s.run("""
        MATCH (p:VulnPattern)-[:MAPS_TO_CWE]->(c:CWE)
        RETURN p.id AS pattern, c.id AS cwe, p.occurrence_count AS freq
        ORDER BY freq DESC LIMIT 5
        """).data()

    driver.close()
    log.info("=" * 60)
    log.info("KNOWLEDGE GRAPH TRAINING RESULTS:")
    log.info(f"  Total Graph Nodes: {node_count}")
    log.info(f"  Total Graph Edges: {edge_count}")
    log.info(f"  Vuln Patterns Learned: {pat_count}")
    log.info("  Top 5 Most Frequent Training Patterns:")
    for tp in top_patterns:
        log.info(f"    • {tp['pattern']} ({tp['cwe']}) -> Frequency: {tp['freq']}")
    log.info("=" * 60)

    return {
        "status": "success",
        "nodes": node_count,
        "edges": edge_count,
        "patterns": pat_count,
        "top_patterns": top_patterns,
    }


def export_sft_dataset() -> int:
    """
    Export the 80% training partition to an instruction-tuning JSONL file.
    Suitable for LoRA / PEFT fine-tuning with HuggingFace or Unsloth.
    """
    if not TRAIN_GT.exists():
        raise FileNotFoundError(f"Train ground truth not found: {TRAIN_GT}")

    with open(TRAIN_GT, "r", encoding="utf-8") as f:
        train_data = json.load(f)

    entries = train_data.get("entries", [])
    log.info(f"Exporting {len(entries)} training samples to SFT format at {SFT_OUT}...")

    count = 0
    with open(SFT_OUT, "w", encoding="utf-8") as f_out:
        for e in entries:
            sf = e["source_file"]
            cwe_id = f"CWE-{e['cwe_id']}"
            cwe_name = e.get("cwe_name", "")
            src_api, snk_api = extract_source_sink_from_name(sf)

            # Sample 1: Vulnerable Bad Binary Instruction Sample
            sample_bad = {
                "instruction": (
                    "Perform static binary taint analysis on the target program flow. "
                    "Analyze whether user-controlled input reaches a sensitive function without sanitization, "
                    "identify the specific vulnerability class (CWE), and output your verdict in structured format."
                ),
                "input": (
                    f"Binary Target: {Path(e['binary_bad']['path']).name}\n"
                    f"Source Function: {src_api}\n"
                    f"Sink Function: {snk_api}\n"
                    f"Candidate Flaw Type: {cwe_id} ({cwe_name})"
                ),
                "output": json.dumps(
                    {
                        "verdict": "VULNERABLE",
                        "cwe": cwe_id,
                        "confidence": 0.95,
                        "taint_source": src_api,
                        "taint_sink": snk_api,
                        "reasoning": (
                            f"Direct taint propagation identified from external input source '{src_api}' "
                            f"to critical sink '{snk_api}'. No validation or bounds check was applied."
                        ),
                    },
                    indent=2,
                ),
            }
            f_out.write(json.dumps(sample_bad) + "\n")
            count += 1

            # Sample 2: Patched Good Binary Instruction Sample (Counter-Example for Robustness)
            sample_good = {
                "instruction": (
                    "Perform static binary taint analysis on the target program flow. "
                    "Analyze whether user-controlled input reaches a sensitive function without sanitization, "
                    "identify the specific vulnerability class (CWE), and output your verdict in structured format."
                ),
                "input": (
                    f"Binary Target: {Path(e['binary_good']['path']).name}\n"
                    f"Source Function: {src_api}\n"
                    f"Sink Function: {snk_api}\n"
                    f"Candidate Flaw Type: {cwe_id} ({cwe_name})"
                ),
                "output": json.dumps(
                    {
                        "verdict": "SAFE",
                        "cwe": cwe_id,
                        "confidence": 0.90,
                        "taint_source": src_api,
                        "taint_sink": snk_api,
                        "reasoning": (
                            f"Sanitization check or static buffer bounding is verified between '{src_api}' "
                            f"and '{snk_api}'. Taint cannot reach dangerous execution sink."
                        ),
                    },
                    indent=2,
                ),
            }
            f_out.write(json.dumps(sample_good) + "\n")
            count += 1

    log.info(f"✓ Exported {count} instruction-tuning prompt pairs (bad + good) to {SFT_OUT}")
    return count


def main():
    parser = argparse.ArgumentParser(description="FirmGraph-LLM Training Pipeline")
    parser.add_argument(
        "--mode",
        choices=["kg", "sft", "all"],
        default="all",
        help="Training mode: 'kg' (Knowledge Graph Memory Ingestion), 'sft' (Instruction Tuning Export), 'all' (Both)",
    )
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j Bolt URI")
    parser.add_argument("--neo4j-user", default="neo4j", help="Neo4j User")
    parser.add_argument("--neo4j-pass", default="firmgraph", help="Neo4j Password")
    parser.add_argument("--batch-size", type=int, default=500, help="Batch size for Cypher UNWIND transactions")
    args = parser.parse_args()

    if args.mode in ("kg", "all"):
        log.info("Starting Knowledge Graph Ingestion Training...")
        train_knowledge_graph(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_pass=args.neo4j_pass,
            batch_size=args.batch_size,
        )

    if args.mode in ("sft", "all"):
        log.info("Starting SFT Instruction Dataset Export...")
        export_sft_dataset()

    log.info("FirmGraph-LLM Training Pipeline finished successfully!")


if __name__ == "__main__":
    main()
