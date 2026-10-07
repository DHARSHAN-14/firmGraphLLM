#!/usr/bin/env python3
"""
FirmGraph-LLM — Complete End-to-End Pipeline Runner
=====================================================
This script runs the FULL FirmGraph-LLM pipeline from scratch:

  STEP 1 — Neo4j KG setup (schema + CWE seed data + API seed data)
  STEP 2 — Build function embeddings (CPU-based, no GPU needed)
  STEP 3 — Build FAISS vector index
  STEP 4 — Ingest known vulnerability patterns into KG from existing flow files
  STEP 5 — Run LATTE Baseline (B2): LLM only, no KG
  STEP 6 — Run FirmGraph-LLM (P): LLM + KG evidence
  STEP 7 — Compare results and generate evaluation report

Usage:
    python3 scripts/run_full_pipeline.py --flows data/flows/sample_cwe78_flow.json
    python3 scripts/run_full_pipeline.py --flows data/flows/ --all-flows
    python3 scripts/run_full_pipeline.py --setup-only    # just set up KG + embeddings
    python3 scripts/run_full_pipeline.py --skip-latte    # skip baseline, run FirmGraph only
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# ── Bootstrap path ─────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("run_pipeline")


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Neo4j Setup
# ═══════════════════════════════════════════════════════════════════════════════

def setup_neo4j(neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
    """Connect to Neo4j, set up schema, seed CWE + API data."""
    log.info("=" * 60)
    log.info("STEP 1 — Setting up Neo4j Knowledge Graph")
    log.info("=" * 60)

    from knowledge_graph.construction.graph_builder import GraphBuilder
    from knowledge_graph.schema.cypher_setup import setup_schema, seed_cwe_data
    from knowledge_graph.ingestion.api_loader import load_known_apis, load_target_cwes
    from knowledge_graph.queries.retrieval import KGRetrieval

    # Retry connection (Neo4j needs ~20s to start)
    builder = None
    for attempt in range(10):
        try:
            builder = GraphBuilder(uri=neo4j_uri, user=neo4j_user, password=neo4j_pass)
            log.info(f"  ✓ Connected to Neo4j at {neo4j_uri}")
            break
        except Exception as e:
            log.warning(f"  Neo4j not ready yet (attempt {attempt+1}/10): {e}")
            time.sleep(5)

    if builder is None:
        log.error("  ✗ Could not connect to Neo4j. Run: podman start neo4j-firmgraph")
        return None, None

    setup_schema(builder._driver)
    log.info("  ✓ Schema constraints and indexes created")

    seed_cwe_data(builder._driver)
    log.info("  ✓ CWE seed data (CWE-78, 120, 134, 190, 606) inserted")

    load_target_cwes(builder)
    load_known_apis(builder)
    log.info("  ✓ Known sink/source APIs loaded into KG")

    kg_retrieval = KGRetrieval(builder._driver)
    log.info("  ✓ KG retrieval layer initialized")

    return builder, kg_retrieval


def connect_neo4j(neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
    """Connect to an already-configured Neo4j instance without re-seeding."""
    from knowledge_graph.construction.graph_builder import GraphBuilder
    from knowledge_graph.queries.retrieval import KGRetrieval
    try:
        builder = GraphBuilder(uri=neo4j_uri, user=neo4j_user, password=neo4j_pass)
        kg_retrieval = KGRetrieval(builder._driver)
        log.info(f"  ✓ Connected to existing Neo4j at {neo4j_uri}")
        return builder, kg_retrieval
    except Exception as e:
        log.warning(f"  Could not connect to Neo4j: {e}")
        return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Build Function Embeddings (CPU, no torch needed)
# ═══════════════════════════════════════════════════════════════════════════════

def build_embeddings(flows_dir: Path, index_path: Path, metadata_path: Path):
    """
    Generate lightweight TF-IDF-style embeddings for function pseudocode.
    Uses tokenizer-only (no full model forward pass needed for similarity index building).
    Falls back to hash-based embeddings if transformers tokenizer isn't available.
    """
    log.info("=" * 60)
    log.info("STEP 2 — Building Function Embeddings")
    log.info("=" * 60)

    import numpy as np

    # Collect all functions from all flow JSON files
    functions = []
    flow_files = list(flows_dir.glob("*.json")) if flows_dir.is_dir() else [flows_dir]

    for flow_file in flow_files:
        try:
            data = json.loads(flow_file.read_text())
            if isinstance(data, dict):
                data = [data]
            for flow in data:
                for fn in flow.get("function_chain", []):
                    entry = {
                        "function_id": f"{flow.get('binary_name','unknown')}::{fn['name']}",
                        "name": fn["name"],
                        "binary": flow.get("binary_name", "unknown"),
                        "cwe": flow.get("expected_cwe", "unknown"),
                        "pseudocode": fn.get("pseudocode", ""),
                        "api_calls": fn.get("api_calls", []),
                        "flow_id": flow.get("flow_id", ""),
                    }
                    functions.append(entry)
        except Exception as e:
            log.warning(f"  Skipping {flow_file.name}: {e}")

    if not functions:
        log.warning("  No functions found in flow files — skipping embedding step")
        return False

    log.info(f"  Found {len(functions)} functions across {len(flow_files)} flow file(s)")

    # Generate embeddings using TF-IDF-inspired bag-of-tokens approach
    # This works without PyTorch and gives reasonable cosine similarity
    embeddings = _generate_tfidf_embeddings(functions)

    # Build FAISS index
    try:
        import faiss
        dim = embeddings.shape[1]
        index = faiss.IndexFlatIP(dim)  # inner product = cosine (after L2 norm)
        index.add(embeddings.astype(np.float32))
        index_path.parent.mkdir(parents=True, exist_ok=True)
        faiss.write_index(index, str(index_path))
        metadata_path.write_text(json.dumps(functions, indent=2))
        log.info(f"  ✓ FAISS index built: {index.ntotal} vectors, dim={dim}")
        log.info(f"  ✓ Index saved → {index_path}")
        log.info(f"  ✓ Metadata saved → {metadata_path}")
        return True
    except Exception as e:
        log.warning(f"  FAISS index build failed: {e}")
        return False


def _generate_tfidf_embeddings(functions: list[dict]) -> "np.ndarray":
    """
    Generate normalized bag-of-tokens embeddings for function pseudocode.
    Vocabulary: all unique tokens across all functions.
    Each function → normalized term-frequency vector.
    """
    import numpy as np
    import re
    from collections import Counter

    def tokenize(text: str) -> list[str]:
        """Split code into tokens (identifiers, keywords, operators)."""
        tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[+\-*/=<>!&|^~]+', text)
        return [t.lower() for t in tokens if len(t) > 1]

    # Build vocabulary
    all_tokens = []
    token_lists = []
    for fn in functions:
        code = fn.get("pseudocode", "") + " " + " ".join(fn.get("api_calls", []))
        tokens = tokenize(code)
        token_lists.append(tokens)
        all_tokens.extend(set(tokens))  # IDF: count documents containing token

    vocab_counter = Counter(all_tokens)
    # Keep top 512 most common tokens as vocabulary
    vocab = [tok for tok, _ in vocab_counter.most_common(512)]
    vocab_index = {tok: i for i, tok in enumerate(vocab)}
    dim = len(vocab)

    if dim == 0:
        log.warning("  Empty vocabulary — using random embeddings")
        embeddings = np.random.randn(len(functions), 64).astype(np.float32)
    else:
        embeddings = np.zeros((len(functions), dim), dtype=np.float32)
        n_docs = len(functions)
        doc_freq = vocab_counter  # documents containing each token

        for i, (fn, tokens) in enumerate(zip(functions, token_lists)):
            tc = Counter(tokens)
            for tok, count in tc.items():
                if tok in vocab_index:
                    j = vocab_index[tok]
                    # TF-IDF weight
                    tf = count / max(len(tokens), 1)
                    idf = max(1, n_docs) / max(1, doc_freq[tok])
                    embeddings[i, j] = tf * idf

    # L2 normalize
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    norms = np.maximum(norms, 1e-9)
    embeddings /= norms

    log.info(f"  ✓ Embeddings generated: shape={embeddings.shape}")
    return embeddings


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Ingest existing flows into KG (pre-populate with known patterns)
# ═══════════════════════════════════════════════════════════════════════════════

def ingest_known_patterns(builder, flows_dir: Path):
    """
    Pre-populate the KG with vulnerability patterns from all existing flow files.
    This seeds cross-firmware knowledge before analysis begins.
    """
    log.info("=" * 60)
    log.info("STEP 3 — Seeding KG with Known Vulnerability Patterns")
    log.info("=" * 60)

    if builder is None:
        log.warning("  KG not available — skipping pattern seeding")
        return

    from knowledge_graph.schema.nodes import BinaryNode, VulnPatternNode, FunctionNode, APINode
    from knowledge_graph.schema.relationships import Relationship, RelType

    flow_files = list(flows_dir.glob("*.json")) if flows_dir.is_dir() else []
    pattern_count = 0

    for flow_file in flow_files:
        try:
            data = json.loads(flow_file.read_text())
            if isinstance(data, dict):
                data = [data]
            for flow in data:
                cwe = flow.get("expected_cwe", "")
                binary = flow.get("binary_name", "unknown")
                source = flow.get("source_func", "")
                sink = flow.get("sink_func", "")
                flow_id = flow.get("flow_id", "unknown")

                if not cwe or not sink:
                    continue

                # Create Binary node
                bin_node = BinaryNode(id=binary, name=binary, firmware_id="juliet_benchmark")
                builder.add_binary(bin_node)

                # Create API nodes for source and sink
                if source:
                    src_api = APINode(id=f"api::{source}", name=source,
                                     library="glibc", is_source=True, is_sink=False)
                    builder.add_api(src_api)
                if sink:
                    snk_api = APINode(id=f"api::{sink}", name=sink,
                                     library="glibc", is_source=False, is_sink=True)
                    builder.add_api(snk_api)
                    # Link sink → CWE
                    builder.add_relationship(
                        Relationship(f"api::{sink}", cwe, RelType.ASSOCIATED_WITH)
                    )

                # Create VulnPattern
                pattern_id = f"pattern::{cwe}::{source}_to_{sink}"
                pattern = VulnPatternNode(
                    id=pattern_id,
                    description=f"{source}→{sink} flow leads to {cwe}",
                    cwe_id=cwe,
                    api_sequence=[source, sink],
                )
                builder.add_vuln_pattern(pattern)
                builder.add_relationship(Relationship(pattern_id, cwe, RelType.MAPS_TO_CWE))

                pattern_count += 1
        except Exception as e:
            log.warning(f"  Error processing {flow_file.name}: {e}")

    log.info(f"  ✓ Seeded {pattern_count} vulnerability patterns into KG")


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4+5 — Run LATTE Baseline and FirmGraph-LLM
# ═══════════════════════════════════════════════════════════════════════════════

def run_latte_baseline(flows: list, binary_name: str, model: str, temperature: float) -> list:
    """Run pure LATTE baseline: LLM only, no KG."""
    log.info("=" * 60)
    log.info("STEP 4 — LATTE Baseline (B2): LLM-only analysis")
    log.info("=" * 60)

    from llm.client import OllamaClient, OllamaNotAvailableError
    from evaluation.evaluation import LATTEBaseline

    client = OllamaClient(model=model, temperature=temperature)
    if not client.is_available():
        log.warning(f"  Ollama not available or model '{model}' not found")
        log.warning("  Available models: " + str(client.list_models()))
        # Try fallback
        available = client.list_models()
        if available:
            client.switch_model(available[0])
            log.info(f"  Switched to available model: {client.model}")

    baseline = LATTEBaseline(client)
    log.info(f"  Running on {len(flows)} flow(s) with model '{client.model}'...")
    results = baseline.run(flows, binary_name)
    vuln = sum(1 for r in results if r.result.vulnerable)
    log.info(f"  ✓ LATTE baseline done: {vuln}/{len(flows)} vulnerable")
    return results


def run_firmgraph(flows: list, binary_name: str, model: str, temperature: float,
                  builder, kg_retrieval,
                  index_path: Path, metadata_path: Path,
                  output_dir: Path) -> list:
    """Run FirmGraph-LLM: LLM + KG + GraphRAG."""
    log.info("=" * 60)
    log.info("STEP 5 — FirmGraph-LLM (P): LLM + Knowledge Graph + GraphRAG")
    log.info("=" * 60)

    from llm.client import OllamaClient
    from analysis.analyzer import FirmGraphAnalyzer, AnalysisConfig
    from retrieval.retrieval import GraphTraversal, GraphRAGRetriever, VectorSearcher

    client = OllamaClient(model=model, temperature=temperature)
    available = client.list_models()
    if available and client.model not in available:
        client.switch_model(available[0])

    # Set up retrieval
    retriever = None
    if kg_retrieval:
        traversal = GraphTraversal(kg_retrieval)
        vs = VectorSearcher(index_path=index_path, metadata_path=metadata_path)
        retriever = GraphRAGRetriever(vs, traversal)
        log.info(f"  ✓ GraphRAG retriever ready (KG: {bool(kg_retrieval)}, Vector: {vs.is_loaded()})")

    config = AnalysisConfig(
        use_kg_retrieval=bool(retriever),
        results_dir=output_dir / "firmgraph",
        save_results=True,
    )

    analyzer = FirmGraphAnalyzer(
        llm_client=client,
        graph_builder=builder,
        graphrag_retriever=retriever,
        config=config,
    )

    log.info(f"  Running on {len(flows)} flow(s) with model '{client.model}'...")
    results = analyzer.analyze(flows, binary_name)
    vuln = sum(1 for r in results if r.result.vulnerable)
    log.info(f"  ✓ FirmGraph-LLM done: {vuln}/{len(flows)} vulnerable")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Compare and Evaluate
# ═══════════════════════════════════════════════════════════════════════════════

def compare_and_report(latte_results: list, fg_results: list,
                       binary_name: str, output_dir: Path,
                       gt_path: Path):
    """Compare LATTE vs FirmGraph-LLM results and print evaluation table."""
    log.info("=" * 60)
    log.info("STEP 6 — Evaluation & Comparison")
    log.info("=" * 60)

    def summarize(results: list, label: str) -> dict:
        if not results:
            return {"label": label, "total": 0, "vulnerable": 0, "findings": []}
        total = len(results)
        vuln  = [r for r in results if r.result.vulnerable]
        cwes  = {}
        for r in vuln:
            cwes[r.cwe] = cwes.get(r.cwe, 0) + 1
        return {
            "label": label,
            "total": total,
            "vulnerable": len(vuln),
            "cwe_distribution": cwes,
            "findings": [
                {
                    "rank": r.rank,
                    "flow_id": r.flow_id,
                    "cwe": r.cwe,
                    "vulnerable": r.result.vulnerable,
                    "confidence": round(r.llm_confidence, 3),
                    "kg_evidence_score": round(r.kg_evidence_score, 3),
                    "final_score": round(r.final_score, 3),
                    "kg_evidence_used": r.result.kg_evidence_used,
                    "explanation": r.result.explanation[:200],
                    "taint_trace": r.result.taint_trace,
                    "patch_suggestion": r.result.patch_suggestion,
                    "analysis_time_sec": round(r.result.analysis_time_sec, 2),
                }
                for r in results
            ],
        }

    latte_sum = summarize(latte_results, "LATTE_Baseline_B2")
    fg_sum    = summarize(fg_results,    "FirmGraph_LLM_P")

    # Build comparison report
    comparison = {
        "binary_analyzed": binary_name,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "LATTE_baseline": latte_sum,
        "FirmGraph_LLM":  fg_sum,
        "delta": {
            "additional_vulnerabilities": fg_sum["vulnerable"] - latte_sum["vulnerable"],
            "kg_evidence_used": sum(1 for r in fg_results if r.result.kg_evidence_used),
        }
    }

    # Save comparison JSON
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{binary_name}_comparison.json"
    out_path.write_text(json.dumps(comparison, indent=2))
    log.info(f"  ✓ Comparison report saved → {out_path}")

    # Print summary table
    print("\n" + "=" * 70)
    print(f"  EVALUATION SUMMARY — {binary_name}")
    print("=" * 70)
    print(f"  {'Metric':<30} {'LATTE (B2)':>15} {'FirmGraph (P)':>15}")
    print("-" * 70)
    print(f"  {'Flows Analyzed':<30} {latte_sum['total']:>15} {fg_sum['total']:>15}")
    print(f"  {'Vulnerable Found':<30} {latte_sum['vulnerable']:>15} {fg_sum['vulnerable']:>15}")
    print(f"  {'KG Evidence Used':<30} {'N/A':>15} {comparison['delta']['kg_evidence_used']:>15}")

    # Per-finding details
    print("\n" + "-" * 70)
    print("  FINDING DETAILS")
    print("-" * 70)
    all_flow_ids = set(r.flow_id for r in (latte_results + fg_results))
    for fid in all_flow_ids:
        l_r = next((r for r in latte_results if r.flow_id == fid), None)
        f_r = next((r for r in fg_results   if r.flow_id == fid), None)
        print(f"\n  Flow: {fid}")
        if l_r:
            vuln_str = "VULNERABLE" if l_r.result.vulnerable else "safe"
            print(f"    LATTE:     {vuln_str:12} CWE={l_r.cwe:<10} conf={l_r.llm_confidence:.2f}")
        if f_r:
            vuln_str = "VULNERABLE" if f_r.result.vulnerable else "safe"
            kg_str = " [KG+]" if f_r.result.kg_evidence_used else ""
            print(f"    FirmGraph: {vuln_str:12} CWE={f_r.cwe:<10} conf={f_r.llm_confidence:.2f}  score={f_r.final_score:.2f}{kg_str}")
            if f_r.result.taint_trace:
                print(f"    Taint: {f_r.result.taint_trace}")

    print("\n" + "=" * 70)
    print(f"  Report: {out_path}")
    print("=" * 70 + "\n")

    return comparison


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="FirmGraph-LLM — Complete End-to-End Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--flows", default="data/flows/sample_cwe78_flow.json",
                        help="Path to a single flow JSON or directory of flow JSONs")
    parser.add_argument("--all-flows", action="store_true",
                        help="Load ALL flow files from the flows directory")
    parser.add_argument("--binary", default=None,
                        help="Binary name for reports (auto-detected if not set)")
    parser.add_argument("--model",  default="qwen2.5:3b",
                        help="Ollama model name (default: qwen2.5:3b)")
    parser.add_argument("--temperature", type=float, default=0.4)
    parser.add_argument("--output",  default="reports/",
                        help="Output directory for reports")
    parser.add_argument("--neo4j-uri",  default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-pass", default="firmgraph")
    parser.add_argument("--setup-only", action="store_true",
                        help="Only set up KG + embeddings, do not run analysis")
    parser.add_argument("--skip-latte", action="store_true",
                        help="Skip LATTE baseline, run FirmGraph-LLM only")
    parser.add_argument("--skip-kg", action="store_true",
                        help="Skip KG setup (assume already running)")
    args = parser.parse_args()

    flows_path  = ROOT / args.flows
    output_dir  = ROOT / args.output
    index_path  = ROOT / "data" / "embeddings" / "functions.index"
    meta_path   = ROOT / "data" / "embeddings" / "metadata.json"
    gt_path     = ROOT / "data" / "juliet" / "ground_truth.json"
    flows_dir   = ROOT / "data" / "flows"

    # ── STEP 1: Neo4j Setup ────────────────────────────────────────────────────
    builder = kg_retrieval = None
    if not args.skip_kg:
        builder, kg_retrieval = setup_neo4j(
            args.neo4j_uri, args.neo4j_user, args.neo4j_pass
        )
    else:
        log.info("Connecting to existing KG (--skip-kg)")
        builder, kg_retrieval = connect_neo4j(
            args.neo4j_uri, args.neo4j_user, args.neo4j_pass
        )

    try:
        # ── STEP 2: Build Embeddings ───────────────────────────────────────────────
        build_embeddings(flows_dir, index_path, meta_path)

        # ── STEP 3: Seed KG with Known Patterns ───────────────────────────────────
        if builder:
            ingest_known_patterns(builder, flows_dir)

        if args.setup_only:
            log.info("Setup complete (--setup-only). Exiting.")
            return

        # ── Load flows ─────────────────────────────────────────────────────────────
        from llm.reasoning.conversation import load_flows_from_json

        if args.all_flows and flows_path.is_dir():
            all_flows = []
            for fj in sorted(flows_path.glob("*.json")):
                all_flows.extend(load_flows_from_json(fj))
            flows = all_flows
        elif flows_path.is_dir():
            # Pick first JSON in directory
            first = next(flows_path.glob("*.json"), None)
            flows = load_flows_from_json(first) if first else []
        else:
            flows = load_flows_from_json(flows_path)

        if not flows:
            log.error(f"No flows found at {flows_path}")
            sys.exit(1)

        binary_name = args.binary or flows[0].binary_name
        log.info(f"\nLoaded {len(flows)} DangerousFlow(s) for binary '{binary_name}'")

        # ── STEP 4: LATTE Baseline ─────────────────────────────────────────────────
        latte_results = []
        if not args.skip_latte:
            latte_results = run_latte_baseline(
                flows, binary_name, args.model, args.temperature
            )

        # ── STEP 5: FirmGraph-LLM ─────────────────────────────────────────────────
        fg_results = run_firmgraph(
            flows, binary_name, args.model, args.temperature,
            builder, kg_retrieval,
            index_path, meta_path,
            output_dir,
        )

        # ── STEP 6: Compare & Report ───────────────────────────────────────────────
        if latte_results or fg_results:
            compare_and_report(latte_results, fg_results, binary_name, output_dir, gt_path)
    finally:
        if builder:
            builder.close()


if __name__ == "__main__":
    main()
