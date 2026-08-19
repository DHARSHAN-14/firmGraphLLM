#!/usr/bin/env python3
"""
FirmGraph-LLM — Main Pipeline Runner
======================================
Entry point for running the full analysis pipeline.

Usage:
    # LATTE baseline (no KG):
    python3 pipeline.py --mode latte --flows data/flows/example.json --binary httpd

    # FirmGraph-LLM (with KG):
    python3 pipeline.py --mode firmgraph --flows data/flows/example.json --binary httpd

    # Run comparative experiment (both modes):
    python3 pipeline.py --mode experiment --flows data/flows/example.json --binary httpd

Prerequisites:
    - Ollama running:  ollama serve
    - Model pulled:    ollama pull qwen3-coder
    - Neo4j running:   (for firmgraph mode) docker run -p 7474:7474 -p 7687:7687 neo4j
"""

import argparse
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("firmgraph")


def build_latte_baseline(args):
    from llm.client import OllamaClient
    from evaluation.evaluation import LATTEBaseline
    client  = OllamaClient(model=args.model, temperature=args.temperature)
    log.info(f"LLM: {client.model} @ {client.base_url}")
    if not client.is_available():
        log.warning("Ollama not responding — ensure 'ollama serve' is running")
    return LATTEBaseline(client)


def build_firmgraph(args):
    from llm.client import OllamaClient
    from analysis.analyzer import FirmGraphAnalyzer, AnalysisConfig
    from knowledge_graph.construction.graph_builder import GraphBuilder
    from knowledge_graph.queries.retrieval import KGRetrieval
    from knowledge_graph.schema.cypher_setup import setup_schema, seed_cwe_data
    from knowledge_graph.ingestion.api_loader import load_known_apis, load_target_cwes
    from retrieval.retrieval import GraphTraversal, GraphRAGRetriever, VectorSearcher

    client = OllamaClient(model=args.model, temperature=args.temperature)

    # KG setup
    try:
        builder = GraphBuilder(uri=args.neo4j_uri, user=args.neo4j_user, password=args.neo4j_pass)
        setup_schema(builder._driver)
        seed_cwe_data(builder._driver)
        load_target_cwes(builder)
        load_known_apis(builder)
        kg_retrieval = KGRetrieval(builder._driver)
    except Exception as e:
        log.warning(f"Neo4j unavailable ({e}) — running without KG (same as LATTE baseline)")
        builder = kg_retrieval = None

    # Retrieval
    retriever = None
    if kg_retrieval:
        traversal = GraphTraversal(kg_retrieval)
        vs = VectorSearcher(
            index_path=ROOT / "data" / "embeddings" / "functions.index",
            metadata_path=ROOT / "data" / "embeddings" / "metadata.json",
        )
        retriever = GraphRAGRetriever(vs, traversal)

    config = AnalysisConfig(
        use_kg_retrieval=bool(retriever),
        results_dir=Path(args.output),
    )
    return FirmGraphAnalyzer(client, graph_builder=builder,
                             graphrag_retriever=retriever, config=config)


def main():
    parser = argparse.ArgumentParser(description="FirmGraph-LLM Pipeline")
    parser.add_argument("--mode",    choices=["latte", "firmgraph", "experiment"],
                        default="latte")
    parser.add_argument("--flows",   required=True, help="Path to DangerousFlows JSON")
    parser.add_argument("--binary",  required=True, help="Binary name (for reports)")
    parser.add_argument("--model",   default="qwen2.5-coder:7b")
    parser.add_argument("--temperature", type=float, default=0.4)
    parser.add_argument("--output",  default="reports/")
    parser.add_argument("--gt",      default="data/juliet/ground_truth.json",
                        help="Ground truth JSON path")
    parser.add_argument("--neo4j-uri",  default="bolt://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-pass", default="firmgraph")
    args = parser.parse_args()

    flows_path = Path(args.flows)
    if not flows_path.exists():
        log.error(f"Flows file not found: {flows_path}")
        sys.exit(1)

    from llm.reasoning.conversation import load_flows_from_json
    flows = load_flows_from_json(flows_path)
    log.info(f"Loaded {len(flows)} DangerousFlows from {flows_path}")

    if args.mode == "latte":
        baseline = build_latte_baseline(args)
        ranked   = baseline.run(flows, args.binary)
        log.info(f"LATTE baseline done: {sum(1 for r in ranked if r.result.vulnerable)} vulnerable")

    elif args.mode == "firmgraph":
        fg     = build_firmgraph(args)
        ranked = fg.analyze(flows, args.binary)
        log.info(f"FirmGraph-LLM done: {sum(1 for r in ranked if r.result.vulnerable)} vulnerable")

    elif args.mode == "experiment":
        from evaluation.evaluation import LATTEBaseline, MetricsCalculator, ExperimentRunner
        baseline = build_latte_baseline(args)
        fg       = build_firmgraph(args)
        metrics  = MetricsCalculator(Path(args.gt))
        runner   = ExperimentRunner(Path(args.gt), Path(args.output) / "experiments/")
        result   = runner.run_experiment(flows, args.binary, baseline, fg, metrics)
        runner.save_experiment_results(result, args.binary)

        print("\n=== Experiment Results ===")
        import json
        print(json.dumps(result["comparison"], indent=2))


if __name__ == "__main__":
    main()
