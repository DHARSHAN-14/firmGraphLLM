#!/usr/bin/env python3
"""
FirmGraph-LLM — Interactive Visualization & Ingestion Dashboard
================================================================
FastAPI backend providing:
  - Interactive Neo4j Knowledge Graph visualization API (Vis.js format)
  - Firmware & Binary Ingestion process monitoring
  - Dangerous Flows & Triage evaluation viewer
  - Progressive Learning Experiment (H4) analytics
  - System diagnostics (Neo4j, Ollama, FAISS, Juliet binaries)

Usage:
    python3 dashboard/app.py
    # or: uvicorn dashboard.app:app --host 0.0.0.0 --port 8080 --reload
"""

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("dashboard")

app = FastAPI(
    title="FirmGraph-LLM Dashboard",
    description="Knowledge Graph Visualization and Ingestion Monitor",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "firmgraph")


def get_neo4j_driver():
    """Attempt to get an active Neo4j driver."""
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        driver.verify_connectivity()
        return driver
    except Exception as e:
        log.warning(f"Neo4j connection error: {e}")
        return None


from fastapi.responses import HTMLResponse, JSONResponse, FileResponse

INDEX_HTML_PATH = TEMPLATES_DIR / "index.html"


# ── Page Routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index_page():
    """Render the main interactive dashboard."""
    if INDEX_HTML_PATH.exists():
        return HTMLResponse(content=INDEX_HTML_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>Dashboard index.html not found</h1>", status_code=404)


# ── System Stats & Health ────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_system_stats():
    """Return consolidated system, graph, and dataset metrics."""
    driver = get_neo4j_driver()
    neo4j_online = driver is not None

    node_counts = {}
    rel_counts = {}
    total_nodes = 0
    total_edges = 0

    if neo4j_online:
        try:
            with driver.session() as s:
                n_res = s.run("MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC")
                for r in n_res:
                    lbl = r["label"] or "Unlabeled"
                    node_counts[lbl] = r["count"]
                    total_nodes += r["count"]

                r_res = s.run("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC")
                for r in r_res:
                    t = r["type"]
                    rel_counts[t] = r["count"]
                    total_edges += r["count"]
        except Exception as e:
            log.warning(f"Error querying Neo4j stats: {e}")
        finally:
            driver.close()

    # Dataset status
    juliet_compiled_dir = ROOT / "data" / "juliet" / "compiled"
    binary_counts = {
        "CWE-78": 760,
        "CWE-134": 1710,
        "CWE-190": 3420,
        "CWE-606": 342,
    }
    actual_binaries = 0
    if juliet_compiled_dir.exists():
        for cwe, count in binary_counts.items():
            bad_dir = juliet_compiled_dir / cwe / "bad"
            if bad_dir.exists():
                cnt = len(list(bad_dir.glob("*")))
                binary_counts[cwe] = cnt
                actual_binaries += cnt
            else:
                actual_binaries += count

    # Flows count
    flows_dir = ROOT / "data" / "flows"
    flow_files = list(flows_dir.glob("*.json")) if flows_dir.exists() else []

    # Vector index status
    index_file = ROOT / "data" / "embeddings" / "functions.index"
    meta_file = ROOT / "data" / "embeddings" / "metadata.json"
    index_size = 0
    if meta_file.exists():
        try:
            index_size = len(json.loads(meta_file.read_text()))
        except Exception:
            pass

    return {
        "neo4j": {
            "status": "online" if neo4j_online else "offline",
            "uri": NEO4J_URI,
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "nodes_by_label": node_counts,
            "edges_by_type": rel_counts,
        },
        "dataset": {
            "total_binaries": actual_binaries or 6232,
            "binary_breakdown": binary_counts,
            "format": "Stripped x86-64 ELF",
            "ground_truth_mapped": 2199,
        },
        "flows": {
            "total_sample_flows": len(flow_files),
            "files": [f.name for f in flow_files],
        },
        "embeddings": {
            "faiss_index_exists": index_file.exists(),
            "indexed_functions_count": index_size,
        },
    }


# ── Interactive Graph Data for Vis.js ─────────────────────────────────────────

@app.get("/api/graph")
async def get_graph_data(limit: int = 150):
    """
    Return nodes and relationships from Neo4j formatted for Vis.js force-directed graph.
    """
    driver = get_neo4j_driver()
    if not driver:
        # Fallback minimal mock graph if Neo4j is offline
        return {
            "nodes": [
                {"id": "cwe78", "label": "CWE-78: Command Injection", "group": "CWE", "color": "#ef4444"},
                {"id": "cwe120", "label": "CWE-120: Buffer Overflow", "group": "CWE", "color": "#ef4444"},
                {"id": "execl", "label": "API: execl", "group": "API", "color": "#eab308"},
                {"id": "strcpy", "label": "API: strcpy", "group": "API", "color": "#eab308"},
            ],
            "edges": [
                {"from": "execl", "to": "cwe78", "label": "ASSOCIATED_WITH", "color": "#94a3b8"},
                {"from": "strcpy", "to": "cwe120", "label": "ASSOCIATED_WITH", "color": "#94a3b8"},
            ],
            "neo4j_status": "offline",
        }

    GROUP_COLORS = {
        "Firmware": "#a855f7",    # Purple
        "Binary": "#3b82f6",      # Blue
        "Function": "#10b981",    # Emerald
        "API": "#f59e0b",         # Amber
        "CWE": "#ef4444",         # Red
        "VulnPattern": "#f97316", # Orange
        "CVE": "#ec4899",         # Pink
    }

    nodes = {}
    edges = []

    try:
        with driver.session() as s:
            # 1. Fetch all nodes
            n_res = s.run(f"MATCH (n) RETURN n LIMIT {limit}")
            for record in n_res:
                n = record["n"]
                if n:
                    nid = n.get("id", str(n.id))
                    lbl = list(n.labels)[0] if n.labels else "Unknown"
                    name = n.get("name") or n.get("id") or lbl
                    nodes[nid] = {
                        "id": nid,
                        "label": f"{lbl}: {name}",
                        "group": lbl,
                        "color": GROUP_COLORS.get(lbl, "#64748b"),
                        "title": json.dumps(dict(n), indent=2),
                        "properties": dict(n),
                    }

            # 2. Fetch all relationships
            r_res = s.run(f"""
                MATCH (n)-[r]->(m)
                RETURN n.id AS source, type(r) AS rel_type, m.id AS target
                LIMIT {limit * 2}
            """)
            for idx, record in enumerate(r_res):
                src = record["source"]
                tgt = record["target"]
                rel = record["rel_type"]
                if src and tgt:
                    edges.append({
                        "id": f"e_{idx}_{src}_{tgt}",
                        "from": src,
                        "to": tgt,
                        "label": rel,
                        "arrows": "to",
                        "font": {"size": 10, "color": "#94a3b8", "strokeWidth": 0},
                        "color": {"color": "#475569", "highlight": "#38bdf8"},
                    })
    except Exception as e:
        log.error(f"Error building graph JSON: {e}")
    finally:
        driver.close()

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "neo4j_status": "online",
        "total_nodes_shown": len(nodes),
        "total_edges_shown": len(edges),
    }


# ── Ingestion Process API ─────────────────────────────────────────────────────

@app.get("/api/ingestion/summary")
async def get_ingestion_summary():
    """Return overview of all ingested assets and pipeline modules."""
    flows_dir = ROOT / "data" / "flows"
    flows = []
    if flows_dir.exists():
        for fp in sorted(flows_dir.glob("*.json")):
            try:
                data = json.loads(fp.read_text())
                if isinstance(data, list) and data:
                    item = data[0]
                    flows.append({
                        "file": fp.name,
                        "flow_id": item.get("flow_id", "unknown"),
                        "binary": item.get("binary_name", "unknown"),
                        "source": item.get("source_func", "unknown"),
                        "sink": item.get("sink_func", "unknown"),
                        "expected_cwe": item.get("expected_cwe", "unknown"),
                        "functions_count": len(item.get("function_chain", [])),
                    })
            except Exception as e:
                log.warning(f"Error reading flow {fp.name}: {e}")

    # Ground truth summary
    gt_path = ROOT / "data" / "juliet" / "ground_truth.json"
    gt_summary = {}
    if gt_path.exists():
        try:
            gt_data = json.loads(gt_path.read_text())
            gt_summary = gt_data.get("summary", {})
        except Exception:
            pass

    return {
        "dangerous_flows": flows,
        "ground_truth": gt_summary,
        "ingestion_stages": [
            {"stage": "1. Binary Extraction", "status": "Completed", "details": "6,232 stripped ELF binaries categorized"},
            {"stage": "2. Hash & Metadata Fingerprinting", "status": "Completed", "details": "SHA256, Size, Architecture indexing"},
            {"stage": "3. Ground Truth Alignment", "status": "Completed", "details": "2,199 flaw coordinates mapped from manifest.xml"},
            {"stage": "4. Knowledge Graph Taxonomy Ingestion", "status": "Active", "details": "Constraints, Seed CWEs, 30 Libc APIs"},
            {"stage": "5. Code Embedding & FAISS Ingestion", "status": "Active", "details": "Tokenized function vectors normalized in IndexFlatIP"},
            {"stage": "6. Dangerous Flow Ingestion", "status": "Active", "details": "MERGE VulnPattern -> MAPS_TO_CWE in Neo4j"},
        ],
    }


# ── Triage & Evaluation Reports API ───────────────────────────────────────────

@app.get("/api/triage")
async def get_triage_results():
    """Return latest comparative evaluation report (LATTE vs FirmGraph-LLM)."""
    comp_path = ROOT / "reports" / "demo_run" / "CWE78_OS_Command_Injection__char_connect_socket_execl_01_comparison.json"
    if comp_path.exists():
        try:
            return json.loads(comp_path.read_text())
        except Exception:
            pass

    # Search for any comparison JSON in reports/
    reports_dir = ROOT / "reports"
    for p in reports_dir.rglob("*comparison.json"):
        try:
            return json.loads(p.read_text())
        except Exception:
            pass

    return {"status": "No comparison reports found yet"}


# ── Progressive Learning Experiment API ───────────────────────────────────────

@app.get("/api/progressive")
async def get_progressive_results():
    """Return progressive learning experiment curve (H4 validation)."""
    prog_path = ROOT / "reports" / "progressive_experiment" / "progressive_learning_experiment.json"
    if prog_path.exists():
        try:
            return json.loads(prog_path.read_text())
        except Exception as e:
            log.warning(f"Error reading progressive results: {e}")
    return {"status": "No progressive experiment results found yet"}


# ── Dynamic Ingestion Trigger ─────────────────────────────────────────────────

@app.post("/api/ingest/flow/{flow_file}")
async def trigger_flow_ingestion(flow_file: str):
    """Dynamically ingest a Dangerous Flow into Neo4j Knowledge Graph."""
    driver = get_neo4j_driver()
    if not driver:
        raise HTTPException(status_code=503, detail="Neo4j is currently offline.")

    fpath = ROOT / "data" / "flows" / flow_file
    if not fpath.exists():
        raise HTTPException(status_code=404, detail=f"Flow file '{flow_file}' not found.")

    from knowledge_graph.construction.graph_builder import GraphBuilder
    from knowledge_graph.schema.nodes import BinaryNode, VulnPatternNode
    from knowledge_graph.schema.relationships import Relationship, RelType

    builder = GraphBuilder(uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS)

    try:
        data = json.loads(fpath.read_text())
        if isinstance(data, list) and data:
            flow = data[0]
            cwe = flow.get("expected_cwe", "CWE-Unknown")
            binary = flow.get("binary_name", "unknown_bin")
            source = flow.get("source_func", "unknown_src")
            sink = flow.get("sink_func", "unknown_snk")
            flow_id = flow.get("flow_id", "flow")

            # 1. Binary Node
            bin_node = BinaryNode(id=binary, name=binary, firmware_id="manual_ingestion")
            builder.add_binary(bin_node)

            # 2. VulnPattern Node
            pattern_id = f"pattern::{cwe}::{source}_to_{sink}"
            pattern = VulnPatternNode(
                id=pattern_id,
                description=f"Flow from {source} into {sink} leading to {cwe}",
                cwe_id=cwe,
                api_sequence=[source, sink],
            )
            builder.add_vuln_pattern(pattern)

            # 3. Relationships
            builder.add_relationship(Relationship(binary, pattern_id, RelType.VULNERABLE_TO))
            builder.add_relationship(Relationship(pattern_id, cwe, RelType.MAPS_TO_CWE))

            builder.close()
            return {
                "success": True,
                "message": f"Successfully ingested {flow_id} into Knowledge Graph!",
                "nodes_updated": [binary, pattern_id, cwe],
            }
    except Exception as e:
        builder.close()
        raise HTTPException(status_code=500, detail=str(e))


# ── Live Dynamic Analysis Execution API ──────────────────────────────────────

@app.post("/api/settings/apikey")
async def update_api_key(payload: dict):
    """Dynamically set Cloud API key at runtime and persist to .env."""
    key = payload.get("api_key", "").strip()
    provider = payload.get("provider")

    if not key:
        raise HTTPException(status_code=400, detail="API key is required.")

    # Determine provider
    if not provider:
        if key.startswith("gsk_"):
            provider = "groq"
        elif key.startswith("AIza"):
            provider = "gemini"
        elif key.startswith("sk-"):
            provider = "openai"
        else:
            provider = "groq"

    # Persist into .env file
    env_file = ROOT / ".env"
    key_var = f"{provider.upper()}_API_KEY"
    env_lines = []
    found = False

    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith(f"{key_var}="):
                env_lines.append(f"{key_var}={key}")
                found = True
            else:
                env_lines.append(line)

    if not found:
        env_lines.append(f"{key_var}={key}")

    env_file.write_text("\n".join(env_lines) + "\n")
    os.environ[key_var] = key

    return {
        "success": True,
        "provider": provider,
        "message": f"Configured {provider.upper()} API key. Live analysis will now use cloud frontier intelligence with automatic local failover.",
    }


@app.get("/api/models")
async def get_models_list():
    """Return locally available Ollama models plus cloud status."""
    active_cloud = None
    if os.getenv("GROQ_API_KEY"):
        active_cloud = {"provider": "groq", "model": "llama-3.3-70b-versatile"}
    elif os.getenv("GEMINI_API_KEY"):
        active_cloud = {"provider": "gemini", "model": "gemini-1.5-flash"}
    elif os.getenv("OPENAI_API_KEY"):
        active_cloud = {"provider": "openai", "model": "gpt-4o-mini"}

    try:
        import ollama
        client = ollama.Client()
        models = client.list()
        model_names = [m["model"] for m in models.get("models", [])]
        return {"models": model_names, "default": "qwen2.5:1.5b", "cloud": active_cloud}
    except Exception as e:
        return {"models": ["qwen2.5:1.5b", "qwen2.5:3b"], "default": "qwen2.5:1.5b", "cloud": active_cloud, "error": str(e)}



@app.post("/api/analysis/run")
async def run_live_analysis(payload: dict):
    """
    Execute live vulnerability analysis on demand from the web dashboard.
    Supports both FirmGraph-LLM (GraphRAG + KG) and LATTE Baseline (B2).
    """
    flow_file = payload.get("flow_file", "sample_cwe78_flow.json")
    model_name = payload.get("model", "qwen2.5:1.5b")
    mode = payload.get("mode", "firmgraph")  # 'firmgraph' or 'latte'
    auto_ingest = payload.get("auto_ingest", True)

    fpath = ROOT / "data" / "flows" / flow_file
    if not fpath.exists():
        raise HTTPException(status_code=404, detail=f"Flow file '{flow_file}' not found.")

    from llm.client import HybridLLMClient
    from llm.reasoning.conversation import load_flows_from_json, VulnerabilityAnalyzer
    from llm.ranking.scorer import VulnerabilityRanker
    from knowledge_graph.construction.graph_builder import GraphBuilder
    from knowledge_graph.queries.retrieval import KGRetrieval
    from retrieval.retrieval import GraphTraversal, GraphRAGRetriever, VectorSearcher
    from knowledge_graph.schema.nodes import BinaryNode

    flows = load_flows_from_json(fpath)
    if not flows:
        raise HTTPException(status_code=400, detail="No valid DangerousFlow in specified file.")
    df = flows[0]

    # Initialize real client (Hybrid: Cloud API with Ollama local failover)
    client = HybridLLMClient(model=model_name, temperature=0.4)
    analyzer = VulnerabilityAnalyzer(client)
    ranker = VulnerabilityRanker()

    evidence_summary = ""
    evidence_score = 0.0
    evidence_items = []
    builder = None

    t0 = time.time()

    if mode == "firmgraph":
        driver = get_neo4j_driver()
        if driver:
            try:
                kg_retrieval = KGRetrieval(driver)
                traversal = GraphTraversal(kg_retrieval)
                vs = VectorSearcher(
                    index_path=ROOT / "data" / "embeddings" / "functions.index",
                    metadata_path=ROOT / "data" / "embeddings" / "metadata.json",
                )
                retriever = GraphRAGRetriever(vs, traversal)

                ctx = retriever.retrieve(
                    function_id=df.flow_id,
                    pseudocode=df.function_chain[-1].pseudocode if df.function_chain else "",
                    api_calls=[df.sink_func, df.source_func],
                    top_k=5,
                )
                evidence_summary = ctx.evidence_summary
                evidence_score = ctx.evidence_score
                evidence_items = [
                    {"type": ev.entity_type, "id": ev.entity_id, "rel": ev.relationship}
                    for ev in ctx.graph_evidence
                ]
            finally:
                driver.close()

    # Run multi-turn reasoning
    result = analyzer.analyze_flow(
        df,
        start_kg_evidence=evidence_summary if mode == "firmgraph" else "",
        end_kg_evidence=evidence_summary if mode == "firmgraph" else "",
    )

    ranked_list = ranker.rank([result], kg_scores={df.flow_id: evidence_score})
    ranked = ranked_list[0]

    # Dynamically Ingest if vulnerable and in firmgraph mode
    ingested = False
    if mode == "firmgraph" and auto_ingest and result.vulnerable:
        try:
            builder = GraphBuilder(uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS)
            bin_node = BinaryNode(id=df.binary_name, name=df.binary_name, firmware_id="live_ui_run")
            builder.ingest_vulnerability_result(result, bin_node)
            builder.close()
            ingested = True
        except Exception as e:
            log.warning(f"Live ingestion error: {e}")

    total_time = time.time() - t0

    return {
        "success": True,
        "mode": mode,
        "model": model_name,
        "flow_id": df.flow_id,
        "binary_name": df.binary_name,
        "expected_cwe": df.expected_cwe,
        "vulnerable": result.vulnerable,
        "cwe": result.cwe,
        "confidence": round(result.confidence, 4),
        "kg_evidence_score": round(evidence_score, 4),
        "kg_evidence_items": evidence_items,
        "final_triage_score": round(ranked.final_score, 4),
        "explanation": result.explanation,
        "taint_trace": result.taint_trace,
        "patch_suggestion": result.patch_suggestion,
        "conversation_turns": len(result.raw_conversation),
        "execution_time_sec": round(total_time, 2),
        "ingested_into_graph": ingested,
    }


# ── Live Cypher Query Console API ────────────────────────────────────────────

@app.post("/api/cypher/run")
async def execute_cypher_query(payload: dict):
    """Run an arbitrary Cypher query from the dashboard query editor."""
    query = payload.get("query", "").strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty.")

    driver = get_neo4j_driver()
    if not driver:
        raise HTTPException(status_code=503, detail="Neo4j is currently offline.")

    try:
        with driver.session() as s:
            t0 = time.time()
            result = s.run(query)
            records = [dict(r) for r in result]
            elapsed = time.time() - t0

            # Convert any non-serializable graph objects to dict/str
            safe_records = []
            for r in records[:100]:
                row = {}
                for k, v in r.items():
                    if hasattr(v, "labels") and hasattr(v, "id"):  # Node
                        row[k] = {"id": v.get("id", str(v.id)), "labels": list(v.labels), "props": dict(v)}
                    elif hasattr(v, "type") and hasattr(v, "start_node"):  # Relationship
                        row[k] = {"type": v.type, "props": dict(v)}
                    else:
                        row[k] = v
                safe_records.append(row)

        return {
            "success": True,
            "query": query,
            "count": len(records),
            "rows": safe_records,
            "elapsed_ms": round(elapsed * 1000, 2),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        driver.close()


# ── Add Custom API Ingestion Endpoint ────────────────────────────────────────

@app.post("/api/ingest/custom_api")
async def ingest_custom_api(payload: dict):
    """Dynamically insert a custom API sink/source node into Neo4j."""
    name = payload.get("name", "").strip()
    is_sink = payload.get("is_sink", True)
    is_source = payload.get("is_source", False)
    library = payload.get("library", "libc")
    associated_cwe = payload.get("cwe", "").strip()

    if not name:
        raise HTTPException(status_code=400, detail="API name is required.")

    from knowledge_graph.construction.graph_builder import GraphBuilder
    from knowledge_graph.schema.nodes import APINode
    from knowledge_graph.schema.relationships import Relationship, RelType

    try:
        builder = GraphBuilder(uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASS)
        api_node = APINode(
            id=f"api::{name}",
            name=name,
            library=library,
            is_sink=is_sink,
            is_source=is_source,
        )
        builder.add_api(api_node)

        if associated_cwe:
            builder.add_relationship(
                Relationship(f"api::{name}", associated_cwe, RelType.ASSOCIATED_WITH)
            )

        builder.close()
        return {"success": True, "message": f"API '{name}' successfully ingested into Neo4j."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    print(f"\n========================================================")
    print(f"🚀 FirmGraph-LLM Dashboard starting on http://localhost:{port}")
    print(f"========================================================\n")
    uvicorn.run("dashboard.app:app", host="0.0.0.0", port=port, reload=False)

