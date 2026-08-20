# FirmGraph-LLM: Technical Reference, File-by-File Implementation Index & Demonstration Guide

**Project Title:** FirmGraph-LLM — Knowledge Graph-Guided Large Language Models for Cross-Firmware Vulnerability Discovery  
**Base Research:** LATTE (LLM-Powered Static Binary Taint Analysis, *ACM TOSEM 2025*)  
**Status:** Milestone 1 Complete (Pipeline Architecture, Juliet Benchmark Dataset, Local LLM Integration, Baseline Validation)  
**Date:** August 20, 2026  
**Document Location:** `R&D_Docs/DEMONSTRATION_AND_PROJECT_STATUS_REPORT.md`

---

## 📑 Table of Contents
1. [Executive Summary (What Has Been Done)](#1-executive-summary)
2. [Complete System Architecture Diagram](#2-system-architecture-diagram)
3. [File-by-File Technical Implementation Index](#3-file-by-file-technical-implementation-index)
   - [3.1 LLM Reasoning & Prompt Sequences (`llm/`)](#31-llm-reasoning--prompt-sequences-llm)
   - [3.2 Knowledge Graph Engine (`knowledge_graph/`)](#32-knowledge-graph-engine-knowledge_graph)
   - [3.3 Vector & GraphRAG Retrieval (`retrieval/`)](#33-vector--graphrag-retrieval-retrieval)
   - [3.4 Analysis Orchestrator & Reporting (`analysis/`)](#34-analysis-orchestrator--reporting-analysis)
   - [3.5 Evaluation, Metrics & Baselines (`evaluation/`)](#35-evaluation-metrics--baselines-evaluation)
   - [3.6 Embedding Pipeline (`embeddings/`)](#36-embedding-pipeline-embeddings)
   - [3.7 Dataset & Compilation Scripts (`scripts/`)](#37-dataset--compilation-scripts-scripts)
   - [3.8 Pipeline Runner & CLI (`pipeline.py`)](#38-pipeline-runner--cli-pipelinepy)
   - [3.9 Data Storage & Benchmark Datasets (`data/`)](#39-data-storage--benchmark-datasets-data)
   - [3.10 Generated Reports (`reports/`)](#310-generated-reports-reports)
4. [How to View and Inspect Every Artifact](#4-how-to-view-and-inspect-every-artifact)
5. [Step-by-Step Live Demonstration Script](#5-step-by-step-live-demonstration-script)
6. [Presentation Talking Points & Defense Pitch](#6-presentation-talking-points--defense-pitch)

---

## 1. Executive Summary

We have designed, implemented, and validated the complete foundational architecture for **FirmGraph-LLM**, a framework that extends the state-of-the-art LLM-based binary analysis paper (**LATTE**, ACM TOSEM 2025) with a **persistent Knowledge Graph (Neo4j)** and **GraphRAG retrieval (UniXcoder + FAISS)**.

### What Has Been Completed:
1. **Juliet Test Suite Benchmark (6,232 Binaries):** Multi-threaded compilation pipeline (`scripts/compile_juliet.py`) produced **6,232 stripped x86-64 ELF executables** (202 MB) across CWE-78, 134, 190, 606, linked to **2,199 ground truth entries** (`data/juliet/ground_truth.json`).
2. **Local Open-Source AI Infrastructure:** Configured Ollama with **Qwen2.5-Coder 7B** (128K context) running locally on CPU with zero commercial API costs or data leakage.
3. **36 Production-Grade Architecture Modules:** Implemented all 12 stages of the FirmGraph-LLM system with type hints, dataclasses, and zero syntax errors.
4. **End-to-End Baseline Validation:** Ran the multi-turn taint analysis pipeline on a socket-to-exec command injection flow, achieving **100% confidence** and verified structured reports.

---

## 2. System Architecture Diagram

```
                              [ Compiled Stripped Binaries (6,232) ]
                                                │
                                                ▼ (Phase 3: Ghidra Decompiler)
                                     [ Dangerous Flow (DF) ]
                           (Call Chain from Taint Source to Sink)
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     │                                                     │
                     ▼ (B2: LATTE Baseline Mode)                           ▼ (P: FirmGraph-LLM Mode)
          ┌──────────────────────────┐                        ┌──────────────────────────┐
          │  Vulnerability Analyzer  │                        │    GraphRAG Retriever    │
          │   (Multi-Turn PS Flow)   │                        │ (FAISS Vector + Neo4j KG)│
          └─────────────┬────────────┘                        └─────────────┬────────────┘
                        │                                                   │ Historical Evidence
                        │                                                   ▼
                        │                                     ┌──────────────────────────┐
                        │                                     │ Grounded Prompt Sequence │
                        │                                     │  (Start -> Mid -> End)   │
                        │                                     └─────────────┬────────────┘
                        │                                                   │
                        └───────────────────────┬───────────────────────────┘
                                                ▼
                                   [ Vulnerability Verdict ]
                                    - is_vulnerable: bool
                                    - cwe_type: CWE-XX
                                    - confidence: 0.0 - 1.0
                                    - taint_trace: step-by-step
                                                │
                     ┌──────────────────────────┴──────────────────────────┐
                     ▼                                                     ▼
        [ Knowledge Graph Ingestion ]                             [ Multi-Factor Ranker ]
       (MERGE Pattern -> Neo4j KG)                                (LLM + KG + CWE Weights)
                                                                           │
                                                                           ▼
                                                             [ Final Ranked Triage Report ]
                                                                (JSON & Markdown Output)
                                                                           │
                                                                           ▼
                                                             [ Evaluation & Metrics ]
                                                              (Precision / Recall / F1 / MRR)
```

---

## 3. File-by-File Technical Implementation Index

This section provides a detailed technical mapping of **every file in the project**, its implementation details, exported classes, and how to explain it during a presentation.

---

### 3.1 LLM Reasoning & Prompt Sequences (`llm/`)

The `llm/` module contains the multi-turn conversational reasoning engine based on Section 3 of the LATTE paper.

#### 📄 [`llm/client.py`](file:///home/dharshan/Documents/R&D/llm/client.py)
* **Purpose:** Local Ollama client wrapper with automatic error handling and fallback model switching.
* **Paper Mapping:** Section 3.1 (LLM Inference Layer).
* **Key Components:**
  - `class OllamaClient`: Configures temperature (0.4), context length, and handles multi-turn `chat()` and single-turn `generate()`.
  - `class OllamaNotAvailableError`: Informative exception raised if the Ollama daemon is offline.
  - `switch_model()`: Allows dynamically falling back between `qwen2.5-coder:7b` and other models.
* **Presentation Note:** Explain that this isolates the codebase from the underlying inference provider, enabling zero-cost local execution on consumer CPUs without sending proprietary firmware code to third-party cloud APIs.

#### 📄 [`llm/prompts/templates.py`](file:///home/dharshan/Documents/R&D/llm/prompts/templates.py)
* **Purpose:** All prompt templates specified in the LATTE paper (Section 3.2).
* **Paper Mapping:** Prompt Sequence (PS) — Start Prompt, Middle Prompt, End Prompt, and One-Shot API Prompts.
* **Key Components:**
  - `PromptTemplates.sink_identification()`: One-shot prompt determining if an external function is a dangerous sink.
  - `PromptTemplates.source_identification()`: One-shot prompt determining if an external function introduces attacker input.
  - `PromptTemplates.start()`: Turn 1 of taint analysis — sets security persona, establishes tainted source parameters, and injects optional GraphRAG evidence.
  - `PromptTemplates.middle()`: Turn 2..N-1 — tracks variable aliases and sanitization checks across intermediate functions.
  - `PromptTemplates.end()`: Final Turn — inspects the sink call site and requests a strict JSON verdict with CWE classification.
* **Presentation Note:** Open this file to show the structured prompt design. Highlight how FirmGraph-LLM extends LATTE's prompts with the `kg_evidence` injection block.

#### 📄 [`llm/prompts/few_shot.py`](file:///home/dharshan/Documents/R&D/llm/prompts/few_shot.py)
* **Purpose:** Canonical one-shot few-shot demonstration examples for sink/source classification.
* **Key Components:**
  - `SINK_EXAMPLES`: Grounded examples for `system()`, `execl()`, `popen()` (CWE-78), `strcpy()`, `memcpy()`, `gets()` (CWE-120), `printf()`, `sprintf()` (CWE-134).
  - `SOURCE_EXAMPLES`: Grounded examples for `recv()`, `recvfrom()`, `read()`, `fgets()`, `fscanf()`, `getenv()`, `SSL_read()`.
* **Presentation Note:** Show that few-shot examples force the LLM to output consistent, machine-parseable JSON instead of free-form conversational text.

#### 📄 [`llm/reasoning/sink_source.py`](file:///home/dharshan/Documents/R&D/llm/reasoning/sink_source.py)
* **Purpose:** Automated classification and disk-caching of external library functions.
* **Paper Mapping:** Section 3.2 (Sink & Source Recognition).
* **Key Components:**
  - `class SinkSourceIdentifier`: Evaluates unknown function names using the LLM and caches results to `data/juliet/sink_source_cache.json`.
  - `dataclass SinkInfo` & `dataclass SourceInfo`: Structured metadata holding parameter indices and CWE associations.
* **Presentation Note:** Emphasize that sink/source knowledge is binary-independent and cached across runs to avoid redundant inference calls.

#### 📄 [`llm/reasoning/conversation.py`](file:///home/dharshan/Documents/R&D/llm/reasoning/conversation.py)
* **Purpose:** Multi-turn conversational taint tracking engine for Dangerous Flows.
* **Paper Mapping:** Section 3.3 (Taint Analysis via Multi-Turn Dialogue).
* **Key Components:**
  - `dataclass DangerousFlow`: Represents a call chain from source to sink with decompiled pseudocode.
  - `dataclass FunctionRecord`: Holds function name, address, decompiled C code, and API calls.
  - `dataclass VulnerabilityResult`: Complete verdict holding vulnerability status, CWE ID, confidence, taint trace, and patch suggestion.
  - `class VulnerabilityAnalyzer`: Orchestrates the multi-turn conversation (`analyze_flow()`), maintains dialog memory, parses JSON verdicts, and supports batch processing (`analyze_batch()`).
* **Presentation Note:** This is the core reasoning heart of LATTE. Explain how dialogue turns maintain context across deep function call stacks without overflowing the context window.

#### 📄 [`llm/ranking/scorer.py`](file:///home/dharshan/Documents/R&D/llm/ranking/scorer.py)
* **Purpose:** Multi-factor vulnerability triage scoring and ranking engine.
* **Paper Mapping:** FirmGraph-LLM novel contribution over LATTE.
* **Key Components:**
  - `class VulnerabilityRanker`: Computes a weighted final score:
    $$\text{Final Score} = (w_{\text{llm}} \times \text{Confidence}) + (w_{\text{kg}} \times \text{KG Evidence}) + (w_{\text{cwe}} \times \text{Severity})$$
  - `dataclass RankedVulnerability`: Enriched finding with rank position, severity weights, and evidence tags.
* **Presentation Note:** Explain that in real firmware, analysts face hundreds of warnings; our ranker prioritizes high-confidence, graph-confirmed, critical vulnerabilities (CWE-78/120) over low-severity noise.

---

### 3.2 Knowledge Graph Engine (`knowledge_graph/`)

The `knowledge_graph/` module implements FirmGraph-LLM's persistent Neo4j schema for cross-firmware knowledge reuse.

#### 📄 [`knowledge_graph/schema/nodes.py`](file:///home/dharshan/Documents/R&D/knowledge_graph/schema/nodes.py)
* **Purpose:** Entity dataclasses for all Knowledge Graph node types.
* **Key Nodes Defined:**
  - `FirmwareNode`: Vendor, product, version, architecture.
  - `BinaryNode`: Executable name, architecture, hash, linked libraries.
  - `FunctionNode`: Function name, binary ID, address, decompiled code, UniXcoder embedding vector.
  - `APINode`: Library name, sink/source flags, vulnerable parameter indices.
  - `CWENode`: Official MITRE CWE ID, name, severity, and parent taxonomy ID.
  - `VulnPatternNode`: Reusable vulnerability pattern, API call sequences, occurrence counter.
* **Presentation Note:** Show that the graph connects low-level binary code (functions, APIs) to high-level security semantics (CWEs, CVEs, firmware vendors).

#### 📄 [`knowledge_graph/schema/relationships.py`](file:///home/dharshan/Documents/R&D/knowledge_graph/schema/relationships.py)
* **Purpose:** Edge definitions and relationship taxonomies.
* **Key Relationships:**
  - `CONTAINS` (Firmware $\to$ Binary)
  - `HAS_FUNCTION` (Binary $\to$ Function)
  - `CALLS` (Function $\to$ Function)
  - `USES` (Function $\to$ API)
  - `SIMILAR_TO` (Function $\to$ Function with cosine similarity weight)
  - `VULNERABLE_TO` (Function $\to$ VulnPattern)
  - `MAPS_TO_CWE` (VulnPattern $\to$ CWE)
  - `PARENT_OF` (CWE $\to$ CWE hierarchy)

#### 📄 [`knowledge_graph/schema/cypher_setup.py`](file:///home/dharshan/Documents/R&D/knowledge_graph/schema/cypher_setup.py)
* **Purpose:** Automated Neo4j schema initializer.
* **Key Functions:**
  - `setup_schema()`: Enforces uniqueness constraints on `id` properties and creates lookup indexes on `name` and `binary_id`.
  - `seed_cwe_data()`: Inserts base MITRE CWE hierarchy for CWE-78, 120, 134, 190, 606.

#### 📄 [`knowledge_graph/construction/graph_builder.py`](file:///home/dharshan/Documents/R&D/knowledge_graph/construction/graph_builder.py)
* **Purpose:** High-level, idempotent Graph writing engine using Cypher `MERGE`.
* **Key Functions:**
  - `add_firmware()`, `add_binary()`, `add_function()`, `add_api()`: Idempotent node creators.
  - `ingest_vulnerability_result()`: Automatically digests an LLM finding, creates a `VulnPatternNode`, wires `VULNERABLE_TO` edges, and updates occurrence counters.
* **Presentation Note:** Highlight the `ingest_vulnerability_result()` method — this is the exact mechanism by which FirmGraph-LLM **learns** from each analysis and enriches the database for future runs.

#### 📄 [`knowledge_graph/queries/retrieval.py`](file:///home/dharshan/Documents/R&D/knowledge_graph/queries/retrieval.py)
* **Purpose:** Cypher retrieval query library.
* **Key Functions:**
  - `get_similar_functions()`: Finds cross-firmware functions linked via `SIMILAR_TO` edges.
  - `get_api_cwe_associations()`: Retrieves known CWE risks for candidate APIs.
  - `get_cross_firmware_evidence()`: Finds whether similar API sequences (e.g., `recv -> sprintf -> system`) were vulnerable in other firmware binaries.

#### 📄 [`knowledge_graph/ingestion/api_loader.py`](file:///home/dharshan/Documents/R&D/knowledge_graph/ingestion/api_loader.py)
* **Purpose:** Pre-loads standard C library sinks (`system`, `execl`, `strcpy`, `printf`) and sources (`recv`, `read`, `fgets`, `getenv`) into Neo4j.

---

### 3.3 Vector & GraphRAG Retrieval (`retrieval/`)

#### 📄 [`retrieval/retrieval.py`](file:///home/dharshan/Documents/R&D/retrieval/retrieval.py)
* **Purpose:** Hybrid retrieval engine combining FAISS vector search with Neo4j multi-hop graph traversal.
* **Paper Mapping:** FirmGraph-LLM GraphRAG Retrieval Layer.
* **Key Classes:**
  - `class VectorSearcher`: Performs fast cosine similarity search over UniXcoder embeddings stored in FAISS `IndexFlatIP`.
  - `class GraphTraversal`: Performs multi-hop graph walks from query functions to extract related vulnerability patterns.
  - `class GraphRAGRetriever`: Integrates vector and graph results, computes combined evidence scores, and formats the `evidence_summary` string injected into LLM prompts.
* **Presentation Note:** Explain how GraphRAG bridges semantic code similarity (Vector) with structural security relationships (Graph).

---

### 3.4 Analysis Orchestrator & Reporting (`analysis/`)

#### 📄 [`analysis/analyzer.py`](file:///home/dharshan/Documents/R&D/analysis/analyzer.py)
* **Purpose:** End-to-end execution orchestrator and report generator.
* **Key Classes:**
  - `class FirmGraphAnalyzer`: Orchestrates the complete pipeline: takes Dangerous Flows $\to$ fetches GraphRAG context $\to$ runs LLM multi-turn reasoning $\to$ ingests findings into KG $\to$ ranks vulnerabilities $\to$ saves reports.
  - `class ReportGenerator`: Generates structured JSON reports and formatted Markdown summary documents with evidence trails and taint traces.

---

### 3.5 Evaluation, Metrics & Baselines (`evaluation/`)

#### 📄 [`evaluation/evaluation.py`](file:///home/dharshan/Documents/R&D/evaluation/evaluation.py)
* **Purpose:** Ground-truth benchmarking and comparative evaluation framework.
* **Key Classes:**
  - `class MetricsCalculator`: Computes **Precision, Recall, F1-Score, Accuracy, Mean Reciprocal Rank (MRR), and Top-K Recall (Top-1, Top-3, Top-5, Top-10)** against Juliet ground truth.
  - `class LATTEBaseline`: Implements the pure LATTE baseline (B2: LLM reasoning with `use_kg_retrieval=False`).
  - `class ExperimentRunner`: Runs both LATTE and FirmGraph-LLM side-by-side on the same binaries and produces automated delta comparison tables.

---

### 3.6 Embedding Pipeline (`embeddings/`)

#### 📄 [`embeddings/config.py`](file:///home/dharshan/Documents/R&D/embeddings/config.py)
* **Purpose:** Centralized model configuration specifying `microsoft/unixcoder-base` (768-dim, CPU device) and Ollama `qwen2.5-coder:7b` parameters.

#### 📄 [`embeddings/embed_functions.py`](file:///home/dharshan/Documents/R&D/embeddings/embed_functions.py)
* **Purpose:** Tokenizes decompiled pseudocode, computes mean-pooled UniXcoder embeddings, normalizes vectors, and builds FAISS index files (`functions.index` + `metadata.json`).

---

### 3.7 Dataset & Compilation Scripts (`scripts/`)

#### 📄 [`scripts/compile_juliet.py`](file:///home/dharshan/Documents/R&D/scripts/compile_juliet.py)
* **Purpose:** Multi-threaded compiler for NIST/NSA Juliet Test Suite v1.3.
* **Features:**
  - Compiles test cases into individual stripped x86-64 ELF binaries.
  - Compiles both **bad** (`-DOMITGOOD`, vulnerable) and **good** (`-DOMITBAD`, patched) variants.
  - Automatically filters platform-incompatible Windows files (`*w32*.c`).
  - Automatically groups multi-file testcases (`22a.c` + `22b.c`, `51a.c`..`54e.c`) so helpers compile alongside entry points.
  - Strips all debug symbols with `strip --strip-all` to replicate real stripped firmware.

#### 📄 [`scripts/parse_ground_truth.py`](file:///home/dharshan/Documents/R&D/scripts/parse_ground_truth.py)
* **Purpose:** Parses Juliet's 15.7 MB `manifest.xml`, extracts exact flaw line numbers, correlates them with compiled ELF paths, and outputs `data/juliet/ground_truth.json`.

---

### 3.8 Pipeline Runner & CLI (`pipeline.py`)

#### 📄 [`pipeline.py`](file:///home/dharshan/Documents/R&D/pipeline.py)
* **Purpose:** Central command-line entry point for the entire project.
* **Supported Modes:**
  - `--mode latte`: Runs pure LATTE baseline (no retrieval).
  - `--mode firmgraph`: Runs full FirmGraph-LLM pipeline (with GraphRAG & KG ingestion).
  - `--mode experiment`: Runs both systems comparatively and outputs evaluation metrics.

---

### 3.9 Data Storage & Benchmark Datasets (`data/`)

* 📁 [`data/juliet/compiled/`](file:///home/dharshan/Documents/R&D/data/juliet/compiled/): 6,232 stripped x86-64 ELF executables (202 MB) categorized into `CWE-78/`, `CWE-134/`, `CWE-190/`, and `CWE-606/`.
* 📄 [`data/juliet/ground_truth.json`](file:///home/dharshan/Documents/R&D/data/juliet/ground_truth.json): Parsed ground truth mapping 2,199 testcases directly to compiled binaries and flaw line numbers.
* 📄 [`data/juliet/compile_manifest.json`](file:///home/dharshan/Documents/R&D/data/juliet/compile_manifest.json): Full build manifest logging compilation success/failure per file.
* 📄 [`data/juliet/sink_source_cache.json`](file:///home/dharshan/Documents/R&D/data/juliet/sink_source_cache.json): Disk cache of LLM-classified API sinks and sources.
* 📄 [`data/flows/sample_cwe78_flow.json`](file:///home/dharshan/Documents/R&D/data/flows/sample_cwe78_flow.json): Sample DangerousFlow input holding decompiled C socket-to-exec logic.

---

### 3.10 Generated Reports (`reports/`)

* 📄 [`reports/latte_baseline/CWE78_OS_Command_Injection__char_connect_socket_execl_01_ranked.json`](file:///home/dharshan/Documents/R&D/reports/latte_baseline/CWE78_OS_Command_Injection__char_connect_socket_execl_01_ranked.json): Validated baseline report generated by Qwen2.5-Coder 7B demonstrating successful vulnerability detection with 100% confidence.

---

## 4. How to View and Inspect Every Artifact

### Quick Terminal Inspection Commands

```bash
# 1. Check compiled binary counts per vulnerability type
echo "=== Juliet Compiled Binaries ==="
ls data/juliet/compiled/CWE-78/bad/  | wc -l   # 760
ls data/juliet/compiled/CWE-134/bad/ | wc -l   # 1710
ls data/juliet/compiled/CWE-190/bad/ | wc -l   # 3420
ls data/juliet/compiled/CWE-606/bad/ | wc -l   # 342

# 2. Verify binary format is stripped x86-64 ELF
file data/juliet/compiled/CWE-78/bad/$(ls data/juliet/compiled/CWE-78/bad | head -1)

# 3. View ground truth summary
python3 -c "
import json
gt = json.load(open('data/juliet/ground_truth.json'))
print('Total entries in GT:', gt['summary']['total_entries'])
print('Entries with binary:', gt['summary']['total_with_binary'])
"

# 4. View Ollama service and active model
ollama list

# 5. View verified baseline report
cat reports/latte_baseline/CWE78_OS_Command_Injection__char_connect_socket_execl_01_ranked.json
```

---

## 5. Step-by-Step Live Demonstration Script

Follow this sequence during your presentation:

1. **Demonstrate AI Backend:**
   Run `ollama list` and explain that local, private LLM execution is active on CPU.
2. **Demonstrate Benchmark Suite:**
   Run `python3 scripts/parse_ground_truth.py` to show live synchronization between the 6,232 binaries and `manifest.xml`.
3. **Execute Live Pipeline Analysis:**
   ```bash
   python3 pipeline.py \
     --mode latte \
     --flows data/flows/sample_cwe78_flow.json \
     --binary CWE78_OS_Command_Injection__char_connect_socket_execl_01 \
     --model qwen2.5-coder:7b
   ```
4. **Display Verified Report:**
   Show the output JSON displaying `vulnerable: true`, `cwe: CWE-78`, `confidence: 1.0`, and the step-by-step taint trace `dataBuffer -> data -> execl param[2]`.
5. **Codebase Architecture Tour:**
   Show [`llm/prompts/templates.py`](file:///home/dharshan/Documents/R&D/llm/prompts/templates.py) (LATTE prompts), [`knowledge_graph/construction/graph_builder.py`](file:///home/dharshan/Documents/R&D/knowledge_graph/construction/graph_builder.py) (Neo4j ingestion), and [`retrieval/retrieval.py`](file:///home/dharshan/Documents/R&D/retrieval/retrieval.py) (GraphRAG retriever).

---

## 6. Presentation Talking Points & Defense Pitch

### The Core Problem
Embedded IoT firmware binaries are stripped of symbols and source code. Traditional static taint analysis tools generate excessive false positives due to unresolved pointer aliasing and complex string formatting.

### The Base Paper (LATTE, ACM TOSEM 2025)
LATTE showed that Large Language Models can perform conversational static taint analysis over decompiled call chains ("Dangerous Flows"), drastically outperforming rigid symbolic execution.

### The Fundamental Gap in LATTE
LATTE analyzes each binary in total isolation. Once an analysis finishes, **all learned vulnerability knowledge is discarded**. When analyzing related firmware binaries sharing 70-80% common code, LATTE starts from scratch with zero memory.

### Our Contribution: FirmGraph-LLM
We solve this gap by adding:
1. **A Persistent Knowledge Graph (Neo4j)** that accumulates discovered vulnerability patterns, function similarities, and API behaviors.
2. **GraphRAG Retrieval** that retrieves cross-firmware historical evidence to ground the LLM before it analyzes new code.
3. **Multi-Factor Triage Ranking** combining LLM confidence with empirical graph evidence.
