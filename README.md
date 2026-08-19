# FirmGraph-LLM

**FirmGraph-LLM: A Knowledge Graph-Guided LLM Framework for Cross-Firmware Vulnerability Discovery and Explainable Security Analysis**

> **Author:** Dharshan P (23ISR012)  
> **Base Paper:** LLM-Powered Static Binary Taint Analysis (LATTE) — Liu et al., ACM TOSEM 2025  

---

## 📌 Project Overview

FirmGraph-LLM addresses the statefulness gap in automated binary taint analysis. While existing LLM-assisted approaches (e.g., LATTE) analyze each binary in isolation, FirmGraph-LLM builds a persistent **Knowledge Graph (KG)** of cross-firmware security concepts (functions, APIs, CFGs, vulnerability patterns, and CWE/CVE taxonomies). 

Using **GraphRAG** (retrieval-augmented generation combining graph traversal and code vector embeddings), FirmGraph-LLM grounds LLM vulnerability reasoning with historical evidence, improving detection precision, ranking accuracy, and report explainability across firmware images.

---

## 📁 Repository Structure

```text
FirmGraph-LLM/
│
├── data/                      # Data storage (raw, processed, firmware, Juliet references)
├── Dataset/                   # Preserved original Juliet dataset
├── Docs/                      # Preserved research documentation and papers
├── firmware/                  # Firmware extraction, identification, preprocessing modules
├── reverse_engineering/       # Ghidra scripts, CFG, call graph & function analysis
├── knowledge_graph/           # Neo4j schema, graph construction, ingestion & queries
├── embeddings/                # Function embedding pipeline & vector search
├── retrieval/                 # Vector, Graph, and GraphRAG retrieval engines
├── llm/                       # Prompt templates, multi-turn reasoning & vulnerability ranking
├── analysis/                  # Vulnerability analysis, evidence mapping & explainability
├── evaluation/                # Baselines (LATTE reproduction), metrics & experiment suite
├── reports/                   # Generated evaluation & analysis reports
├── scripts/                   # Utility & automation scripts
├── tests/                     # Test suite
├── docs/                      # Technical documentation
├── requirements.txt           # Python dependency definitions
├── README.md                  # Project overview & instructions
└── .gitignore                 # Git ignore configuration
```

---

## 🚦 Project Status

- **Current Phase:** Step 1 — Project Structure & Environment Setup (Complete)
- **Next Phase:** Step 2 — Ghidra Headless Setup & Juliet Compilation
