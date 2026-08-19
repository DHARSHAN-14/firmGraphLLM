# FirmGraph-LLM: Research Understanding Report

> **Author:** Dharshan P (23ISR012)
> **Base Paper:** LLM-Powered Static Binary Taint Analysis (LATTE) — Liu et al., ACM TOSEM 2025
> **Proposed Research:** FirmGraph-LLM — A Knowledge Graph-Guided LLM Framework for Cross-Firmware Vulnerability Discovery
> **Date:** 2026-08-17
> **Status:** Research Understanding Phase — NO IMPLEMENTATION

---

## 1. BASE PAPER UNDERSTANDING

### 1.1 Research Problem

LATTE addresses the problem of **automating static binary taint analysis** for vulnerability detection in released binaries (especially IoT firmware). Traditional taint analysis requires extensive manual effort to define:

1. **Taint source identification rules** — which functions receive external input (e.g., `recv`, `fgets`, `fscanf`, third-party functions like `SSL_read`)
2. **Taint propagation/sanitization rules** — how taint labels flow through assignments, calculations, function calls, and when sanitization removes taint
3. **Sink inspection rules** — which functions are security-sensitive (e.g., `system`, `strcpy`, `printf`) and how to check if tainted data reaching them constitutes a vulnerability

These rules must be manually crafted by human experts for each vulnerability type and each binary's linked libraries, making existing tools (Emtaint, Arbiter, Karonte, DTaint, Saluki, SAC, FBI) limited in both coverage and scalability.

### 1.2 Motivation

- Binary analysis lacks source code information (no variable names, no comments, no type definitions)
- Each prior tool supports only a **subset** of taint-style vulnerability types (see Table 1 in paper)
- Rule-based systems are **error-prone** and introduce FPs/FNs due to rule errors and absences
- Extending rules to new binaries or vulnerability types demands **significant human effort**
- LLMs have demonstrated strong code understanding capabilities (code generation, summarization) — the insight is to use LLMs to **replace manual rule definition** with semantic understanding

### 1.3 Existing Limitations (of prior work, NOT of LATTE)

| Tool | Limitation |
|------|-----------|
| Emtaint | Supports CWE-78, CWE-120, CWE-134 only; manual rules |
| Arbiter | Requires symbol table for integer overflow detection; manual rule extension |
| Karonte | Multi-binary analysis but limited CWE coverage; symbolic execution overhead |
| DTaint | Only CWE-78, CWE-120 |
| Saluki | Only CWE-78 |
| SAC/FBI | Optimized Karonte rules, still manually defined |

### 1.4 Input to LATTE

- A **stripped binary** (no debug info, no symbol tables) — compiled from C/C++ code
- The binary is loaded into **Ghidra** for reverse engineering
- Extracted: decompiled pseudocode, call graph, control flow graph, import table, function metadata

### 1.5 Binary Analysis Pipeline (LATTE Workflow)

LATTE has **three main modules**:

#### Module 1: Preprocessing
- Binary → Ghidra → Disassembly + Decompilation
- Extract: function list, external functions (from import table), call graph, CFG

#### Module 2: Code Slicing & Prompt Construction (Core)
This module has three phases:

**Phase 1 — Function Call Chain (CC) Extraction:**
1. Extract all external functions from binary (`F_external`)
2. Use LLM to identify **sinks** from external functions (with one-shot prompt, persona assignment)
3. For each sink, find all **call sites** = Vulnerable Destinations (VDs)
4. Backward data-dependency slicing (intraprocedural + interprocedural) from each VD
5. Build function Call Chains (CCs): `[f1, f2, ..., fn]` where `fn` contains VD

**Phase 2 — Dangerous Flow (DF) Generation:**
1. Use LLM to identify **sources** from external functions
2. Match sources within CCs — if a source caller exists in a CC and has data dependency with VD, create Candidate DF (CDF)
3. Deduplicate: keep longest CDF per CC, remove subchains
4. Result: set of DFs (slices connecting external input to potential vulnerability)

**Phase 3 — Prompt Sequence (PS) Construction:**
1. Three **Prompt Templates (PTs)**: Start, Middle, End
2. **Start template**: persona assignment (program analyst), specify taint source + parameter, append first function body, instruct data dependency/alias/taint analysis
3. **Middle template**: continue analysis from previous function, append next function body, handle intermediate sources
4. **End template**: instruct final vulnerability inspection, classify by CWE, provide patch suggestions

#### Module 3: LLM Conversation
- Feed PS to GPT-4.0 in multi-turn conversation
- LLM performs step-by-step analysis per function unit
- Output: vulnerability classification (CWE type), location, explanation, patching suggestion

### 1.6 How Static Binary Taint Analysis Works in LATTE

LATTE does **NOT implement a traditional taint engine**. Instead:
- Traditional taint analysis components (source ID, propagation, sanitization, sink inspection) are **replaced by LLM reasoning**
- Static program analysis is used ONLY for: call graph construction, data dependency slicing, function CC extraction
- The LLM handles the semantic understanding parts that traditionally require manual rules

### 1.7 How the LLM is Used

The LLM (GPT-4.0) is used for four distinct tasks:

1. **Sink identification**: Given an external function name, determine if it's a taint sink and which parameters trigger vulnerabilities
2. **Source identification**: Given an external function name, determine if it receives external input and which parameters store it
3. **Taint propagation analysis**: Analyze each function in a DF to trace how tainted data flows, including alias analysis
4. **Vulnerability inspection**: Final determination of whether a vulnerability exists, CWE classification, and explanation

### 1.8 Prompt / Reasoning Workflow

```
[Start Prompt]
→ Persona: "program analyst"
→ Task: "data dependency analysis, alias analysis, taint analysis"
→ Context: taint source function + parameter
→ Code: first function body in DF
→ LLM Response: taint propagation analysis for function 1

[Middle Prompt(s)] (repeated for each intermediate function)
→ Continue analysis from previous function
→ Code: next function body
→ If new source: mention it
→ LLM Response: continued taint tracking

[End Prompt]
→ Instruct vulnerability inspection
→ CWE classification
→ LLM Response: vulnerability verdict + explanation + patch suggestion
```

### 1.9 Taint Source and Sink Identification

- **Sources**: Functions that receive external/attacker-controllable data (e.g., `recv`, `fgets`, `fscanf`, `getenv`, `SSL_read`, `BIO_read`)
- **Sinks**: Functions where tainted data misuse leads to vulnerabilities (e.g., `system`, `execl`, `strcpy`, `printf`, `memcpy`)
- Both identified via LLM with one-shot prompt including standardized output format
- Results are **cacheable and reusable** across binaries using the same dynamic libraries
- 100% coverage on Juliet target scenarios; 82.1% average precision on broader identification

### 1.10 Taint Propagation Process

LATTE's taint propagation is a **hybrid**:
- **Static analysis**: data dependency slicing (backward, intraprocedural + interprocedural) to extract DFs
- **LLM reasoning**: semantic taint tracking within each function, including sanitization detection
- The static analysis part is flow-insensitive and path-insensitive
- Pointer alias analysis assisted by Ghidra's variable description definitions
- Context call depth limited to 50 to manage path explosion

### 1.11 Static Analysis Components

| Component | Tool/Method |
|-----------|-------------|
| Disassembly/Decompilation | Ghidra |
| Call Graph | Ghidra (function addresses + call/jump instructions) |
| Intraprocedural data dependency | Custom backward analysis on decompiled code |
| Interprocedural data dependency | Recursive caller analysis with context sensitivity |
| Pointer alias analysis | Variable description definitions + addressing methods |
| Code slicing | Custom DF extraction algorithm (Algorithm 1) |

### 1.12 Vulnerability Detection Process

1. Preprocess binary → Ghidra
2. Identify sinks → LLM
3. Find VDs (call sites of sinks) → Static analysis
4. Backward slice to build CCs → Static analysis
5. Identify sources → LLM
6. Match sources in CCs → build DFs → Static analysis
7. Construct PS for each DF → Prompt engineering
8. Multi-turn conversation with LLM → Vulnerability verdict
9. Output: CWE classification + explanation + patch suggestion

### 1.13 Output Produced by LATTE

For each analyzed DF:
- **Vulnerability verdict**: vulnerable or not vulnerable
- **CWE classification**: specific CWE type (e.g., CWE-78, CWE-120, CWE-134, CWE-190, CWE-606)
- **Taint propagation trace**: step-by-step description of how tainted data flows
- **Vulnerability explanation**: why the vulnerability exists
- **Patching suggestion**: how to fix the vulnerability
- Results saved as individual files for post-analysis review

### 1.14 Datasets Used by LATTE

| Dataset | Purpose | Details |
|---------|---------|---------|
| Juliet Test Suite v1.3 | Standard benchmark (RQ1–RQ4) | Compiled and stripped; test subjects with external data sources; CWE-78 (960/960), CWE-134 (1200/1200), CWE-190 (2860/2860), CWE-606 (240/240) |
| Karonte firmware dataset | Real-world evaluation (RQ5) | 49 firmware images from NETGEAR, D-Link, TP-Link, Tenda; no source code available |

### 1.15 Evaluation Methodology

Five Research Questions:
- **RQ1**: Vulnerability inspection effectiveness, stability, efficiency
- **RQ2**: Sink and source identification accuracy
- **RQ3**: DF extraction effectiveness
- **RQ4**: Impact of PS construction (ablation study)
- **RQ5**: Scalability to real-world firmware

Ablation on PS construction tested 5 variants:
1. Entire program as input
2. Entire DF as input
3. Only code lines related to data dependency
4. No persona assignment
5. No task splitting

### 1.16 Evaluation Metrics

| Metric | Formula |
|--------|---------|
| True Positive (TP) | Correctly identified vulnerability |
| False Negative (FN) | Missed vulnerability |
| True Negative (TN) | Correctly identified non-vulnerability |
| False Positive (FP) | Incorrectly flagged vulnerability |
| Accuracy | (TP + TN) / (TP + TN + FP + FN) |
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 Score | 2 × Precision × Recall / (Precision + Recall) |
| Stability | TP intersection across 5 test rounds |
| Time | Seconds per test subject |
| Cost | $ per DF analysis (~$0.35) |

### 1.17 Main Experimental Results

#### Juliet Results (Table 2):

| CWE | LATTE Accuracy | LATTE F1 | Emtaint Accuracy | Arbiter Accuracy |
|-----|---------------|----------|------------------|-----------------|
| CWE-78 | **96.46%** | **96.33%** | 92.7% | 43.64% |
| CWE-134 | **93.88%** | **93.99%** | 93.63% | 49.83% |
| CWE-190 | **62.1%** | **62.05%** | N/A | 44.32% |
| CWE-606 | **73.33%** | **74.24%** | N/A | N/A |

#### Karonte Firmware Results (Table 6):

| Metric | Karonte | Emtaint | Arbiter | LATTE |
|--------|---------|---------|---------|-------|
| TP | 46 | 65 | 151 | **222** |
| FP | 28 | 1,518 | 149 | **33** |
| Precision | 62.2% | 4.1% | 48.7% | **87.1%** |
| Unique bugs | 37 | 98 | 52 | **119** |
| New bugs | — | — | — | **37** (10 CVEs) |

#### Key findings:
- Average accuracy on Juliet: 77% (LATTE) vs 43.5% (Arbiter on supported types)
- 5-round TP intersection recall: 79.85% (acceptable stability)
- GPT-4.0 outperforms GPT-3.5 by ~14% average accuracy
- Temperature 0.4–0.6 balances stability and effectiveness
- Average analysis time: ~15 seconds per Juliet test subject
- Cost: ~$0.35 per DF

### 1.18 Strengths

1. **Full automation**: No manual rule definition for taint analysis
2. **Broad vulnerability coverage**: Supports all 5 taint-style CWE types (more than any single prior tool)
3. **Low engineering cost**: Plug-and-play with different LLMs
4. **High precision on real firmware**: 87.1% precision vs. Karonte's 62.2%
5. **Novel PS construction**: Function-level slicing + step-by-step prompting significantly outperforms alternatives
6. **Reusable sink/source analysis**: Cache results across binaries with same libraries
7. **Real-world impact**: 37 new bugs, 10 CVEs
8. **Applicable to source code too**: Demonstrated with SVF-based DF extraction

### 1.19 Limitations

1. **Cannot handle non-taint-style vulnerabilities**: Logic bugs, race conditions, complex math vulnerabilities are out of scope
2. **Binary analysis limitations (Ghidra)**:
   - Pointer alias analysis inaccurate → missed CCs → missed DFs
   - Virtual call resolution difficulties (C++ polymorphism)
   - Function inlining complicates structure recovery
3. **LLM instability**: GPT-4.0 randomness causes fluctuating results (especially CWE-190)
4. **CWE-190 weakness**: Without symbol table info, LLM struggles with data type judgments for integer overflow
5. **Cannot analyze obfuscated/encrypted binaries** without prior deobfuscation
6. **Cost**: Requires LLM API token expenditure
7. **Source/sink identification FPs**: LLM hallucination (e.g., misclassifying `recv` as a sink)
8. **Custom functions**: LLM cannot identify custom taint sources/sinks in unfamiliar code
9. **Single-binary analysis**: Each binary analyzed independently — **no cross-firmware knowledge reuse**
10. **No persistent memory**: Analysis results not structured or queryable for future use

### 1.20 Exact Assumptions Made by LATTE

1. Binaries are **not obfuscated or encrypted**
2. Source and sink functions are primarily from **dynamically linked libraries** (e.g., glibc)
3. Decompilation by Ghidra produces **reasonably accurate** pseudocode
4. Context call depth of **50** is sufficient for most real-world programs
5. LLM (GPT-4.0) has **sufficient code understanding** for taint-style analysis
6. **Function-level granularity** is appropriate for code slicing
7. Taint-style vulnerabilities are the **primary target** (data-flow sensitive, caused by external inputs)
8. Source/sink identification results can be **reused** across binaries with same libraries

### 1.21 What LATTE Does NOT Solve

- ❌ Cross-firmware knowledge accumulation or transfer
- ❌ Persistent vulnerability knowledge storage
- ❌ Structured reasoning with graph-based evidence
- ❌ Explainable analysis with evidence trails
- ❌ Knowledge reuse between different firmware analyses
- ❌ Vulnerability pattern similarity matching across firmware
- ❌ Non-taint-style vulnerability detection
- ❌ Logic vulnerabilities, race conditions, crypto issues
- ❌ C++ virtual call resolution
- ❌ Obfuscated/encrypted binary analysis
- ❌ Reducing LLM hallucination through grounding
- ❌ Cross-architecture firmware comparison

---

## 2. LATTE PIPELINE (Summary Diagram)

```
Binary (stripped)
    │
    ▼
[Ghidra Preprocessing]
    │ → Decompiled code, Call graph, CFG, Import table
    ▼
[Sink Identification — LLM]
    │ → Set of (sink, parameter) pairs
    ▼
[VD Identification — Static Analysis]
    │ → Call sites of sinks: (location, sink, argument)
    ▼
[Backward Data-Dependency Slicing — Static Analysis]
    │ → Function Call Chains (CCs)
    ▼
[Source Identification — LLM]
    │ → Set of (source, parameter) pairs
    ▼
[DF Generation — Static Analysis]
    │ → Match sources in CCs, deduplicate
    │ → Dangerous Flows (DFs)
    ▼
[PS Construction — Prompt Engineering]
    │ → Start + Middle + End templates per DF
    ▼
[LLM Conversation — GPT-4.0]
    │ → Multi-turn vulnerability inspection
    ▼
[Output]
    → Vulnerability verdict
    → CWE classification
    → Taint trace
    → Explanation + Patch suggestion
```

---

## 3. LATTE LIMITATIONS (as Relevant to FirmGraph-LLM)

> [!IMPORTANT]
> These are the specific gaps that FirmGraph-LLM aims to address:

| # | LATTE Limitation | FirmGraph-LLM Opportunity |
|---|-----------------|--------------------------|
| 1 | Each binary analyzed independently | **Cross-firmware knowledge accumulation** |
| 2 | No persistent knowledge storage | **Knowledge Graph for reusable vulnerability knowledge** |
| 3 | No structured evidence for findings | **Graph-based evidence trails** |
| 4 | LLM hallucination ungrounded | **GraphRAG grounding with structured knowledge** |
| 5 | No similarity search across firmware | **Embedding-based function similarity** |
| 6 | Sink/source reuse is only per-library | **Cross-firmware function-level knowledge reuse** |
| 7 | No vulnerability pattern database | **KG stores patterns, CWE mappings, exploit primitives** |
| 8 | No explainability beyond LLM text | **Graph-backed reasoning paths** |
| 9 | No progressive learning | **KG grows with each analysis** |
| 10 | No analyst triage support | **Ranked, evidence-grounded vulnerability reports** |

---

## 4. JULIET DATASET UNDERSTANDING

### 4.1 Dataset Structure

```
Juliet_Test_Suite_v1.3_for_C_Cpp/
└── C/
    ├── testcases/           # 118 CWE directories
    │   ├── CWE78_OS_Command_Injection/
    │   │   ├── s01/         # Subdivisions by variant
    │   │   ├── s02/
    │   │   └── ...
    │   ├── CWE121_Stack_Based_Buffer_Overflow/
    │   ├── CWE134_Uncontrolled_Format_String/
    │   ├── CWE190_Integer_Overflow/
    │   ├── CWE606_Unchecked_Loop_Condition/
    │   └── ... (118 total CWE categories)
    ├── testcasesupport/     # Shared support code
    │   ├── std_testcase.h   # Standard test case header
    │   ├── io.c             # I/O utilities
    │   ├── main.cpp         # Combined main for all tests
    │   └── ...
    ├── manifest.xml         # Ground truth: flaw locations
    ├── Makefile
    └── doc/                 # User guide + changelog
```

### 4.2 Vulnerability Categories

**118 CWE categories** covering a broad range of software weaknesses:
- Buffer overflows (CWE-121, CWE-122, CWE-124, CWE-126, CWE-127, CWE-785)
- Injection (CWE-78 OS Command, CWE-90 LDAP)
- Format string (CWE-134)
- Integer issues (CWE-190, CWE-191, CWE-194–197, CWE-680, CWE-681)
- Memory management (CWE-401, CWE-415, CWE-416, CWE-590, CWE-761, CWE-762, CWE-789)
- NULL pointer (CWE-476, CWE-690)
- Race conditions (CWE-364, CWE-366, CWE-367)
- Crypto weaknesses (CWE-325, CWE-327, CWE-328, CWE-338, CWE-780)
- Information exposure (CWE-526, CWE-534, CWE-535)
- Path traversal (CWE-23, CWE-36)
- Code quality (CWE-398, CWE-561, CWE-563, CWE-570, CWE-571)
- And many more

### 4.3 CWE Organization

Each CWE directory has subdirectories (`s01/`, `s02/`, ...) grouping test cases by **flow variant** — different data flow patterns and control structures (if/else, loops, function pointers, threading, etc.).

### 4.4 Good/Bad Test Cases

Each test file contains:
- **`bad()` function** (`#ifndef OMITBAD`): Contains the vulnerability — tainted data reaches a sink without proper sanitization
- **`good()` function** (`#ifndef OMITGOOD`): Fixed version — uses safe data (e.g., fixed string) or proper validation
- **`main()`** (`#ifdef INCLUDEMAIN`): Calls both good and bad for standalone testing

Naming convention: `CWE{id}_{name}__{type}_{source}_{sink}_{variant}.c`
- Example: `CWE78_OS_Command_Injection__char_connect_socket_execl_01.c`
  - CWE-78, char type, source=connect_socket, sink=execl, variant=01 (baseline)

### 4.5 Source-Code Structure

Each test case file:
1. Header comments specifying CWE, source, sink, and flow variant
2. Platform-specific includes and definitions (Windows vs Linux)
3. `bad()` function: introduces vulnerability via external input to dangerous sink
4. `good()` function: demonstrates safe usage (good-source to bad-sink, or bad-source to good-sink)
5. `main()` for standalone compilation

Flow variants encode different program structures:
- `01`: Baseline (straightforward)
- `02`–`18`: Different control flow patterns (if/else, switch, loops)
- `21`–`45`: Inter-procedural variants (function calls, pointers, structs)
- Higher numbers: More complex data flow patterns

### 4.6 How Ground Truth is Represented

1. **manifest.xml**: Machine-readable ground truth
   - `<flaw line="N" name="CWE-XXX: ..."/>` — exact line number of vulnerability
   - One entry per testcase file
2. **Function naming convention**: `*_bad()` = contains vulnerability, `*_good()` = does not
3. **Code comments**: `/* POTENTIAL FLAW */` and `/* FIX */` markers in source code
4. **OMITBAD / OMITGOOD macros**: Compile-time selection of vulnerable or safe version

### 4.7 How It Can Be Used for Controlled Vulnerability Evaluation

- Compile test cases to **stripped binaries** (remove symbols, debug info)
- Run analysis tool on binaries
- Compare tool's output against `manifest.xml` ground truth
- Measure TP/FN/TN/FP/Accuracy/Precision/Recall/F1
- LATTE did exactly this for CWE-78, CWE-134, CWE-190, CWE-606

### 4.8 What Juliet CAN Validate

- ✅ Binary vulnerability detection accuracy per CWE type
- ✅ Source and sink identification correctness
- ✅ Taint propagation / data flow extraction effectiveness
- ✅ LLM reasoning quality on controlled examples
- ✅ False positive and false negative rates
- ✅ CWE classification accuracy
- ✅ Comparison between analysis approaches (ablation studies)
- ✅ Stability across multiple runs (due to LLM randomness)

### 4.9 What Juliet CANNOT Validate

- ❌ **Real-world firmware complexity**: Juliet is synthetic, not real firmware
- ❌ **Cross-firmware knowledge transfer**: Each test case is independent
- ❌ **Multi-binary interactions**: Juliet is single-file programs
- ❌ **Architecture-specific issues**: Not built for ARM/MIPS firmware
- ❌ **Library diversity**: Uses standard C/C++ libraries only
- ❌ **Knowledge graph utility**: No inter-test-case relationships to exploit
- ❌ **Scale**: Individual programs are small (~200 lines each)
- ❌ **Zero-day detection**: All vulnerabilities are pre-labeled
- ❌ **Analyst triage time**: No manual analysis workflow to measure
- ❌ **Firmware extraction**: No filesystem unpacking needed

### 4.10 Role of Juliet in FirmGraph-LLM Research

| Use Case | How |
|----------|-----|
| **Validation data** | Verify that our pipeline correctly detects known vulnerabilities (regression test against LATTE results) |
| **Vulnerability classification benchmark** | Test CWE classification accuracy of LLM+KG reasoning |
| **Controlled ground-truth evaluation** | Measure Precision/Recall/F1 with exact ground truth |
| **LLM reasoning evaluation** | Compare quality of LLM reasoning with and without KG evidence |
| **KG/CWE relationship validation** | Build initial CWE → vulnerability pattern mappings and validate them |
| **Baseline comparison** | Reproduce LATTE's reported results as Baseline 2 |

### 4.11 Additional Data Eventually Required

> [!WARNING]
> Juliet alone is **insufficient** for evaluating the core FirmGraph-LLM hypothesis (cross-firmware knowledge reuse). Real firmware data will be needed.

| Data Type | Source | Purpose |
|-----------|--------|---------|
| Real firmware images | OpenWrt, vendor dumps, FirmAE/Firmadyne, Karonte dataset | Cross-firmware analysis evaluation |
| CVE/CWE metadata | NVD, MITRE | Knowledge graph population, ground truth |
| Binary artifacts | Ghidra-extracted functions, CFGs, APIs | KG node construction |
| Function embeddings | CodeBERT/UniXcoder on decompiled code | Similarity search |

---

## 5. RESEARCH PROBLEM

### The Actual Research Gap

Current LLM-based binary analysis (exemplified by LATTE) performs **isolated analysis** — each binary is analyzed from scratch without leveraging knowledge gained from prior analyses. This is like a security analyst who forgets everything after each engagement.

The gap is **NOT** simply "LATTE doesn't use a Knowledge Graph." The gap is:

> **There is no mechanism to persistently accumulate, structure, and reuse security knowledge across firmware analyses, and no evidence on whether such accumulated knowledge actually improves vulnerability discovery, ranking, or explainability.**

Key aspects of the gap:

1. **Knowledge waste**: LATTE identifies sink/source pairs, taint flows, vulnerability patterns — all discarded after each analysis
2. **No structural relationships**: Vulnerability patterns in different firmware may share common API sequences, library usages, or code structures — these relationships are invisible in isolated analysis
3. **Ungrounded LLM reasoning**: LLM can hallucinate because it has no structured evidence to anchor its claims
4. **No progressive improvement**: Analysis quality does not improve as more firmware is analyzed
5. **No cross-firmware insight**: A vulnerability found in Firmware A's `httpd` binary cannot inform analysis of a similar `httpd` in Firmware B

---

## 6. PROPOSED RESEARCH IDEA

### FirmGraph-LLM: Core Concept

Build a system where firmware analysis **accumulates structured knowledge** in a Knowledge Graph, and this knowledge is used via **GraphRAG** to improve LLM-based vulnerability reasoning on new firmware.

```
═══════════════════════════════════════════════════════
  ANALYSIS SESSION 1: Firmware A
═══════════════════════════════════════════════════════
  Firmware A → Extract → Reverse Engineer → Analyze
      ↓
  Knowledge extracted:
    • Functions with vulnerability patterns
    • API call sequences
    • CWE mappings
    • Taint source→sink flows
      ↓
  ┌─────────────────────────┐
  │   Knowledge Graph (KG)  │ ← POPULATED
  └─────────────────────────┘

═══════════════════════════════════════════════════════
  ANALYSIS SESSION 2: Firmware B
═══════════════════════════════════════════════════════
  Firmware B → Extract → Reverse Engineer
      ↓
  Query KG: "Find similar functions/patterns to Firmware B"
      ↓
  Retrieved: related vulnerability patterns from Firmware A
      ↓
  LLM Reasoning (grounded by KG evidence)
      ↓
  Ranked vulnerability report with evidence trails

═══════════════════════════════════════════════════════
  ANALYSIS SESSION N: Firmware N
═══════════════════════════════════════════════════════
  Firmware N → Query KG (knowledge from A + B + ... + N-1)
      ↓
  Richer evidence → Better ranking → Less analyst effort
```

The system should **progressively accumulate security knowledge** with each analysis.

---

## 7. FULL PROPOSED PIPELINE

```
┌─────────────────────────────────────────────────────┐
│                  FIRMWARE IMAGE                      │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│          FIRMWARE EXTRACTION                         │
│  → File system, binaries, libraries, configs         │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│       REVERSE ENGINEERING (Ghidra)                   │
│  → Functions, CFG, Call Graph, APIs, Strings          │
│  → Decompiled pseudocode                             │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│      FEATURE / EMBEDDING EXTRACTION                  │
│  → Code embeddings per function (model TBD)          │
│  → Structural features (API sequences, CFG metrics)  │
└──────────┬───────────────────────────┬──────────────┘
           ▼                           ▼
┌──────────────────┐    ┌──────────────────────────────┐
│ KNOWLEDGE GRAPH  │    │  VECTOR / SIMILARITY INDEX   │
│    (Neo4j)       │    │    (tool TBD)                │
│                  │    │                              │
│ Firmware nodes   │    │ Function embeddings          │
│ Binary nodes     │    │ Structural fingerprints      │
│ Function nodes   │    │                              │
│ API nodes        │    │                              │
│ CWE/CVE nodes    │    │                              │
│ Pattern nodes    │    │                              │
│ + relationships  │    │                              │
└────────┬─────────┘    └────────────┬─────────────────┘
         │                           │
         └────────────┬──────────────┘
                      ▼
┌─────────────────────────────────────────────────────┐
│            GraphRAG RETRIEVAL                        │
│  → Query: new function/binary to analyze             │
│  → Graph traversal: find related entities            │
│  → Vector similarity: find similar functions         │
│  → Combine: structural + semantic relevance          │
│  → Output: ranked evidence set                       │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│            LLM REASONING                             │
│  → Input: decompiled code + retrieved KG evidence    │
│  → Task: vulnerability assessment grounded by        │
│    known patterns, CWE relationships, prior findings │
│  → Output: vulnerability classification + confidence │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│         VULNERABILITY RANKING                        │
│  → Score functions by: LLM confidence × KG evidence  │
│  → Rank by likelihood and severity                   │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│     EXPLAINABLE SECURITY REPORT                      │
│  → Ranked vulnerable functions                       │
│  → CWE classification                                │
│  → Evidence from KG (similar past vulnerabilities)   │
│  → Reasoning trace                                   │
│  → Confidence score                                  │
│  → Patching suggestion                               │
└─────────────────────────────────────────────────────┘
```

---

## 8. KNOWLEDGE GRAPH CONCEPT

### Proposed Entity Types (Conceptual — NOT finalized)

| Entity Type | Description | Example |
|-------------|-------------|---------|
| Firmware | A firmware image | (e.g., a specific vendor firmware build) |
| Binary | An executable within firmware | `httpd`, `uhttpd`, `libcurl.so` |
| Function | A function within a binary | `sub_400A10`, `handle_request` |
| API | External/library function call | `recv`, `system`, `strcpy` |
| Library | Linked library | `glibc`, `openssl` (per LATTE paper) |
| CWE | Weakness category | `CWE-78`, `CWE-120` |
| CVE | Specific vulnerability | `CVE-2023-12345` |
| VulnPattern | Abstracted vulnerability pattern | `recv→sprintf→system` |
| ExploitPrimitive | Exploitation technique | `stack_buffer_overflow`, `command_injection` |
| String | Interesting string in binary | `/bin/sh`, `%s`, format strings |

### Proposed Relationship Types (Conceptual — NOT finalized)

| Relationship | From → To | Meaning |
|-------------|-----------|---------|
| CONTAINS | Firmware → Binary | Firmware contains this binary |
| HAS_FUNCTION | Binary → Function | Binary contains this function |
| CALLS | Function → Function | Function A calls Function B |
| IMPORTS | Binary → API | Binary uses this API |
| USES | Function → API | Function calls this API |
| SIMILAR_TO | Function → Function | Functions have similar structure/embeddings |
| ASSOCIATED_WITH | Function → CWE | Function is associated with this weakness type |
| VULNERABLE_TO | Function → VulnPattern | Function matches this vulnerability pattern |
| MAPS_TO_CWE | VulnPattern → CWE | Pattern corresponds to this CWE |
| HAS_CVE | Binary → CVE | Binary has this known CVE |
| LINKS_TO | Library → API | Library provides this API |
| REFERENCES | Function → String | Function references this string |

### Schema Principles

> [!NOTE]
> The schema is **NOT finalized**. It should be refined iteratively based on what relationships actually prove useful for retrieval and reasoning.

1. Start minimal — add entities/relationships only when they provide measurable retrieval value
2. CWE hierarchy should be modeled (Pillar → Class → Base → Variant)
3. Similarity relationships should have numeric weights (cosine similarity, structural similarity)
4. Temporal metadata: when was knowledge added, from which analysis session

---

## 9. GRAPH RAG ROLE

### Why Ordinary Vector RAG May Not Be Sufficient

| Aspect | Vector RAG | GraphRAG |
|--------|-----------|----------|
| **Retrieval basis** | Semantic embedding similarity | Graph structure + embeddings |
| **Relationships** | Implicit (in embedding space) | Explicit (typed edges in graph) |
| **Multi-hop reasoning** | Not native | Natural (traverse edges) |
| **CWE hierarchy** | Flat similarity | Hierarchical traversal |
| **Cross-firmware links** | Not structured | Explicit Firmware→Binary→Function→API paths |
| **Evidence trails** | Retrieved chunks only | Graph paths showing reasoning connections |
| **Structural patterns** | Lost in embedding | Preserved in graph topology |

### How GraphRAG Would Work in FirmGraph-LLM

```
Query: "Analyze function sub_400A10 from firmware B's httpd binary"
    │
    ▼
Step 1: Vector similarity
    → Find top-K similar functions by embedding (code embedding model)
    → Retrieve: [func_X from firmware A, func_Y from firmware C, ...]

Step 2: Graph traversal
    → func_X →[VULNERABLE_TO]→ Pattern_P →[MAPS_TO_CWE]→ CWE-78
    → func_X →[USES]→ recv, system
    → func_X →[HAS_FUNCTION]← binary_A →[CONTAINS]← firmware_A
    → Sub-graph of related evidence

Step 3: Structural matching
    → sub_400A10 also USES recv, system
    → API overlap with known vulnerable function
    → Same library context

Step 4: Evidence compilation
    → "Function sub_400A10 is structurally similar to func_X (cosine=0.89)
       which was found vulnerable to CWE-78 in firmware_A's httpd.
       Both call recv() followed by system() without sanitization."

Step 5: LLM Reasoning (grounded)
    → Input: decompiled code + compiled evidence
    → Output: grounded vulnerability assessment
```

### What Should Be Experimentally Compared

> [!IMPORTANT]
> The value of GraphRAG over vector RAG is a **hypothesis, not a proven fact**. The experimental design must include this comparison.

1. **No retrieval** — LLM analyzes code alone (like LATTE)
2. **Vector RAG** — retrieve similar functions by embedding similarity, feed to LLM
3. **Graph retrieval** — traverse KG for related entities, feed to LLM
4. **GraphRAG (combined)** — vector similarity + graph traversal + structured evidence

---

## 10. CROSS-FIRMWARE REASONING

### The Fundamental Difference

**Single-Firmware Analysis (LATTE):**
```
Firmware A → Analyze → Report → DONE (knowledge discarded)
Firmware B → Analyze from scratch → Report → DONE
Firmware C → Analyze from scratch → Report → DONE
```

**Cross-Firmware Knowledge Reuse (FirmGraph-LLM):**
```
Firmware A → Analyze → Store knowledge in KG
Firmware B → Analyze + Query KG(A) → Better analysis → Update KG
Firmware C → Analyze + Query KG(A,B) → Even better analysis → Update KG
...
Firmware N → Analyze + Query KG(A,...,N-1) → Best analysis → Update KG
```

### What Cross-Firmware Reasoning Could Enable (Research Hypotheses)

1. **Pattern recognition**: "Firmware B's HTTP handler is structurally similar to Firmware A's vulnerable HTTP handler"
2. **Library vulnerability propagation**: "Firmware C uses the same libcurl version as Firmware A, which had CVE-XXXX"
3. **Vendor pattern detection**: "Multiple D-Link firmware share the same vulnerable CGI handler pattern"
4. **API sequence matching**: "This recv→sprintf→system sequence was vulnerable in 5 prior firmware"
5. **Prioritization**: "Analyze this function first because similar functions in 3 other firmware were vulnerable"

### What Cross-Firmware Reasoning CANNOT (yet) Claim

- ❌ Zero-day detection — unproven hypothesis
- ❌ Knowledge transfer — must be experimentally validated
- ❌ Guaranteed improved accuracy — could also introduce noise
- ❌ Complete vulnerability coverage — still limited by analysis technique

---

## 11. RESEARCH HYPOTHESES

### Primary Hypotheses

**H1 — Cross-firmware retrieval improves ranking:**
> Cross-firmware knowledge retrieval from a persistent Knowledge Graph improves vulnerable-function ranking accuracy compared with independent binary analysis (LATTE-style).

**H2 — Graph-based retrieval outperforms vector-only retrieval:**
> Graph-based retrieval (preserving structural relationships between functions, APIs, CWEs, and firmware) provides more relevant security evidence than vector-only similarity retrieval.

**H3 — Knowledge-grounded reasoning reduces hallucination:**
> LLM reasoning grounded by Knowledge Graph evidence produces fewer unsupported vulnerability claims (lower FP rate) than ungrounded LLM reasoning.

**H4 — Progressive knowledge accumulation improves performance:**
> The system's vulnerability detection performance improves as the Knowledge Graph grows with each additional firmware analysis (learning curve effect).

### Secondary Hypotheses

**H5 — Explainability:**
> Graph-backed evidence trails are judged more useful by security analysts than LLM-only textual explanations.

**H6 — Triage efficiency:**
> Analysts spend less time triaging vulnerability reports when KG evidence is provided.

**H7 — CWE classification accuracy:**
> CWE classification accuracy improves when CWE hierarchy and associated patterns from the KG are provided as context.

> [!CAUTION]
> All hypotheses are **testable claims, NOT proven facts**. The experimental design must be capable of **falsifying** each hypothesis.

---

## 12. BASELINES

| ID | Baseline | Description | What It Tests |
|----|----------|-------------|---------------|
| B1 | Traditional static analysis | Emtaint/Arbiter-style rule-based binary taint analysis | Lower bound (manual rules) |
| B2 | LATTE-style LLM analysis | LLM + code slicing + prompt sequences (no retrieval) | Direct comparison — isolates KG/RAG contribution |
| B3 | LLM + Vector RAG | LLM + function embedding similarity retrieval | Isolates graph structure contribution |
| **P** | **FirmGraph-LLM** | **LLM + Knowledge Graph + GraphRAG** | **Proposed system** |

### Ablation Studies

| Ablation | What It Tests |
|----------|---------------|
| P without graph traversal (vector only) | Value of graph structure |
| P without vector similarity (graph only) | Value of embeddings |
| P without CWE/CVE nodes | Value of vulnerability metadata |
| P without cross-firmware links | Value of cross-firmware knowledge |
| P with empty KG vs. populated KG | Value of accumulated knowledge |
| P with different LLMs | LLM dependence |

---

## 13. EVALUATION METRICS

### Vulnerability Detection Metrics (Quantitative)

| Metric | Formula | What It Measures |
|--------|---------|------------------|
| Precision | TP / (TP + FP) | How many flagged vulnerabilities are real |
| Recall | TP / (TP + FN) | How many real vulnerabilities are found |
| F1 Score | 2PR / (P+R) | Balanced detection performance |
| Accuracy | (TP+TN) / Total | Overall correctness |
| FP Rate | FP / (FP + TN) | False alarm rate |

### Ranking Metrics (Quantitative)

| Metric | What It Measures |
|--------|------------------|
| Top-K Recall | % of true vulnerabilities in top K ranked functions |
| MRR (Mean Reciprocal Rank) | Average 1/rank of first true vulnerability |
| NDCG | Quality of ranking considering position and relevance |
| MAP (Mean Average Precision) | Average precision across different recall levels |

### Retrieval Metrics (Quantitative)

| Metric | What It Measures |
|--------|------------------|
| Retrieval Precision@K | % of retrieved evidence items that are relevant |
| Retrieval Recall@K | % of relevant evidence items that are retrieved |
| Evidence relevance (human-judged) | Are retrieved KG patterns actually related? |

### Knowledge Accumulation Metrics (Quantitative)

| Metric | What It Measures |
|--------|------------------|
| Learning curve | Performance vs. number of firmware analyzed |
| KG growth rate | Entities + relationships added per firmware |
| Knowledge reuse rate | % of analyses where KG evidence was used |

### Explainability Metrics (Qualitative/Semi-quantitative)

| Metric | What It Measures |
|--------|------------------|
| Evidence trail completeness | Does the report trace back to KG evidence? |
| Analyst satisfaction | User study / survey (if feasible) |
| Explanation correctness | Are graph-based explanations factually correct? |

---

## 14. DATA REQUIREMENTS

### A. Controlled Vulnerability Benchmark

| Item | Source | Status |
|------|--------|--------|
| Juliet Test Suite v1.3 | Present in project | ✅ Available |
| Compiled stripped binaries | Compile from Juliet source | ⚠️ Needs compilation |
| Ground truth labels | manifest.xml | ✅ Available |

**Use:** Baseline comparison, CWE classification accuracy, regression testing

### B. Real Firmware Corpus

| Item | Source | Status |
|------|--------|--------|
| Karonte firmware dataset | From Karonte paper authors (used in LATTE evaluation) | ❌ Not yet available |
| Vendor firmware (NETGEAR, D-Link, TP-Link, Tenda) | Public repositories (same vendors as LATTE RQ5) | ❌ Not yet available |
| Additional real firmware | To be determined based on research needs | ❌ Not yet available |

**Use:** Cross-firmware evaluation, real-world scalability

### C. Vulnerability Knowledge

| Item | Source | Status |
|------|--------|--------|
| CVE database | NVD API | ❌ Not yet collected |
| CWE taxonomy | MITRE (XML/JSON) | ❌ Not yet collected |
| CWE hierarchy | MITRE | ❌ Not yet collected |
| Known firmware CVE mappings | NVD + vendor advisories | ❌ Not yet collected |

**Use:** KG population, ground truth for CVE/CWE relationships

### D. Reverse-Engineered Artifacts

| Item | Tool | Status |
|------|------|--------|
| Decompiled pseudocode | Ghidra | ❌ Requires Ghidra installation |
| Call graphs | Ghidra | ❌ Requires Ghidra installation |
| Control flow graphs | Ghidra | ❌ Requires Ghidra installation |
| Function boundaries | Ghidra | ❌ Requires Ghidra installation |
| Import tables (API lists) | Ghidra | ❌ Requires Ghidra installation |
| Strings | Ghidra / strings utility | ❌ Not yet extracted |

**Use:** KG node construction, embedding generation, function analysis

### How Datasets Connect

```
Juliet Source Code
    → Compile → Stripped Binaries
    → Ghidra → Decompiled Code + CFG + Call Graph
    → Feature Extraction → Embeddings + Structural Features
    → Knowledge Graph (initial population from Juliet)
    → Validate against manifest.xml ground truth

Real Firmware Images
    → Firmware extraction tool → File System + Binaries
    → Ghidra → Same as above
    → Embeddings → Vector index
    → Knowledge Graph (cross-firmware links)
    → CVE/CWE data → KG enrichment
    → GraphRAG → LLM → Vulnerability reports
```

---

## 15. IMPLEMENTATION MODULES

| Module | Description | Key Dependencies |
|--------|-------------|-----------------|
| **M1: Firmware Ingestion** | Accept firmware images, organize, track metadata | Python, filesystem |
| **M2: Firmware Extraction** | Unpack file systems, identify binaries | Firmware extraction tool (TBD) |
| **M3: Reverse Engineering** | Decompile, extract CFG/call graph/APIs/strings | Ghidra headless (used by LATTE) |
| **M4: Binary/Function Representation** | Extract function features, generate embeddings | Code embedding model (TBD) |
| **M5: Knowledge Extraction** | Identify sink/source/vulnerability indicators | LLM (TBD) |
| **M6: Knowledge Graph Construction** | Build and maintain graph schema | Graph database (Neo4j per user request) |
| **M7: Embedding Index** | Store and query function embeddings | Vector index (TBD) |
| **M8: GraphRAG Retrieval** | Graph traversal + vector similarity → evidence | Graph queries + vector search (TBD) |
| **M9: LLM Reasoning** | Vulnerability analysis grounded by KG evidence | LLM API (TBD) |
| **M10: Vulnerability Ranking** | Score and rank candidate vulnerable functions | Custom scoring logic |
| **M11: Evidence & Report Generation** | Produce explainable reports with graph evidence | Templating, visualization |
| **M12: Evaluation Framework** | Benchmark against baselines, measure metrics | Custom evaluation scripts |

---

## 16. FEASIBILITY ANALYSIS

### Technically Difficult Components

| Component | Difficulty | Reason |
|-----------|-----------|--------|
| Ghidra headless automation | **Medium** | Requires scripting Ghidra's Python API; well-documented but setup-heavy |
| Firmware extraction | **Low-Medium** | Mature open-source tools exist; specific tool TBD |
| Code embedding generation | **Medium** | Requires model selection and possibly GPU; pre-trained models available |
| Knowledge Graph | **Medium** | Schema design is iterative; graph database selection TBD |
| GraphRAG retrieval | **High** | No off-the-shelf firmware-specific GraphRAG; requires custom implementation |
| LLM prompt engineering for grounded reasoning | **Medium-High** | Designing prompts that properly use KG evidence is non-trivial |
| Cross-firmware similarity matching | **Medium** | Embedding quality depends on model choice and fine-tuning |
| Evaluation framework | **Medium** | Requires careful experiment design and reproducibility |

### Components That Can Be Simplified

| Component | Simplification |
|-----------|---------------|
| Firmware extraction | Start with Juliet (no extraction needed) before moving to real firmware |
| Embedding model | Use a pre-trained code embedding model without fine-tuning initially |
| KG schema | Start with minimal schema, add relationships as needed |
| LLM | Use free/low-cost LLM APIs or local open-source models |
| Vector index | Use an in-memory vector index instead of a full vector database |
| Visualization | Use graph database browser for KG visualization; skip custom dashboards |

### Existing Open-Source Tools Available

> [!NOTE]
> Specific tool selections have NOT been finalized. The following are categories of open-source tools that exist for each need. Final choices will be made during implementation planning.

| Need | Category | Notes |
|------|----------|-------|
| Firmware extraction | Firmware unpacking tools | Multiple mature options exist |
| Reverse engineering | Ghidra (free, used by LATTE) | Mature; confirmed baseline tool |
| Knowledge Graph | Graph databases | Multiple free options available |
| Code embeddings | Pre-trained code models | Multiple models on Hugging Face |
| Vector indexing | Vector search libraries | Multiple CPU/GPU options |
| LLM | Commercial APIs or local models | Depends on budget and GPU access |
| Graph queries | Graph query languages | Depends on graph database choice |

### GPU/API Access Requirements

| Component | Requirement | Alternative |
|-----------|-------------|-------------|
| Code embedding inference | GPU preferred (~4GB VRAM) | CPU possible but slow |
| LLM reasoning | API access (commercial LLM) | Local open-source models (~8GB+ VRAM) |
| Embedding generation (batch) | GPU recommended | CPU feasible for small datasets |
| Graph database | CPU + RAM (4GB+ recommended) | Runs fine on laptop |
| Vector index | CPU sufficient | GPU for large-scale indexing |

### Potential Bottlenecks

1. **Ghidra analysis time**: Real firmware binaries can take minutes to hours per binary
2. **LLM API costs**: At $0.35/DF (LATTE's figure), analyzing many DFs across many firmware adds up
3. **Knowledge Graph scalability**: Schema must be designed carefully to avoid query explosion
4. **Ground truth for real firmware**: No labeled dataset for cross-firmware vulnerability knowledge reuse
5. **Reproducibility**: LLM outputs are non-deterministic; results require multiple runs
6. **Firmware acquisition**: Some vendor firmware requires legal/ethical consideration

### Dataset Limitations

- Juliet is synthetic — does NOT represent real firmware complexity
- No existing labeled dataset for cross-firmware knowledge reuse evaluation
- Karonte dataset (used by LATTE) may be difficult to obtain
- CVE/CWE data quality varies; many CVEs lack detailed technical descriptions

### Evaluation Challenges

- **Cross-firmware baseline**: No prior system to directly compare against for KG-guided analysis
- **KG population chicken-and-egg**: Need to analyze firmware to populate KG, but need KG to test retrieval
- **Human evaluation**: Explainability metrics may require security expert judges
- **Incremental evaluation**: Testing progressive knowledge accumulation requires analyzing firmware in sequence

### Honest Assessment

> [!WARNING]
> **Over-engineering risk**: The full proposed pipeline (firmware extraction → reverse engineering → embeddings → knowledge graph → vector index → GraphRAG → LLM → ranking → evidence → report) has **12 modules** with complex interactions. A college research team should prioritize proving the **core hypothesis** (does KG-guided retrieval improve vulnerability analysis?) before building all components.

> [!TIP]
> **Recommended simplification**: Start with Juliet compiled binaries (skip firmware extraction), use Ghidra for reverse engineering, build a minimal KG, implement simple graph retrieval, and compare against LATTE-style baseline. This tests the core hypothesis with minimal infrastructure.

---

## 17. RISKS / OPEN QUESTIONS

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| KG evidence doesn't improve LLM reasoning | Core hypothesis fails | Start with ablation study; measure evidence relevance |
| LLM hallucination persists despite grounding | Reduced trustworthiness | Use structured prompts that force citation of KG evidence |
| Embedding quality insufficient for cross-firmware similarity | Poor retrieval | Evaluate multiple embedding models; consider fine-tuning |
| Neo4j performance degrades at scale | Slow retrieval | Optimize queries; limit graph depth; use indexing |
| Ghidra decompilation quality varies | Poor code representation | Use multiple architectures; handle Ghidra errors gracefully |

### Research Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Cannot reproduce LATTE baseline | No valid comparison | Carefully follow LATTE's methodology; use same dataset |
| Juliet insufficient for cross-firmware evaluation | Cannot test core hypothesis | Must eventually use real firmware |
| No ground truth for cross-firmware knowledge value | Cannot measure core contribution | Design proxy metrics; use synthetic cross-firmware scenarios |
| Scope too broad for college research | Incomplete implementation | Prioritize core hypothesis; simplify non-critical components |

### Open Questions

1. **What is the minimal effective KG schema?** — Start minimal and expand based on retrieval experiments
2. **How to handle KG noise?** — Incorrect entries (from LLM hallucination) could propagate errors
3. **What similarity threshold is meaningful?** — When are two functions "similar enough" to be useful?
4. **How to evaluate explainability without human experts?** — Proxy metrics needed
5. **Which LLM to use?** — Commercial APIs are expensive; can open-source local models achieve similar results?
6. **How to handle CWE overlap?** — Vulnerabilities can map to multiple CWEs
7. **What is the minimum firmware corpus size?** — How many firmware are needed to demonstrate progressive learning?
8. **How to initialize the KG?** — Cold-start problem: first firmware has no prior knowledge to leverage

---

## 18. RECOMMENDED IMPLEMENTATION ORDER

### Phase 1: Foundation (Weeks 1–3)

> [!IMPORTANT]
> Prove core feasibility before building the full pipeline.

| Step | Task | Justification |
|------|------|---------------|
| **1** | **Set up Ghidra headless + Python scripting** | Foundation for all binary analysis; test on Juliet binaries |
| **2** | **Compile Juliet test cases to stripped binaries** (CWE-78, CWE-134, CWE-190, CWE-606) | Create controlled evaluation dataset matching LATTE's setup |
| **3** | **Reproduce LATTE baseline** on Juliet (simplified: LLM + prompt sequences for a subset) | Establish Baseline B2; verify understanding of LATTE methodology |

### Phase 2: Core KG & Retrieval (Weeks 4–7)

| Step | Task | Justification |
|------|------|---------------|
| **4** | **Design minimal KG schema + set up Neo4j** | Start with: Function, API, CWE nodes and CALLS, USES, ASSOCIATED_WITH edges |
| **5** | **Implement function embedding pipeline** (code embedding model on decompiled code → vector index) | Enable similarity search |
| **6** | **Implement basic GraphRAG retrieval** | Combine graph traversal + embedding similarity |
| **7** | **Build LLM reasoning module with KG grounding** | Feed retrieved evidence to LLM alongside code |

### Phase 3: Evaluation (Weeks 8–10)

| Step | Task | Justification |
|------|------|---------------|
| **8** | **Run comparative evaluation on Juliet** (B2 vs. P, B3 vs. P) | Test H1, H2, H3 on controlled benchmark |
| **9** | **Implement progressive learning experiment** | Analyze Juliet CWEs sequentially, measure if KG improves later analyses |

### Phase 4: Real-World Extension (Weeks 11+)

| Step | Task | Justification |
|------|------|---------------|
| **10** | **Add firmware extraction** and test on real firmware | Test scalability and cross-firmware hypothesis |
| **11** | **Enrich KG with CVE/CWE metadata** from NVD/MITRE | Improve knowledge quality |
| **12** | **Full evaluation on real firmware** | Test H1–H4 on real-world data |

---

## WHAT WE SHOULD IMPLEMENT FIRST

> [!IMPORTANT]
> These are the first 5 concrete implementation steps. Do NOT implement them until explicitly instructed.

### Step 1: Ghidra Headless Binary Analysis Pipeline
- Install Ghidra and configure headless mode
- Write a Python/Java script to: load binary → extract decompiled code, function list, call graph, import table
- Test on a small set of Juliet compiled binaries
- **Why first**: Everything downstream depends on binary analysis output

### Step 2: Compile Juliet Evaluation Dataset
- Compile Juliet CWE-78, CWE-134, CWE-190, CWE-606 test cases to stripped x86-64 ELF binaries
- Organize as: `compiled/CWE-78/binary_01`, etc.
- Parse `manifest.xml` to create a clean ground-truth JSON
- **Why second**: Creates the controlled evaluation dataset for all experiments

### Step 3: LATTE Baseline Reproduction (Simplified)
- Implement DF extraction (sink/source identification + backward slicing) using Ghidra output
- Implement PS construction with the three prompt templates
- Run against LLM (to be selected) and record results
- Compare against LATTE's reported accuracy on Juliet
- **Why third**: Establishes Baseline B2 and validates our understanding of the paper

### Step 4: Minimal Knowledge Graph + Neo4j
- Design initial schema (Function, API, CWE nodes; CALLS, USES, ASSOCIATED_WITH edges)
- Populate with data from Step 1 (Ghidra-extracted functions and API calls)
- Add CWE metadata from MITRE
- Test basic Cypher queries
- **Why fourth**: KG is the core differentiator; must be validated before building GraphRAG

### Step 5: Function Embedding Pipeline
- Use a pre-trained code embedding model to generate embeddings from decompiled function pseudocode
- Build a vector index for similarity search
- Test: given a vulnerable function, can we retrieve structurally similar functions?
- **Why fifth**: Enables the similarity-based retrieval component of GraphRAG

---

> **END OF RESEARCH UNDERSTANDING REPORT**
>
> **Status:** Awaiting user instruction before proceeding to implementation.
>
> **No code has been written. No datasets have been downloaded. No architecture has been finalized.**
