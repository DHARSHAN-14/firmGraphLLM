# FirmGraph-LLM vs. LATTE Baseline: Comparative Demonstration Report

> **Project:** FirmGraph-LLM (23ISR012)  
> **Benchmark:** ACM TOSEM 2025 LATTE Base Paper  
> **Knowledge Graph State:** 10,243 Nodes, 20,156 Edges, 168 Learned Vulnerability Patterns  

---

## 1. Executive Summary Table

| Case ID | Scenario Description | Ground Truth | Base Setup (LATTE Baseline) | FirmGraph-LLM (Our System) | Core Root Cause |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **CASE-1** | Sanitized Network Flow | **SAFE** | ❌ **FALSE POSITIVE** (Flagged as Vuln) | ✅ **TRUE NEGATIVE** (Correctly Safe) | LATTE suffers from "Sink Trap" sensory bias; FirmGraph verifies safe pattern from KG. |
| **CASE-2** | Multi-Hop Pointer Aliasing | **VULN** | ❌ **FALSE NEGATIVE** (Uncertain / Safe) | ✅ **TRUE POSITIVE** (95% Confident) | LATTE dilutes context across hops; FirmGraph uses structural Call Graph reachability. |
| **CASE-3** | Recurring Cross-Firmware Pattern | **VULN** | ⚠️ **AMNESIA / LOW RANK** (Score 0.35) | ✅ **TOP RANK 1** (Score 0.905) | LATTE has zero memory; FirmGraph leverages frequency counter (159 occurrences in KG). |

---

## 2. In-Depth Failure Mode Analysis

### Case 1: Sanitized Network Input (False Positive Elimination)
- **The Vulnerability Trap:** Developers often write code calling `execl()`, but validate user input using regular expressions or alphanumeric checks.
- **Why the Base Setup (LATTE) Fails:** LATTE has no knowledge memory. Large Language Models exhibit *sensory bias*: when sensitive API names like `execl()` appear in prompt context alongside network sockets, the LLM hallucinates an unmitigated vulnerability, wasting human analysts' time.
- **Why FirmGraph-LLM Succeeds:** FirmGraph-LLM queries Neo4j for the sub-pattern `recv -> is_valid_alphanumeric -> execl`. The Knowledge Graph confirms that alphanumeric bounding breaks the taint reachability chain, giving a high-confidence **SAFE** verdict.

### Case 2: Multi-Hop Pointer Aliasing (Precision Tracking)
- **The Vulnerability Trap:** Firmware binaries rarely pass arguments directly from socket to sink in a single function; data is routed across 3–5 intermediate wrapper functions with pointer aliases (`buffer -> dst -> msg -> alias -> fmt`).
- **Why the Base Setup (LATTE) Fails:** Multi-turn conversational prompting without graph guidance causes context dilution. The model loses track of pointer equivalence and outputs an uncertain or non-vulnerable verdict.
- **Why FirmGraph-LLM Succeeds:** FirmGraph-LLM leverages the Neo4j Call Graph: `(read_input)-[:CALLS]->(wrap_log)-[:CALLS]->(print_msg)`. The exact parameter indices and propagation path are injected as pre-computed graph evidence into the prompt sequence.

### Case 3: Cross-Firmware Pattern Memory (Triage Prioritization)
- **Why the Base Setup (LATTE) Fails:** LATTE isolates every binary. It analyzes binary A, deletes all memory, and when it analyzes binary B sharing 80% identical code, it re-analyzes with zero historical grounding (`kg_evidence_score = 0.0`).
- **Why FirmGraph-LLM Succeeds:** FirmGraph-LLM accumulates security memory in Neo4j. In this case, it matches `pattern::CWE-190::t::fscanf` which has 159 verified occurrences. The multi-factor triage formula `(0.5×LLM + 0.3×KG + 0.2×CWE)` prioritizes this recurring bug to Rank 1.
