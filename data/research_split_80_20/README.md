# FirmGraph-LLM Research Dataset: 80/20 Stratified Split

This directory contains the isolated, dedicated benchmark dataset split for the **FirmGraph-LLM** research project (benchmarked against the ACM TOSEM 2025 LATTE base paper).

## Partition Overview
- **Split Ratio:** 80% Training (Knowledge Graph ingestion, few-shot tuning, pattern indexing) / 20% Testing (Unseen evaluation benchmark)
- **Random Seed:** 42 (100% deterministic and reproducible)
- **Target CWEs:** CWE-78, CWE-134, CWE-190, CWE-606
- **Architecture:** Linux x86-64 stripped ELF binaries compiled with GCC (`-O0`, `-fno-stack-protector`, `-no-pie`)

## Statistical Breakdown

| CWE Identifier | Vulnerability Name | Total Cases | Train Cases (80%) | Test Cases (20%) | Train Binaries (Bad+Good) | Test Binaries (Bad+Good) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **CWE-78** | OS Command Injection | 760 | 608 (80.0%) | 152 (20.0%) | 1216 | 304 |
| **CWE-134** | Uncontrolled Format String | 1,710 | 1368 (80.0%) | 342 (20.0%) | 2736 | 684 |
| **CWE-190** | Integer Overflow | 3,420 | 2736 (80.0%) | 684 (20.0%) | 5472 | 1368 |
| **CWE-606** | Unchecked Loop Condition | 342 | 274 (80.12%) | 68 (19.88%) | 548 | 136 |
| **TOTAL** | **All 4 Vulnerability Classes** | **6232** | **4986 (79.99%)** | **1246 (20.01%)** | **9972** | **2492** |

## Directory Structure
```
data/research_split_80_20/
├── train/
│   ├── CWE-78/    (bad/ and good/ binaries)
│   ├── CWE-134/   (bad/ and good/ binaries)
│   ├── CWE-190/   (bad/ and good/ binaries)
│   └── CWE-606/   (bad/ and good/ binaries)
├── test/
│   ├── CWE-78/    (bad/ and good/ binaries)
│   ├── CWE-134/   (bad/ and good/ binaries)
│   ├── CWE-190/   (bad/ and good/ binaries)
│   └── CWE-606/   (bad/ and good/ binaries)
├── _build/        (helper object files io.o, std_thread.o)
├── train_manifest.json
├── test_manifest.json
├── train_ground_truth.json
├── test_ground_truth.json
└── split_summary.json
```

## Anti-Leakage Guarantee
In the Juliet test suite, each test case comprises a vulnerable binary (`bad`) and its safe counterpart (`good`). Both counterparts are strictly assigned together to either `train/` or `test/`. Unseen evaluation on `test/` is therefore completely isolated from the training partition.
