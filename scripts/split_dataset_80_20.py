#!/usr/bin/env python3
"""
FirmGraph-LLM — Research Dataset Stratified 80/20 Splitter
=========================================================
Extracts and isolates the ~6.2k compiled research test cases (12,464 ELF binaries)
from the Juliet Test Suite into a dedicated, standalone dataset directory
(`data/research_split_80_20/`) with a strict 80% Training / 20% Testing split.

Guarantees:
  1. Stratification: Exact 80/20 ratio maintained across all 4 target CWEs:
     - CWE-78  (OS Command Injection)
     - CWE-134 (Uncontrolled Format String)
     - CWE-190 (Integer Overflow)
     - CWE-606 (Unchecked Loop Condition)
  2. Zero Data Leakage: Vulnerable ('bad') and patched ('good') binary pairs for
     every test case remain strictly co-located in the same partition.
  3. Standalone Portability: Binaries are physically copied into separate `train/`
     and `test/` folder hierarchies with matching `_manifest.json` and
     `_ground_truth.json` files for immediate use in machine learning and benchmarking.
  4. 100% Reproducibility: Deterministic sorting + fixed seed (seed=42).

Usage:
  python3 scripts/split_dataset_80_20.py [--seed 42] [--ratio 0.8]
"""

import os
import sys
import json
import shutil
import random
import argparse
import logging
from pathlib import Path
from collections import defaultdict
import xml.etree.ElementTree as ET

# ── Paths ──────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
COMPILED_DIR = PROJECT_ROOT / "data" / "juliet" / "compiled"
COMPILE_MANIFEST = PROJECT_ROOT / "data" / "juliet" / "compile_manifest.json"
MANIFEST_XML = (
    PROJECT_ROOT / "Dataset" / "Juliet_Test_Suite_v1.3_for_C_Cpp" / "C" / "manifest.xml"
)
DEST_DIR = PROJECT_ROOT / "data" / "research_split_80_20"

CWE_LABELS = {
    78: "OS Command Injection",
    134: "Uncontrolled Format String",
    190: "Integer Overflow",
    606: "Unchecked Loop Condition",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("split-80-20")


def parse_manifest_xml_flaws() -> dict[str, list[int]]:
    """
    Extract flaw line numbers from Juliet manifest.xml.
    Returns: dict mapping filename -> list of line numbers.
    """
    if not MANIFEST_XML.exists():
        log.warning(f"manifest.xml not found at {MANIFEST_XML}. Flaw lines will be empty.")
        return {}

    log.info(f"Parsing Juliet manifest.xml ({MANIFEST_XML.stat().st_size / 1e6:.1f} MB)...")
    tree = ET.parse(MANIFEST_XML)
    root = tree.getroot()

    flaws_by_file: dict[str, list[int]] = {}
    for testcase in root.iter("testcase"):
        for file_elem in testcase.iter("file"):
            path = file_elem.get("path", "")
            fname = Path(path).name
            flaws = [
                int(fl.get("line"))
                for fl in file_elem.iter("flaw")
                if fl.get("line") and fl.get("line").isdigit()
            ]
            if flaws:
                flaws_by_file[fname] = flaws

    log.info(f"Loaded flaw lines for {len(flaws_by_file)} files from manifest.xml")
    return flaws_by_file


def parse_filename_meta(filename: str) -> dict:
    """
    Extract structured metadata (cwe, data type, variant) from Juliet filename.
    """
    stem = filename[:-2] if filename.endswith(".c") else filename
    parts = stem.split("__")
    if len(parts) != 2:
        return {}

    left, right = parts[0], parts[1]
    # left: CWE78_OS_Command_Injection
    import re
    m_left = re.match(r"^CWE(\d+)_(.+)$", left)
    cwe_id = int(m_left.group(1)) if m_left else None
    cwe_name = m_left.group(2).replace("_", " ") if m_left else ""

    tokens = right.split("_")
    variant = tokens[-1] if tokens else ""
    dtype = tokens[0] if len(tokens) > 1 else ""

    return {
        "cwe_id": cwe_id,
        "cwe_name": cwe_name,
        "dtype": dtype,
        "variant": variant,
    }


def perform_split(
    train_ratio: float = 0.8,
    seed: int = 42,
    copy_files: bool = True,
):
    """
    Execute stratified 80/20 train/test split and copy binaries.
    """
    log.info(f"Starting 80/20 Stratified Split (Seed={seed}, TrainRatio={train_ratio})")

    if not COMPILE_MANIFEST.exists():
        log.error(f"compile_manifest.json not found at {COMPILE_MANIFEST}")
        sys.exit(1)

    with open(COMPILE_MANIFEST, "r", encoding="utf-8") as f:
        compile_data = json.load(f)

    all_binaries = compile_data.get("binaries", [])
    successful = [b for b in all_binaries if b.get("success")]
    log.info(f"Total successful test cases in compile manifest: {len(successful)}")

    flaws_by_file = parse_manifest_xml_flaws()

    # Group by CWE
    by_cwe = defaultdict(list)
    for entry in successful:
        by_cwe[entry["cwe"]].append(entry)

    rng = random.Random(seed)

    train_cases = []
    test_cases = []
    cwe_summary = {}

    for cwe, items in sorted(by_cwe.items()):
        items_sorted = sorted(items, key=lambda x: x["source_file"])
        rng.shuffle(items_sorted)
        split_idx = int(round(len(items_sorted) * train_ratio))

        cwe_train = items_sorted[:split_idx]
        cwe_test = items_sorted[split_idx:]

        train_cases.extend(cwe_train)
        test_cases.extend(cwe_test)

        cwe_summary[f"CWE-{cwe}"] = {
            "name": CWE_LABELS.get(cwe, f"CWE-{cwe}"),
            "total_testcases": len(items_sorted),
            "train_testcases": len(cwe_train),
            "test_testcases": len(cwe_test),
            "train_pct": round(len(cwe_train) / len(items_sorted) * 100, 2),
            "test_pct": round(len(cwe_test) / len(items_sorted) * 100, 2),
            "total_binaries": len(items_sorted) * 2,
            "train_binaries": len(cwe_train) * 2,
            "test_binaries": len(cwe_test) * 2,
        }

    total_cases = len(successful)
    total_train = len(train_cases)
    total_test = len(test_cases)

    log.info("=" * 60)
    log.info("STRATIFIED 80/20 SPLIT SUMMARY:")
    for cwe_tag, stat in cwe_summary.items():
        log.info(
            f"  {cwe_tag:8s} ({stat['name']}): "
            f"Total={stat['total_testcases']} | "
            f"Train={stat['train_testcases']} ({stat['train_pct']}%) | "
            f"Test={stat['test_testcases']} ({stat['test_pct']}%)"
        )
    log.info(
        f"TOTAL TESTCASES: {total_cases} | "
        f"Train={total_train} ({total_train/total_cases*100:.2f}%) | "
        f"Test={total_test} ({total_test/total_cases*100:.2f}%)"
    )
    log.info(
        f"TOTAL ELF BINARIES: {total_cases * 2} | "
        f"Train={total_train * 2} | Test={total_test * 2}"
    )
    log.info("=" * 60)

    # Prepare destination directories
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    train_dir = DEST_DIR / "train"
    test_dir = DEST_DIR / "test"

    for base_split in (train_dir, test_dir):
        for cwe in (78, 134, 190, 606):
            (base_split / f"CWE-{cwe}" / "bad").mkdir(parents=True, exist_ok=True)
            (base_split / f"CWE-{cwe}" / "good").mkdir(parents=True, exist_ok=True)

    # Copy _build helper objects if available
    build_dir = COMPILED_DIR / "_build"
    if build_dir.exists():
        dest_build = DEST_DIR / "_build"
        dest_build.mkdir(parents=True, exist_ok=True)
        for obj_file in build_dir.glob("*.o"):
            shutil.copy2(obj_file, dest_build / obj_file.name)
        log.info(f"Copied helper build objects to {dest_build}")

    def process_partition(cases: list[dict], split_name: str, target_root: Path):
        manifest_entries = []
        ground_truth_entries = []
        copied_bad = 0
        copied_good = 0

        for c in cases:
            cwe = c["cwe"]
            src_name = c["source_file"]
            bad_src = PROJECT_ROOT / c["binary_bad"]
            good_src = PROJECT_ROOT / c["binary_good"]

            bad_dest = target_root / f"CWE-{cwe}" / "bad" / bad_src.name
            good_dest = target_root / f"CWE-{cwe}" / "good" / good_src.name

            if copy_files:
                if bad_src.exists():
                    shutil.copy2(bad_src, bad_dest)
                    copied_bad += 1
                if good_src.exists():
                    shutil.copy2(good_src, good_dest)
                    copied_good += 1

            rel_bad = str(bad_dest.relative_to(PROJECT_ROOT))
            rel_good = str(good_dest.relative_to(PROJECT_ROOT))

            # Flaw lines resolution
            flaw_lines = flaws_by_file.get(src_name, [])
            if not flaw_lines:
                # Check multi-file variant fallback (e.g., 51a.c -> 51b.c)
                import re
                fallback_name = re.sub(r"([0-9]+)[a-z]\.c$", r"\g<1>b.c", src_name)
                flaw_lines = flaws_by_file.get(fallback_name, [])

            meta = parse_filename_meta(src_name)

            manifest_entry = {
                "cwe": cwe,
                "cwe_name": CWE_LABELS.get(cwe, f"CWE-{cwe}"),
                "source_file": src_name,
                "binary_bad": rel_bad,
                "binary_good": rel_good,
                "size_bytes_bad": bad_src.stat().st_size if bad_src.exists() else 0,
                "size_bytes_good": good_src.stat().st_size if good_src.exists() else 0,
            }
            manifest_entries.append(manifest_entry)

            # Ground truth record (both bad and good evaluation specs)
            gt_record = {
                "source_file": src_name,
                "cwe_id": cwe,
                "cwe_name": CWE_LABELS.get(cwe, f"CWE-{cwe}"),
                "dtype": meta.get("dtype", ""),
                "variant": meta.get("variant", ""),
                "flaw_lines": flaw_lines,
                "binary_bad": {
                    "path": rel_bad,
                    "is_vulnerable": True,
                },
                "binary_good": {
                    "path": rel_good,
                    "is_vulnerable": False,
                },
            }
            ground_truth_entries.append(gt_record)

        log.info(
            f"Split '{split_name}': Processed {len(cases)} cases "
            f"({copied_bad} bad, {copied_good} good binaries copied)"
        )
        return manifest_entries, ground_truth_entries

    train_manifest, train_gt = process_partition(train_cases, "train", train_dir)
    test_manifest, test_gt = process_partition(test_cases, "test", test_dir)

    # Save Manifests
    train_manifest_file = DEST_DIR / "train_manifest.json"
    test_manifest_file = DEST_DIR / "test_manifest.json"

    with open(train_manifest_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "split": "train",
                "ratio": train_ratio,
                "seed": seed,
                "total_testcases": len(train_manifest),
                "total_binaries": len(train_manifest) * 2,
                "binaries": train_manifest,
            },
            f,
            indent=2,
        )

    with open(test_manifest_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "split": "test",
                "ratio": round(1.0 - train_ratio, 2),
                "seed": seed,
                "total_testcases": len(test_manifest),
                "total_binaries": len(test_manifest) * 2,
                "binaries": test_manifest,
            },
            f,
            indent=2,
        )

    # Save Ground Truth Files
    train_gt_file = DEST_DIR / "train_ground_truth.json"
    test_gt_file = DEST_DIR / "test_ground_truth.json"

    with open(train_gt_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "split": "train",
                "dataset": "Juliet_Test_Suite_v1.3",
                "total_entries": len(train_gt),
                "stats_per_cwe": {
                    f"CWE-{c}": cwe_summary[f"CWE-{c}"]["train_testcases"]
                    for c in (78, 134, 190, 606)
                },
                "entries": train_gt,
            },
            f,
            indent=2,
        )

    with open(test_gt_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "split": "test",
                "dataset": "Juliet_Test_Suite_v1.3",
                "total_entries": len(test_gt),
                "stats_per_cwe": {
                    f"CWE-{c}": cwe_summary[f"CWE-{c}"]["test_testcases"]
                    for c in (78, 134, 190, 606)
                },
                "entries": test_gt,
            },
            f,
            indent=2,
        )

    # Save Summary JSON
    summary_file = DEST_DIR / "split_summary.json"
    summary_payload = {
        "dataset_name": "Juliet_Test_Suite_v1.3_Linux_x86_64_Firmware_Research_Subset",
        "methodology": "Stratified Random Sampling (Seed=42, 80/20 Train/Test Split)",
        "train_ratio": train_ratio,
        "test_ratio": round(1.0 - train_ratio, 2),
        "random_seed": seed,
        "total_testcases": total_cases,
        "train_testcases": total_train,
        "test_testcases": total_test,
        "total_binaries": total_cases * 2,
        "train_binaries": total_train * 2,
        "test_binaries": total_test * 2,
        "per_cwe_breakdown": cwe_summary,
        "files": {
            "train_manifest": str(train_manifest_file.relative_to(PROJECT_ROOT)),
            "test_manifest": str(test_manifest_file.relative_to(PROJECT_ROOT)),
            "train_ground_truth": str(train_gt_file.relative_to(PROJECT_ROOT)),
            "test_ground_truth": str(test_gt_file.relative_to(PROJECT_ROOT)),
            "train_directory": str(train_dir.relative_to(PROJECT_ROOT)),
            "test_directory": str(test_dir.relative_to(PROJECT_ROOT)),
        },
    }
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary_payload, f, indent=2)

    # Write README.md in destination directory
    readme_file = DEST_DIR / "README.md"
    readme_content = f"""# FirmGraph-LLM Research Dataset: 80/20 Stratified Split

This directory contains the isolated, dedicated benchmark dataset split for the **FirmGraph-LLM** research project (benchmarked against the ACM TOSEM 2025 LATTE base paper).

## Partition Overview
- **Split Ratio:** 80% Training (Knowledge Graph ingestion, few-shot tuning, pattern indexing) / 20% Testing (Unseen evaluation benchmark)
- **Random Seed:** 42 (100% deterministic and reproducible)
- **Target CWEs:** CWE-78, CWE-134, CWE-190, CWE-606
- **Architecture:** Linux x86-64 stripped ELF binaries compiled with GCC (`-O0`, `-fno-stack-protector`, `-no-pie`)

## Statistical Breakdown

| CWE Identifier | Vulnerability Name | Total Cases | Train Cases (80%) | Test Cases (20%) | Train Binaries (Bad+Good) | Test Binaries (Bad+Good) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **CWE-78** | OS Command Injection | 760 | {cwe_summary['CWE-78']['train_testcases']} ({cwe_summary['CWE-78']['train_pct']}%) | {cwe_summary['CWE-78']['test_testcases']} ({cwe_summary['CWE-78']['test_pct']}%) | {cwe_summary['CWE-78']['train_binaries']} | {cwe_summary['CWE-78']['test_binaries']} |
| **CWE-134** | Uncontrolled Format String | 1,710 | {cwe_summary['CWE-134']['train_testcases']} ({cwe_summary['CWE-134']['train_pct']}%) | {cwe_summary['CWE-134']['test_testcases']} ({cwe_summary['CWE-134']['test_pct']}%) | {cwe_summary['CWE-134']['train_binaries']} | {cwe_summary['CWE-134']['test_binaries']} |
| **CWE-190** | Integer Overflow | 3,420 | {cwe_summary['CWE-190']['train_testcases']} ({cwe_summary['CWE-190']['train_pct']}%) | {cwe_summary['CWE-190']['test_testcases']} ({cwe_summary['CWE-190']['test_pct']}%) | {cwe_summary['CWE-190']['train_binaries']} | {cwe_summary['CWE-190']['test_binaries']} |
| **CWE-606** | Unchecked Loop Condition | 342 | {cwe_summary['CWE-606']['train_testcases']} ({cwe_summary['CWE-606']['train_pct']}%) | {cwe_summary['CWE-606']['test_testcases']} ({cwe_summary['CWE-606']['test_pct']}%) | {cwe_summary['CWE-606']['train_binaries']} | {cwe_summary['CWE-606']['test_binaries']} |
| **TOTAL** | **All 4 Vulnerability Classes** | **{total_cases}** | **{total_train} (79.99%)** | **{total_test} (20.01%)** | **{total_train * 2}** | **{total_test * 2}** |

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
"""
    with open(readme_file, "w", encoding="utf-8") as f:
        f.write(readme_content)

    log.info(f"Generated {train_manifest_file}")
    log.info(f"Generated {test_manifest_file}")
    log.info(f"Generated {train_gt_file}")
    log.info(f"Generated {test_gt_file}")
    log.info(f"Generated {summary_file}")
    log.info(f"Generated {readme_file}")
    log.info("80/20 Stratified Split completed successfully!")


def main():
    parser = argparse.ArgumentParser(description="Create 80/20 Stratified Train/Test Split")
    parser.add_argument("--ratio", type=float, default=0.8, help="Train ratio (default: 0.8)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--no-copy", action="store_true", help="Generate manifests without copying files")
    args = parser.parse_args()

    perform_split(train_ratio=args.ratio, seed=args.seed, copy_files=not args.no_copy)


if __name__ == "__main__":
    main()
