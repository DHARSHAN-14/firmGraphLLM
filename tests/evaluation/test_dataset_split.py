"""
Tests for the 80/20 Stratified Research Dataset Split
"""

import json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SPLIT_DIR = ROOT / "data" / "research_split_80_20"


def test_split_files_exist():
    assert (SPLIT_DIR / "split_summary.json").exists()
    assert (SPLIT_DIR / "train_manifest.json").exists()
    assert (SPLIT_DIR / "test_manifest.json").exists()
    assert (SPLIT_DIR / "train_ground_truth.json").exists()
    assert (SPLIT_DIR / "test_ground_truth.json").exists()
    assert (SPLIT_DIR / "README.md").exists()


def test_no_data_leakage():
    with open(SPLIT_DIR / "train_manifest.json") as f:
        train_data = json.load(f)
    with open(SPLIT_DIR / "test_manifest.json") as f:
        test_data = json.load(f)

    train_sources = {b["source_file"] for b in train_data["binaries"]}
    test_sources = {b["source_file"] for b in test_data["binaries"]}

    overlap = train_sources.intersection(test_sources)
    assert len(overlap) == 0, f"Found overlapping files between train and test: {overlap}"


def test_ratio_and_stratification():
    with open(SPLIT_DIR / "split_summary.json") as f:
        summary = json.load(f)

    assert summary["total_testcases"] == 6232
    assert summary["total_binaries"] == 12464
    assert summary["train_testcases"] == 4986
    assert summary["test_testcases"] == 1246

    # Verify per-CWE stratification is ~80%
    for cwe_tag, stats in summary["per_cwe_breakdown"].items():
        assert 79.0 <= stats["train_pct"] <= 81.0
        assert 19.0 <= stats["test_pct"] <= 21.0


def test_binaries_present_on_disk():
    with open(SPLIT_DIR / "test_manifest.json") as f:
        test_data = json.load(f)

    # Check a sample of 20 test cases to verify disk presence
    sample = test_data["binaries"][:20]
    for case in sample:
        bad_path = ROOT / case["binary_bad"]
        good_path = ROOT / case["binary_good"]
        assert bad_path.exists(), f"Missing binary: {bad_path}"
        assert good_path.exists(), f"Missing binary: {good_path}"
        assert bad_path.stat().st_size > 0
        assert good_path.stat().st_size > 0
