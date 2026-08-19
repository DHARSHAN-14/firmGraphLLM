#!/usr/bin/env python3
"""
FirmGraph-LLM — Juliet Ground Truth Parser
==========================================
Parses Juliet's manifest.xml and produces a clean ground_truth.json
mapping each compiled binary to its known vulnerability metadata:
  - CWE ID
  - Flaw line number(s)
  - Source file path
  - Binary paths (bad/good)
  - Source/sink function names (extracted from filename convention)

The ground truth JSON is the reference used during evaluation to
compute TP/FP/FN/TN against our analysis output.

Usage:
    python3 scripts/parse_ground_truth.py [--cwes 78 134 190 606]
"""

import json
import re
import xml.etree.ElementTree as ET
import argparse
import logging
from pathlib import Path
from collections import defaultdict

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).resolve().parent.parent
JULIET_C      = ROOT / "Dataset" / "Juliet_Test_Suite_v1.3_for_C_Cpp" / "C"
MANIFEST_XML  = JULIET_C / "manifest.xml"
COMPILE_MANIFEST = ROOT / "data" / "juliet" / "compile_manifest.json"
OUT_JSON      = ROOT / "data" / "juliet" / "ground_truth.json"

TARGET_CWES = {78, 134, 190, 606}

# ── Filename convention parser ─────────────────────────────────────────────────
# Pattern: CWE{id}_{name}__{type}_{source}_{sink}_{variant}.c
FILENAME_RE = re.compile(
    r"CWE(?P<cwe>\d+)_(?P<cwe_name>[^_]+(?:_[^_]+)*)__"
    r"(?P<dtype>[^_]+)_(?P<source>[^_]+)_(?P<sink>[^_]+)_(?P<variant>\d+)"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ground-truth")


def parse_filename(filename: str) -> dict:
    """
    Extract structured metadata from a Juliet filename.

    Example:
        CWE78_OS_Command_Injection__char_connect_socket_execl_01.c
        → cwe=78, source=connect_socket, sink=execl, variant=01
    """
    stem = Path(filename).stem
    m = FILENAME_RE.match(stem)
    if not m:
        return {}
    return {
        "cwe_id":   int(m.group("cwe")),
        "cwe_name": m.group("cwe_name").replace("_", " "),
        "dtype":    m.group("dtype"),
        "source":   m.group("source"),
        "sink":     m.group("sink"),
        "variant":  int(m.group("variant")),
    }


def parse_manifest_xml(target_cwes: set[int]) -> dict[str, list[int]]:
    """
    Parse Juliet manifest.xml → dict: {filename: [flaw_line, ...]}

    Actual manifest.xml structure:
        <container>
          <testcase>
            <file path="CWE78_OS_Command_Injection__....c">
              <flaw line="N" name="CWE-78: ..."/>
            </file>
          </testcase>
        </container>
    """
    log.info(f"Parsing manifest.xml ({MANIFEST_XML.stat().st_size / 1e6:.1f} MB)...")
    tree = ET.parse(MANIFEST_XML)
    root = tree.getroot()

    flaw_map: dict[str, list[int]] = {}
    total = 0

    for testcase in root.iter("testcase"):
        for file_elem in testcase.iter("file"):
            path = file_elem.get("path", "")
            filename = Path(path).name

            # Filter to target CWEs only
            parsed = parse_filename(filename)
            if not parsed or parsed.get("cwe_id") not in target_cwes:
                continue

            flaws = []
            for flaw in file_elem.iter("flaw"):
                line = flaw.get("line")
                if line:
                    flaws.append(int(line))

            if flaws:
                flaw_map[filename] = flaws
                total += 1

    log.info(f"  Parsed {total} entries for CWEs {sorted(target_cwes)}")
    return flaw_map


def load_compile_manifest() -> dict[str, dict]:
    """
    Load the compile_manifest.json produced by compile_juliet.py.
    Returns dict: {source_filename: {binary_bad, binary_good, success, ...}}
    """
    if not COMPILE_MANIFEST.exists():
        log.warning(
            f"compile_manifest.json not found at {COMPILE_MANIFEST}. "
            "Run compile_juliet.py first. Proceeding with source files only."
        )
        return {}

    data = json.loads(COMPILE_MANIFEST.read_text())
    index = {}
    for entry in data.get("binaries", []):
        if entry.get("success"):
            fname = entry["source_file"]
            index[fname] = entry
    log.info(f"  Loaded compile manifest: {len(index)} successfully compiled binaries")
    return index


def build_ground_truth(
    flaw_map: dict[str, list[int]],
    compile_index: dict[str, dict],
    target_cwes: set[int],
) -> dict:
    """
    Merge manifest.xml flaws with compiled binary paths.
    Produces the final ground_truth.json structure.
    """
    entries = []
    stats: dict[int, dict] = defaultdict(lambda: {"total": 0, "with_binary": 0})

    for filename, flaw_lines in sorted(flaw_map.items()):
        parsed = parse_filename(filename)
        if not parsed:
            continue

        cwe_id = parsed["cwe_id"]
        compile_info = compile_index.get(filename, {})

        entry = {
            "filename":    filename,
            "cwe_id":      cwe_id,
            "cwe_name":    parsed.get("cwe_name", ""),
            "dtype":       parsed.get("dtype", ""),
            "source_func": parsed.get("source", ""),
            "sink_func":   parsed.get("sink", ""),
            "variant":     parsed.get("variant", 0),
            "flaw_lines":  flaw_lines,
            "is_vulnerable": True,        # BAD binary always has the flaw
            "binary_bad":  compile_info.get("binary_bad"),
            "binary_good": compile_info.get("binary_good"),
            "compiled":    compile_info.get("success", False),
        }
        entries.append(entry)
        stats[cwe_id]["total"] += 1
        if compile_info.get("success"):
            stats[cwe_id]["with_binary"] += 1

    ground_truth = {
        "dataset":      "Juliet_Test_Suite_v1.3",
        "target_cwes":  sorted(target_cwes),
        "total_entries": len(entries),
        "stats_per_cwe": {
            cwe: {
                "total_entries":        s["total"],
                "with_compiled_binary": s["with_binary"],
            }
            for cwe, s in sorted(stats.items())
        },
        "cwe_labels": {
            "78":  "OS Command Injection",
            "134": "Uncontrolled Format String",
            "190": "Integer Overflow",
            "606": "Unchecked Loop Condition",
        },
        "entries": entries,
    }
    return ground_truth


def main():
    parser = argparse.ArgumentParser(
        description="Parse Juliet ground truth for FirmGraph-LLM evaluation"
    )
    parser.add_argument(
        "--cwes", nargs="+", type=int, default=[78, 134, 190, 606],
        help="CWE IDs to include (default: 78 134 190 606)"
    )
    args = parser.parse_args()

    target = set(args.cwes)

    log.info("FirmGraph-LLM — Juliet Ground Truth Parser")
    log.info(f"  Target CWEs : {sorted(target)}")

    # 1. Parse manifest.xml
    flaw_map = parse_manifest_xml(target)

    # 2. Load compile manifest (may not exist yet)
    compile_index = load_compile_manifest()

    # 3. Build ground truth
    ground_truth = build_ground_truth(flaw_map, compile_index, target)

    # 4. Save
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(ground_truth, indent=2))
    log.info(f"\nGround truth saved → {OUT_JSON.relative_to(ROOT)}")

    # 5. Summary
    log.info("\n" + "=" * 60)
    log.info("GROUND TRUTH SUMMARY")
    log.info("=" * 60)
    log.info(f"  Total entries   : {ground_truth['total_entries']}")
    for cwe, s in ground_truth["stats_per_cwe"].items():
        label = ground_truth["cwe_labels"].get(str(cwe), "")
        log.info(
            f"  CWE-{cwe} ({label}): "
            f"{s['total_entries']} entries, "
            f"{s['with_compiled_binary']} with compiled binary"
        )
    log.info("=" * 60)


if __name__ == "__main__":
    main()
