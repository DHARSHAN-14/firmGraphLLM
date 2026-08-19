#!/usr/bin/env python3
"""
FirmGraph-LLM — Juliet Test Suite Compiler
===========================================
Compiles Juliet CWE-78, 134, 190, 606 test cases into individual
stripped x86-64 ELF binaries for evaluation.

Key behaviours:
  - Skips Windows-only files (any filename containing 'w32')
  - Groups multi-file variants: the 'a' file is the entry point,
    sibling files (b,c,d,e...) are compiled together with it.
    e.g. _22a.c + _22b.c → one binary named after _22a
  - Standalone files (single-digit or no-suffix variants) compiled alone
  - Both BAD (vulnerable, OMITGOOD) and GOOD (safe, OMITBAD) binaries produced
  - All output binaries are stripped of debug symbols

Usage:
    python3 scripts/compile_juliet.py [--cwes 78 134 190 606] [--limit N] [--clean]
"""

import os
import re
import sys
import subprocess
import shutil
import argparse
import json
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import defaultdict

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).resolve().parent.parent
JULIET_C      = ROOT / "Dataset" / "Juliet_Test_Suite_v1.3_for_C_Cpp" / "C"
TESTCASES_DIR = JULIET_C / "testcases"
SUPPORT_DIR   = JULIET_C / "testcasesupport"
OUT_BASE      = ROOT / "data" / "juliet" / "compiled"
LOG_DIR       = ROOT / "data" / "juliet"

# ── Target CWEs ───────────────────────────────────────────────────────────────
CWE_MAP = {
    78:  "CWE78_OS_Command_Injection",
    134: "CWE134_Uncontrolled_Format_String",
    190: "CWE190_Integer_Overflow",
    606: "CWE606_Unchecked_Loop_Condition",
}

# ── Compiler flags ─────────────────────────────────────────────────────────────
CFLAGS_BASE = [
    "-m64",
    "-O0",                  # No optimisation — preserve taint flows
    "-fno-stack-protector",
    "-fno-pie",
    "-no-pie",
    "-w",                   # Suppress warnings (Juliet has intentional issues)
    "-DINCLUDEMAIN",
]

LDFLAGS = ["-lpthread", "-lm"]
STRIP_CMD = ["strip", "--strip-all"]

# Multi-file variant pattern: ends with _NNa.c (a = entry point)
MULTIFILE_ENTRY_RE = re.compile(r"_(\d{2,})a\.c$")
# Sibling file suffix: _NNb.c, _NNc.c, _NNd.c, _NNe.c ...
MULTIFILE_SIBLING_RE = re.compile(r"_(\d{2,})([b-z])\.c$")

# ── Support sources ────────────────────────────────────────────────────────────
SUPPORT_SOURCES = [SUPPORT_DIR / "io.c", SUPPORT_DIR / "std_thread.c"]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("juliet-compile")


@dataclass
class CompileResult:
    cwe: int
    source_file: str               # primary source filename (entry point)
    extra_sources: list[str] = field(default_factory=list)  # sibling files
    binary_bad: Optional[str] = None
    binary_good: Optional[str] = None
    success: bool = False
    error: Optional[str] = None
    size_bytes: int = 0


def is_windows_only(path: Path) -> bool:
    """Return True for files that use Windows-only APIs and won't compile on Linux."""
    name = path.name.lower()
    # 'w32' prefix in source type section means Windows-specific APIs
    return "w32" in name


def group_source_files(cwe_src_dir: Path) -> list[list[Path]]:
    """
    Collect all Linux-compatible .c files and group multi-file variants.

    Returns a list of groups. Each group is a list of Path objects where:
      - groups of size 1 → standalone compilation
      - groups of size >1 → must be compiled together (entry point first)

    Multi-file pattern:
      CWE78_..._22a.c   (entry, has main-equivalent bad()/good())
      CWE78_..._22b.c   (helper, defines helper functions called by 22a)
    """
    all_sources = sorted(cwe_src_dir.rglob("*.c"))

    # Filter Windows-only
    linux_sources = [s for s in all_sources if not is_windows_only(s)]

    # Separate into sibling sets and standalone
    # Key: (parent_dir, base_stem_without_variant_letter) → list of files
    sibling_groups: dict[str, list[Path]] = defaultdict(list)
    standalone: list[Path] = []

    for src in linux_sources:
        m_sibling = MULTIFILE_SIBLING_RE.search(src.name)
        m_entry   = MULTIFILE_ENTRY_RE.search(src.name)

        if m_sibling:
            # This is a b/c/d/e... sibling — group it with its 'a' counterpart
            variant_num = m_sibling.group(1)
            base = MULTIFILE_SIBLING_RE.sub(f"_{variant_num}", src.name)
            key = f"{src.parent}::{base}"
            sibling_groups[key].append(src)
        elif m_entry:
            # This is the 'a' entry point — start its group
            variant_num = m_entry.group(1)
            base = MULTIFILE_ENTRY_RE.sub(f"_{variant_num}", src.name)
            key = f"{src.parent}::{base}"
            sibling_groups[key].insert(0, src)  # entry point first
        else:
            standalone.append(src)

    groups: list[list[Path]] = [[s] for s in standalone]
    for key, files in sibling_groups.items():
        # Sort so 'a' is first (it has the lowest ord value)
        sorted_files = sorted(files, key=lambda p: p.name)
        # Confirm entry point exists — if not, skip (incomplete group)
        if MULTIFILE_ENTRY_RE.search(sorted_files[0].name):
            groups.append(sorted_files)
        else:
            # Entry point missing — treat each as standalone best-effort
            for f in sorted_files:
                groups.append([f])

    return groups


def compile_support_objects(build_dir: Path) -> list[str]:
    """Compile shared testcasesupport C files into object files."""
    obj_files = []
    build_dir.mkdir(parents=True, exist_ok=True)

    for src in SUPPORT_SOURCES:
        obj = build_dir / (src.stem + ".o")
        cmd = [
            "gcc", "-c", "-m64", "-O0", "-w",
            "-I", str(SUPPORT_DIR),
            "-DINCLUDEMAIN",
            str(src), "-o", str(obj),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log.error(f"Failed to compile support {src.name}: {result.stderr[:200]}")
            sys.exit(1)
        obj_files.append(str(obj))
        log.info(f"  Compiled support: {src.name}")

    return obj_files


def compile_one(
    file_group: list[Path],
    cwe_id: int,
    out_dir: Path,
    support_objs: list[str],
    compile_good: bool = True,
) -> CompileResult:
    """
    Compile one test case (single file or multi-file group) into
    bad (vulnerable) and optionally good (safe) stripped ELF binaries.

    The entry-point file (first in group, or the only file) determines
    the binary name and is the -DINCLUDEMAIN holder.
    """
    entry = file_group[0]
    stem  = entry.stem

    # Remove trailing 'a' from multi-file entry stem for cleaner naming
    display_stem = re.sub(r'(\d{2,})a$', r'\1', stem)

    result = CompileResult(
        cwe=cwe_id,
        source_file=entry.name,
        extra_sources=[f.name for f in file_group[1:]],
    )

    src_args = [str(f) for f in file_group]

    # ── BAD binary (vulnerable path) ──────────────────────────────────────
    bad_out = out_dir / "bad" / display_stem
    bad_out.parent.mkdir(parents=True, exist_ok=True)

    cmd_bad = (
        ["gcc"]
        + CFLAGS_BASE
        + ["-DOMITGOOD"]
        + ["-I", str(SUPPORT_DIR)]
        + src_args
        + support_objs
        + LDFLAGS
        + ["-o", str(bad_out)]
    )
    r = subprocess.run(cmd_bad, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        result.error = r.stderr[:400].strip()
        return result

    subprocess.run(STRIP_CMD + [str(bad_out)], capture_output=True)
    result.binary_bad = str(bad_out.relative_to(ROOT))
    result.size_bytes += bad_out.stat().st_size

    # ── GOOD binary (safe path) ────────────────────────────────────────────
    if compile_good:
        good_out = out_dir / "good" / display_stem
        good_out.parent.mkdir(parents=True, exist_ok=True)

        cmd_good = (
            ["gcc"]
            + CFLAGS_BASE
            + ["-DOMITBAD"]
            + ["-I", str(SUPPORT_DIR)]
            + src_args
            + support_objs
            + LDFLAGS
            + ["-o", str(good_out)]
        )
        rg = subprocess.run(cmd_good, capture_output=True, text=True, timeout=60)
        if rg.returncode == 0:
            subprocess.run(STRIP_CMD + [str(good_out)], capture_output=True)
            result.binary_good = str(good_out.relative_to(ROOT))
            result.size_bytes  += good_out.stat().st_size

    result.success = True
    return result


def compile_cwe(
    cwe_id: int,
    support_objs: list[str],
    limit: Optional[int],
    workers: int,
    compile_good: bool,
) -> list[CompileResult]:
    """Compile all test cases for a given CWE (Linux-only, grouped multi-files)."""
    cwe_dir_name = CWE_MAP[cwe_id]
    cwe_src_dir  = TESTCASES_DIR / cwe_dir_name
    cwe_out_dir  = OUT_BASE / f"CWE-{cwe_id}"

    if not cwe_src_dir.exists():
        log.error(f"CWE source dir not found: {cwe_src_dir}")
        return []

    groups = group_source_files(cwe_src_dir)
    if limit:
        groups = groups[:limit]

    total_files = sum(len(g) for g in groups)
    log.info(f"\n{'='*60}")
    log.info(f"  CWE-{cwe_id} ({cwe_dir_name})")
    log.info(f"  Groups: {len(groups)} (covering {total_files} source files)")
    log.info(f"{'='*60}")

    results = []
    ok = fail = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                compile_one, grp, cwe_id, cwe_out_dir, support_objs, compile_good
            ): grp
            for grp in groups
        }
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            if r.success:
                ok += 1
                if ok % 200 == 0:
                    log.info(f"  [{cwe_id}] ✓ {ok} compiled, ✗ {fail} failed")
            else:
                fail += 1
                log.debug(f"  [{cwe_id}] FAIL {r.source_file}: {r.error}")

    log.info(f"  [{cwe_id}] DONE — ✓ {ok} succeeded, ✗ {fail} failed")
    return results


def save_manifest(all_results: list[CompileResult], cwes: list[int]) -> Path:
    """Save compilation manifest JSON with per-binary metadata."""
    manifest = {
        "dataset":   "Juliet_Test_Suite_v1.3",
        "target_cwes": cwes,
        "compiler":  "gcc",
        "arch":      "x86-64",
        "stripped":  True,
        "linux_only": True,
        "flags":     CFLAGS_BASE,
        "total":     len(all_results),
        "success":   sum(1 for r in all_results if r.success),
        "failed":    sum(1 for r in all_results if not r.success),
        "binaries":  [asdict(r) for r in all_results],
    }
    out = LOG_DIR / "compile_manifest.json"
    out.write_text(json.dumps(manifest, indent=2))
    log.info(f"\nManifest saved → {out.relative_to(ROOT)}")
    return out


def main():
    parser = argparse.ArgumentParser(description="Compile Juliet test cases for FirmGraph-LLM")
    parser.add_argument("--cwes", nargs="+", type=int, default=[78, 134, 190, 606])
    parser.add_argument("--limit",   type=int, default=None, help="Max groups per CWE")
    parser.add_argument("--workers", type=int, default=6,   help="Parallel workers")
    parser.add_argument("--no-good", action="store_true",   help="Skip GOOD binaries")
    parser.add_argument("--clean",   action="store_true",   help="Remove prior output")
    args = parser.parse_args()

    for cwe in args.cwes:
        if cwe not in CWE_MAP:
            log.error(f"Unsupported CWE-{cwe}. Supported: {list(CWE_MAP.keys())}")
            sys.exit(1)

    if args.clean and OUT_BASE.exists():
        log.info(f"Cleaning {OUT_BASE}")
        shutil.rmtree(OUT_BASE)

    OUT_BASE.mkdir(parents=True, exist_ok=True)

    # ── Expected counts (Linux-only, after filtering) ──────────────────────
    # CWE-78 : ~680 groups (1040 standalone + 480 multi → ~700 after dedup)
    # CWE-134: ~1900 groups
    # CWE-190: ~3420 groups
    # CWE-606: ~380 groups

    log.info("FirmGraph-LLM — Juliet Compilation Pipeline")
    log.info(f"  Target CWEs : {args.cwes}")
    log.info(f"  Platform    : Linux only (w32 files skipped)")
    log.info(f"  Workers     : {args.workers}")
    log.info(f"  Limit/CWE   : {args.limit or 'all'}")

    # Step 1: Compile support objects
    build_dir = OUT_BASE / "_build"
    log.info("\nCompiling testcasesupport objects...")
    support_objs = compile_support_objects(build_dir)

    # Step 2: Compile each CWE
    all_results: list[CompileResult] = []
    for cwe_id in args.cwes:
        results = compile_cwe(
            cwe_id=cwe_id,
            support_objs=support_objs,
            limit=args.limit,
            workers=args.workers,
            compile_good=not args.no_good,
        )
        all_results.extend(results)

    # Step 3: Save manifest
    save_manifest(all_results, args.cwes)

    # Step 4: Summary
    total   = len(all_results)
    success = sum(1 for r in all_results if r.success)
    failed  = sum(1 for r in all_results if not r.success)
    total_mb = sum(r.size_bytes for r in all_results) / (1024 * 1024)

    log.info("\n" + "="*60)
    log.info("COMPILATION SUMMARY")
    log.info("="*60)
    log.info(f"  Total groups compiled : {total}")
    log.info(f"  ✓ Succeeded           : {success}")
    log.info(f"  ✗ Failed              : {failed}")
    log.info(f"  Total binary size     : {total_mb:.1f} MB")
    log.info("="*60)

    if failed > 0:
        failures = [r for r in all_results if not r.success][:5]
        log.warning(f"First {len(failures)} failures:")
        for f in failures:
            log.warning(f"  CWE-{f.cwe} {f.source_file}: {f.error}")


if __name__ == "__main__":
    main()
