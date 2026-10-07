"""
firmware.preprocessing.binary_filter
====================================
Binary Discovery & Preprocessing Filter.

Scans an extracted firmware filesystem tree to discover:
- Executable ELF binaries (bin, sbin, usr/bin, etc.)
- Shared libraries (.so)
- Filters out non-executable assets, text files, and broken links
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..identification.architecture import ArchitectureIdentifier, ArchitectureInfo

log = logging.getLogger(__name__)


@dataclass
class TargetBinary:
    path: Path
    name: str
    size_bytes: int
    arch_info: ArchitectureInfo


class BinaryFilter:
    """Discovers and filters executable binaries in a directory."""

    def __init__(self, target_architectures: Optional[list[str]] = None):
        # Optional filter by machine name (e.g. ["ARM (32-bit)", "MIPS", "x86-64"])
        self.target_architectures = target_architectures

    def scan_directory(self, root_dir: Path) -> list[TargetBinary]:
        """Recursively scan root_dir and return all valid ELF binaries."""
        root_path = Path(root_dir).resolve()
        if not root_path.is_dir():
            return []

        candidates: list[TargetBinary] = []

        for p in root_path.rglob("*"):
            if not p.is_file() or p.is_symlink():
                continue

            # Quick filter: file must be >= 52 bytes to be an ELF
            try:
                size = p.stat().st_size
                if size < 52:
                    continue
            except OSError:
                continue

            arch_info = ArchitectureIdentifier.identify(p)
            if not arch_info.is_elf:
                continue

            if self.target_architectures and arch_info.machine not in self.target_architectures:
                continue

            candidates.append(
                TargetBinary(
                    path=p,
                    name=p.name,
                    size_bytes=size,
                    arch_info=arch_info,
                )
            )

        log.info(f"Discovered {len(candidates)} valid executable binaries in {root_path.name}")
        return candidates
