"""
reverse_engineering.ghidra.headless_decompile
=============================================
Ghidra Headless Decompilation Runner.

Automates invoking Ghidra's analyzeHeadless script or fallback disassembler
to decompile firmware binaries into structured JSON records.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class GhidraDecompiler:
    """Wrapper to run Ghidra headless decompilation on binary files."""

    def __init__(self, ghidra_home: Optional[Path] = None):
        self.ghidra_home = Path(ghidra_home or os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
        self.analyze_headless = self.ghidra_home / "support" / "analyzeHeadless"

    def is_ghidra_available(self) -> bool:
        """Check if analyzeHeadless exists and is executable."""
        return self.analyze_headless.is_file() and os.access(self.analyze_headless, os.X_OK)

    def run_headless(
        self,
        binary_path: Path,
        project_dir: Path,
        project_name: str = "firmgraph_temp",
        post_script: Optional[str] = None,
        script_args: Optional[list[str]] = None,
    ) -> bool:
        """Execute Ghidra analyzeHeadless on the specified binary."""
        if not self.is_ghidra_available():
            log.warning(f"Ghidra analyzeHeadless not found at {self.analyze_headless}")
            return False

        cmd = [
            str(self.analyze_headless),
            str(project_dir),
            project_name,
            "-import",
            str(binary_path),
            "-overwrite",
        ]
        if post_script:
            cmd.extend(["-postScript", post_script])
        if script_args:
            cmd.extend(script_args)

        try:
            log.info(f"Launching Ghidra headless for {binary_path.name}...")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            log.info("Ghidra headless completed successfully.")
            return True
        except subprocess.CalledProcessError as e:
            log.error(f"Ghidra headless failed: {e.stderr}")
            return False
