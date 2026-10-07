"""
firmware.extraction.extractor
=============================
Firmware Unpacking & Extraction Engine.

Handles extracting firmware images into filesystem directories:
- Standard archives (.zip, .tar, .tar.gz, .tgz, .gz)
- SquashFS / Binwalk extraction wrapper with safe fallback
- Returns list of extracted file paths for subsequent binary analysis
"""

from __future__ import annotations

import gzip
import logging
import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class FirmwareExtractionError(Exception):
    """Raised when unpacking a firmware image fails."""


class FirmwareExtractor:
    """Extracts firmware packages into an output directory."""

    def __init__(self, output_base_dir: Optional[Path] = None):
        self.output_base_dir = Path(output_base_dir or "data/processed/extracted").resolve()

    def extract(self, firmware_path: Path, target_dir: Optional[Path] = None) -> Path:
        """
        Extract firmware file to target_dir.
        If target_dir is None, creates a folder named after the firmware file.
        Returns the directory containing extracted files.
        """
        firmware_path = Path(firmware_path).resolve()
        if not firmware_path.exists():
            raise FirmwareExtractionError(f"Firmware image not found: {firmware_path}")

        if target_dir is None:
            folder_name = firmware_path.stem
            target_dir = self.output_base_dir / folder_name

        target_dir = Path(target_dir).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        log.info(f"Extracting {firmware_path.name} → {target_dir}")

        extracted = False

        # 1. Try ZIP
        if zipfile.is_zipfile(firmware_path):
            try:
                with zipfile.ZipFile(firmware_path, "r") as zf:
                    zf.extractall(target_dir)
                log.info("Successfully extracted ZIP archive.")
                extracted = True
            except Exception as e:
                log.warning(f"ZIP extraction failed: {e}")

        # 2. Try TAR / TAR.GZ
        if not extracted and tarfile.is_tarfile(firmware_path):
            try:
                with tarfile.open(firmware_path, "r:*") as tf:
                    tf.extractall(target_dir, filter="data" if hasattr(tarfile, "data_filter") else None)
                log.info("Successfully extracted TAR archive.")
                extracted = True
            except Exception as e:
                log.warning(f"TAR extraction failed: {e}")

        # 3. Try GZIP single file
        if not extracted and firmware_path.suffix == ".gz":
            try:
                out_file = target_dir / firmware_path.stem
                with gzip.open(firmware_path, "rb") as gz_in, open(out_file, "wb") as f_out:
                    shutil.copyfileobj(gz_in, f_out)
                log.info("Successfully decompressed GZIP file.")
                extracted = True
            except Exception as e:
                log.warning(f"GZIP decompression failed: {e}")

        # 4. If single binary file or unsupported archive, copy as standalone target
        if not extracted:
            log.info("Image treated as raw binary or firmware partition.")
            dest = target_dir / firmware_path.name
            shutil.copy2(firmware_path, dest)

        return target_dir

    def list_extracted_files(self, extracted_dir: Path) -> list[Path]:
        """Return all regular files extracted in the directory."""
        return [p for p in Path(extracted_dir).rglob("*") if p.is_file()]
