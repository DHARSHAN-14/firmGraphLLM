"""
firmware.ingestion
==================
Firmware ingestion pipeline for FirmGraph-LLM.

Accepts raw firmware images, computes cryptographic fingerprints,
identifies the file/container format, and writes a structured
metadata record — without ever modifying the original input.
"""

from .fingerprint import compute_hashes, make_firmware_id
from .file_identification import identify_file
from .metadata import build_metadata, save_metadata
from .ingest import ingest_firmware

__all__ = [
    "compute_hashes",
    "make_firmware_id",
    "identify_file",
    "build_metadata",
    "save_metadata",
    "ingest_firmware",
]
