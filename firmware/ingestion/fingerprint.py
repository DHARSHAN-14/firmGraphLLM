"""
firmware.ingestion.fingerprint
==============================
Cryptographic hashing and deterministic firmware-ID generation.

Rules:
- Reads the file in streaming chunks (constant memory, any file size).
- The firmware_id is derived deterministically from the SHA-256 digest,
  so identical firmware always yields the same ID.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict

# Chunk size for streaming I/O (1 MiB).
_CHUNK = 1 << 20  # 1 048 576 bytes

# Prefix that namespaces our IDs and makes them human-readable at a glance.
_FW_PREFIX = "fw"


def compute_hashes(path: Path) -> Dict[str, str]:
    """Return MD5, SHA-1, and SHA-256 digests for *path*.

    The file is read once in streaming fashion so that very large firmware
    images do not exhaust available RAM.

    Parameters
    ----------
    path:
        Absolute or relative path to the firmware file.  The caller is
        responsible for confirming the path is readable before calling this
        function.

    Returns
    -------
    dict with keys ``"md5"``, ``"sha1"``, and ``"sha256"``.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def make_firmware_id(sha256: str) -> str:
    """Derive a deterministic, collision-resistant firmware identifier.

    The ID is constructed as::

        fw-<first 16 hex chars of sha256>

    Properties
    ----------
    - **Deterministic**: the same binary always produces the same ID.
    - **Unique**: the 16-char prefix gives 2^64 unique values — acceptable
      collision resistance for a research dataset of firmware images.
    - **Readable**: the ``fw-`` prefix makes IDs immediately recognisable
      in logs, JSON files, and graph-node labels.

    Parameters
    ----------
    sha256:
        Full 64-character lowercase hexadecimal SHA-256 digest.
    """
    if len(sha256) != 64:
        raise ValueError(
            f"sha256 must be a 64-character hex string; got length {len(sha256)}"
        )
    return f"{_FW_PREFIX}-{sha256[:16]}"
