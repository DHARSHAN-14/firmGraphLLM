"""
firmware.ingestion.ingest
==========================
Orchestration layer — ties fingerprinting, identification, and metadata
persistence together.  This module is also the ``__main__`` entry point
for the CLI:

    python -m firmware.ingestion.ingest <firmware_path> [--output-dir DIR]

Exit codes
----------
0  Success.
1  Input file not found.
2  Input file is not readable (permissions, etc.).
3  Unexpected error during ingestion.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .file_identification import identify_file
from .fingerprint import compute_hashes, make_firmware_id
from .metadata import FirmwareMetadata, build_metadata, save_metadata

# Default storage location relative to the project root.
_DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[3] / "data" / "processed" / "firmware"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class IngestionError(Exception):
    """Raised when ingestion cannot proceed due to an input problem."""


def ingest_firmware(
    firmware_path: Path,
    output_dir: Optional[Path] = None,
) -> FirmwareMetadata:
    """Run the full ingestion pipeline for a single firmware file.

    The function is intentionally *side-effect-free* with respect to the
    original file: it only reads *firmware_path* and writes to *output_dir*.

    Parameters
    ----------
    firmware_path:
        Path to the firmware image.  Must exist and be readable.
    output_dir:
        Directory where the metadata JSON will be stored.
        Defaults to ``data/processed/firmware/`` under the project root.

    Returns
    -------
    A fully populated :class:`~metadata.FirmwareMetadata` instance.

    Raises
    ------
    IngestionError
        If the file does not exist or is not readable.
    """
    firmware_path = Path(firmware_path).resolve()
    output_dir = Path(output_dir).resolve() if output_dir else _DEFAULT_OUTPUT_DIR

    # ------------------------------------------------------------------ #
    # Step 1 — Validate input                                              #
    # ------------------------------------------------------------------ #
    if not firmware_path.exists():
        raise IngestionError(f"File not found: {firmware_path}")
    if not firmware_path.is_file():
        raise IngestionError(f"Path is not a regular file: {firmware_path}")
    if not _is_readable(firmware_path):
        raise IngestionError(f"File is not readable: {firmware_path}")

    # ------------------------------------------------------------------ #
    # Step 2 — Hash the file (original is never modified)                  #
    # ------------------------------------------------------------------ #
    hashes = compute_hashes(firmware_path)
    firmware_id = make_firmware_id(hashes["sha256"])

    # ------------------------------------------------------------------ #
    # Step 3 — Identify the file format                                    #
    # ------------------------------------------------------------------ #
    fmt = identify_file(firmware_path)

    # ------------------------------------------------------------------ #
    # Step 4 — Build the metadata record                                   #
    # ------------------------------------------------------------------ #
    size_bytes = firmware_path.stat().st_size
    meta = build_metadata(
        firmware_id=firmware_id,
        source_path=firmware_path,
        size_bytes=size_bytes,
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        mime_type=fmt.mime_type,
        magic_description=fmt.magic_description,
        category=fmt.category,
        format_tag=fmt.format_tag,
        identification_source=fmt.source,
        extra=fmt.extra if fmt.extra else {},
    )

    # ------------------------------------------------------------------ #
    # Step 5 — Persist metadata JSON                                       #
    # ------------------------------------------------------------------ #
    save_metadata(meta, output_dir)

    return meta


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_readable(path: Path) -> bool:
    """Return True if *path* can be opened for reading."""
    try:
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m firmware.ingestion.ingest",
        description=(
            "FirmGraph-LLM — Firmware Ingestion Pipeline\n"
            "Accepts a firmware file, fingerprints it, identifies its format,\n"
            "and writes a structured metadata JSON to the processed data store."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "firmware_path",
        metavar="FIRMWARE_PATH",
        help="Path to the firmware image to ingest.",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default=None,
        help=(
            "Directory where the metadata JSON will be stored. "
            f"Defaults to data/processed/firmware/ in the project root."
        ),
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Print the full metadata JSON to stdout instead of the summary.",
    )
    return parser


def _print_summary(meta: FirmwareMetadata, json_path: Path) -> None:
    """Print a human-readable ingestion summary."""
    sep = "─" * 60
    print(sep)
    print("  FirmGraph-LLM · Firmware Ingestion Complete")
    print(sep)
    print(f"  Firmware ID  : {meta.firmware_id}")
    print(f"  Filename     : {meta.filename}")
    print(f"  Size         : {meta.size_bytes:,} bytes")
    print(f"  SHA-256      : {meta.sha256}")
    print(f"  SHA-1        : {meta.sha1}")
    print(f"  MD5          : {meta.md5}")
    print(f"  MIME type    : {meta.mime_type}")
    print(f"  Format       : {meta.format_tag}  ({meta.magic_description})")
    print(f"  Category     : {meta.category}")
    print(f"  ID source    : {meta.identification_source}")
    print(f"  Ingested at  : {meta.ingested_at}")
    print(f"  Metadata     : {json_path}")
    print(sep)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point.  Returns an integer exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    firmware_path = Path(args.firmware_path)
    output_dir = Path(args.output_dir) if args.output_dir else None

    try:
        meta = ingest_firmware(firmware_path, output_dir=output_dir)
    except IngestionError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        if "not found" in str(exc).lower():
            return 1
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] Unexpected failure during ingestion: {exc}", file=sys.stderr)
        return 3

    out_dir = output_dir or _DEFAULT_OUTPUT_DIR
    json_path = out_dir / f"{meta.firmware_id}.json"

    if args.json_output:
        from dataclasses import asdict
        print(json.dumps(asdict(meta), indent=2))
    else:
        _print_summary(meta, json_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
