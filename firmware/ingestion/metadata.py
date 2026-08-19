"""
firmware.ingestion.metadata
============================
Build and persist the structured metadata record for an ingested firmware.

Schema version: 1
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# Bump this when the schema changes in a backwards-incompatible way.
_SCHEMA_VERSION = "1"


@dataclass
class FirmwareMetadata:
    """Complete metadata record for a single firmware sample.

    All fields are plain Python types so that ``dataclasses.asdict``
    produces a JSON-serialisable dict directly.
    """

    # Identity
    firmware_id: str
    schema_version: str = _SCHEMA_VERSION

    # Source provenance
    filename: str = ""
    source_path: str = ""         # Absolute path at ingestion time
    extension: str = ""

    # Size and hashes
    size_bytes: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""

    # Format identification
    mime_type: str = ""
    magic_description: str = ""   # Raw libmagic description
    category: str = ""            # Coarse category (firmware_image, archive, …)
    format_tag: str = ""          # Machine-readable format token
    identification_source: str = ""  # "magic", "heuristic", or "extension"

    # Lifecycle
    ingested_at: str = ""         # ISO-8601 UTC timestamp
    status: str = "ingested"      # Coarse pipeline status

    # Free-form extras (identification engine extras, future fields)
    extra: Dict[str, Any] = field(default_factory=dict)


def build_metadata(
    *,
    firmware_id: str,
    source_path: Path,
    size_bytes: int,
    sha256: str,
    sha1: str,
    md5: str,
    mime_type: str,
    magic_description: str,
    category: str,
    format_tag: str,
    identification_source: str,
    extra: Optional[Dict[str, Any]] = None,
) -> FirmwareMetadata:
    """Assemble a :class:`FirmwareMetadata` from ingestion artefacts.

    Parameters
    ----------
    firmware_id:
        Deterministic ID produced by :func:`~fingerprint.make_firmware_id`.
    source_path:
        Absolute path to the original firmware file.
    size_bytes:
        File size in bytes.
    sha256, sha1, md5:
        Hexadecimal digest strings.
    mime_type, magic_description, category, format_tag, identification_source:
        Values from :class:`~file_identification.FormatInfo`.
    extra:
        Optional free-form dict for future or engine-specific fields.
    """
    source_path = Path(source_path).resolve()

    return FirmwareMetadata(
        firmware_id=firmware_id,
        filename=source_path.name,
        source_path=str(source_path),
        extension=source_path.suffix.lower(),
        size_bytes=size_bytes,
        sha256=sha256,
        sha1=sha1,
        md5=md5,
        mime_type=mime_type,
        magic_description=magic_description,
        category=category,
        format_tag=format_tag,
        identification_source=identification_source,
        ingested_at=_utc_now(),
        status="ingested",
        extra=extra or {},
    )


def save_metadata(
    metadata: FirmwareMetadata,
    output_dir: Path,
) -> Path:
    """Serialise *metadata* to a JSON file inside *output_dir*.

    The filename is ``<firmware_id>.json``.  The output directory is
    created if it does not already exist.

    Parameters
    ----------
    metadata:
        Fully populated :class:`FirmwareMetadata` instance.
    output_dir:
        Directory where the JSON file will be written.

    Returns
    -------
    Path to the written JSON file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    out_path = output_dir / f"{metadata.firmware_id}.json"

    payload = asdict(metadata)

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    return out_path


def load_metadata(json_path: Path) -> FirmwareMetadata:
    """Deserialise a previously saved metadata JSON file.

    Parameters
    ----------
    json_path:
        Path to a JSON file written by :func:`save_metadata`.
    """
    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)

    # Pop known fields; anything extra goes into `extra`.
    known = {f.name for f in FirmwareMetadata.__dataclass_fields__.values()}
    core = {k: v for k, v in data.items() if k in known}
    overflow = {k: v for k, v in data.items() if k not in known}

    if overflow:
        core.setdefault("extra", {}).update(overflow)

    return FirmwareMetadata(**core)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string with 'Z' suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
