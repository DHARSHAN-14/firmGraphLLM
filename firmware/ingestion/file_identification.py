"""
firmware.ingestion.file_identification
========================================
Format detection for firmware images.

Strategy
--------
1. **python-magic** (libmagic bindings) — the most reliable method;
   inspects actual file bytes, not the extension.
2. **mimetypes** (stdlib) — fast, extension-based, used only as a
   secondary source of human-readable MIME type when magic gives a
   low-information result.
3. **Heuristic byte patterns** — lightweight signature scan for common
   firmware/filesystem magic bytes when libmagic is unavailable or
   returns "data".

The result is a :class:`FormatInfo` dataclass with:

- ``mime_type``  — canonical MIME type string.
- ``magic_description`` — full libmagic description string.
- ``category``  — coarse category label (see :data:`CATEGORIES`).
- ``format_tag`` — short machine-readable tag, e.g. ``"elf"``, ``"zip"``.
"""

from __future__ import annotations

import mimetypes
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import magic as _magic

    _MAGIC_AVAILABLE = True
    # Detect API variant:
    #   python-magic  → exposes magic.from_file()
    #   file-magic    → exposes magic.detect_from_filename()
    _MAGIC_IS_PYTHON_MAGIC = hasattr(_magic, "from_file")
except ImportError:  # pragma: no cover
    _MAGIC_AVAILABLE = False
    _MAGIC_IS_PYTHON_MAGIC = False

# ---------------------------------------------------------------------------
# Category constants
# ---------------------------------------------------------------------------
CAT_FIRMWARE = "firmware_image"
CAT_FILESYSTEM = "filesystem"
CAT_ARCHIVE = "archive"
CAT_EXECUTABLE = "executable"
CAT_SCRIPT = "script"
CAT_UNKNOWN = "unknown"

# ---------------------------------------------------------------------------
# Heuristic magic-byte signatures
# (offset, bytes_to_match, format_tag, category, human_label)
# ---------------------------------------------------------------------------
_SIGNATURES: list[tuple[int, bytes, str, str, str]] = [
    # Executables
    (0, b"\x7fELF", "elf", CAT_EXECUTABLE, "ELF Executable"),
    (0, b"MZ", "pe", CAT_EXECUTABLE, "PE/Windows Executable"),
    # Archives
    (0, b"PK\x03\x04", "zip", CAT_ARCHIVE, "ZIP Archive"),
    (0, b"PK\x05\x06", "zip_empty", CAT_ARCHIVE, "ZIP Archive (empty)"),
    (0, b"\x1f\x8b", "gzip", CAT_ARCHIVE, "GZIP Compressed Data"),
    (0, b"BZh", "bzip2", CAT_ARCHIVE, "BZIP2 Compressed Data"),
    (0, b"\xfd7zXZ\x00", "xz", CAT_ARCHIVE, "XZ Compressed Data"),
    (0, b"ustar", "tar", CAT_ARCHIVE, "TAR Archive"),           # offset 0 variant
    (257, b"ustar", "tar", CAT_ARCHIVE, "TAR Archive"),          # POSIX offset 257
    (0, b"7z\xbc\xaf'\x1c", "7z", CAT_ARCHIVE, "7-Zip Archive"),
    (0, b"Rar!\x1a\x07", "rar", CAT_ARCHIVE, "RAR Archive"),
    # Filesystems
    (0, b"\x19\x02", "jffs2_le", CAT_FILESYSTEM, "JFFS2 Filesystem (LE)"),
    (0, b"\x02\x19", "jffs2_be", CAT_FILESYSTEM, "JFFS2 Filesystem (BE)"),
    (0, b"sqsh", "squashfs", CAT_FILESYSTEM, "SquashFS Filesystem"),
    (0, b"hsqs", "squashfs_be", CAT_FILESYSTEM, "SquashFS Filesystem (BE)"),
    (0, b"qshs", "squashfs_le", CAT_FILESYSTEM, "SquashFS Filesystem (LE)"),
    (0, b"shsq", "squashfs_v4", CAT_FILESYSTEM, "SquashFS v4 Filesystem"),
    (0, b"\x53\xef", "ext2_3_4", CAT_FILESYSTEM, "EXT2/3/4 Filesystem (superblock)"),
    (1080, b"\x53\xef", "ext2_3_4", CAT_FILESYSTEM, "EXT2/3/4 Filesystem"),
    (0, b"CramFs", "cramfs", CAT_FILESYSTEM, "CramFS Filesystem"),
    (0, b"ANDROID!", "android_sparse", CAT_FILESYSTEM, "Android Sparse Image"),
    # Firmware containers
    (0, b"HDR0", "trx_hdr0", CAT_FIRMWARE, "Broadcom TRX Firmware"),
    (0, b"\x48\x44\x52\x30", "trx", CAT_FIRMWARE, "TRX Firmware Container"),
    (0, b"U-Boot", "uboot", CAT_FIRMWARE, "U-Boot Image"),
    (0, b"\x27\x05\x19\x56", "uboot_legacy", CAT_FIRMWARE, "U-Boot Legacy Image"),
    (0, b"\xd0\x0d\xfe\xed", "fdt", CAT_FIRMWARE, "Flattened Device Tree (FDT/DTB)"),
    # D-Link CHK format
    (0, b"\x2a\x23\x24\x5e", "chk", CAT_FIRMWARE, "D-Link CHK Firmware"),
]


@dataclass
class FormatInfo:
    """Structured result of file-format identification."""

    mime_type: str
    magic_description: str
    category: str
    format_tag: str
    source: str = "magic"                    # "magic", "heuristic", or "extension"
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def identify_file(path: Path) -> FormatInfo:
    """Identify the format of *path* without relying solely on the extension.

    Parameters
    ----------
    path:
        Readable file path.

    Returns
    -------
    :class:`FormatInfo` describing the detected format.
    """
    path = Path(path)

    if _MAGIC_AVAILABLE:
        result = _identify_via_magic(path)
    else:
        result = _identify_via_heuristic(path)

    # If magic returned low-information type, supplement via heuristics.
    if result.format_tag in ("data", "unknown", "") or result.category == CAT_UNKNOWN:
        heuristic = _identify_via_heuristic(path)
        if heuristic.category != CAT_UNKNOWN:
            # Merge: keep magic description but override format/category.
            result.category = heuristic.category
            result.format_tag = heuristic.format_tag
            result.extra["heuristic_description"] = heuristic.magic_description

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _identify_via_magic(path: Path) -> FormatInfo:
    """Use libmagic bindings to detect the format.

    Supports both API variants:
    - ``python-magic``: ``magic.from_file(path, mime=True)``
    - ``file-magic``:  ``magic.detect_from_filename(path)`` → ``FileMagic`` namedtuple
    """
    if _MAGIC_IS_PYTHON_MAGIC:
        mime_type: str = _magic.from_file(str(path), mime=True) or "application/octet-stream"
        description: str = _magic.from_file(str(path)) or "data"
    else:
        # file-magic API: returns a FileMagic namedtuple with .mime_type and .name
        result = _magic.detect_from_filename(str(path))
        mime_type = result.mime_type or "application/octet-stream"
        description = result.name or "data"

    category, format_tag = _categorise_from_magic(mime_type, description)

    return FormatInfo(
        mime_type=mime_type,
        magic_description=description,
        category=category,
        format_tag=format_tag,
        source="magic",
    )


def _identify_via_heuristic(path: Path) -> FormatInfo:
    """Byte-pattern scan using known firmware/archive magic bytes."""
    try:
        # Read enough bytes to cover the deepest signature offset (ext superblock at 1080).
        with open(path, "rb") as fh:
            header = fh.read(1088)
    except OSError:
        header = b""

    for offset, pattern, fmt_tag, category, label in _SIGNATURES:
        end = offset + len(pattern)
        if len(header) >= end and header[offset:end] == pattern:
            mime_type = mimetypes.guess_type(f"file.{fmt_tag}")[0] or "application/octet-stream"
            return FormatInfo(
                mime_type=mime_type,
                magic_description=label,
                category=category,
                format_tag=fmt_tag,
                source="heuristic",
            )

    # Fallback: use extension only.
    ext_result = _identify_via_extension(path)
    return ext_result


def _identify_via_extension(path: Path) -> FormatInfo:
    """Last-resort identification from the file extension."""
    suffix = path.suffix.lower().lstrip(".")
    mime_type, _ = mimetypes.guess_type(str(path))
    mime_type = mime_type or "application/octet-stream"

    _ext_map: dict[str, tuple[str, str]] = {
        "bin": (CAT_FIRMWARE, "bin"),
        "img": (CAT_FIRMWARE, "img"),
        "fw": (CAT_FIRMWARE, "fw"),
        "trx": (CAT_FIRMWARE, "trx"),
        "chk": (CAT_FIRMWARE, "chk"),
        "zip": (CAT_ARCHIVE, "zip"),
        "tar": (CAT_ARCHIVE, "tar"),
        "gz": (CAT_ARCHIVE, "gzip"),
        "bz2": (CAT_ARCHIVE, "bzip2"),
        "xz": (CAT_ARCHIVE, "xz"),
        "elf": (CAT_EXECUTABLE, "elf"),
        "exe": (CAT_EXECUTABLE, "pe"),
        "sh": (CAT_SCRIPT, "shell"),
        "py": (CAT_SCRIPT, "python"),
    }

    category, format_tag = _ext_map.get(suffix, (CAT_UNKNOWN, suffix or "unknown"))

    return FormatInfo(
        mime_type=mime_type,
        magic_description=f"Extension-based guess: .{suffix}" if suffix else "Unknown",
        category=category,
        format_tag=format_tag,
        source="extension",
    )


def _categorise_from_magic(mime_type: str, description: str) -> tuple[str, str]:
    """Map a libmagic MIME type and description to (category, format_tag).

    MIME type checks take priority over description-text checks to avoid
    false positives where a valid description contains incidental keywords
    (e.g. gzip files describing the original OS as "MS-DOS").
    """
    desc_lower = description.lower()
    mime_lower = mime_type.lower()

    # --- Archives — MIME type checked first (most authoritative) ---
    if "gzip" in mime_lower:
        return CAT_ARCHIVE, "gzip"
    if "zip" in mime_lower:
        return CAT_ARCHIVE, "zip"
    if "bzip2" in mime_lower:
        return CAT_ARCHIVE, "bzip2"
    if "xz" in mime_lower:
        return CAT_ARCHIVE, "xz"
    if "tar" in mime_lower or "x-tar" in mime_lower:
        return CAT_ARCHIVE, "tar"
    if "7z" in mime_lower:
        return CAT_ARCHIVE, "7z"
    if "rar" in mime_lower:
        return CAT_ARCHIVE, "rar"

    # --- Executables ---
    if "elf" in desc_lower:
        return CAT_EXECUTABLE, "elf"
    if "pe32" in desc_lower or "pe64" in desc_lower or "ms-dos" in desc_lower:
        return CAT_EXECUTABLE, "pe"

    # --- Filesystems ---
    if "squashfs" in desc_lower:
        return CAT_FILESYSTEM, "squashfs"
    if "jffs2" in desc_lower:
        return CAT_FILESYSTEM, "jffs2"
    if "ext2" in desc_lower or "ext3" in desc_lower or "ext4" in desc_lower:
        return CAT_FILESYSTEM, "ext2_3_4"
    if "cramfs" in desc_lower:
        return CAT_FILESYSTEM, "cramfs"
    if "yaffs" in desc_lower:
        return CAT_FILESYSTEM, "yaffs"
    if "ubifs" in desc_lower:
        return CAT_FILESYSTEM, "ubifs"

    # --- Archives — description-text fallback ---
    if "zip" in desc_lower:
        return CAT_ARCHIVE, "zip"
    if "gzip" in desc_lower:
        return CAT_ARCHIVE, "gzip"
    if "bzip2" in desc_lower:
        return CAT_ARCHIVE, "bzip2"
    if "xz" in desc_lower and "compress" in desc_lower:
        return CAT_ARCHIVE, "xz"
    if "tar" in desc_lower:
        return CAT_ARCHIVE, "tar"
    if "7-zip" in desc_lower:
        return CAT_ARCHIVE, "7z"
    if "rar" in desc_lower:
        return CAT_ARCHIVE, "rar"

    # --- Firmware-specific ---
    if "u-boot" in desc_lower or "uboot" in desc_lower:
        return CAT_FIRMWARE, "uboot"
    if "device tree" in desc_lower or "dtb" in desc_lower:
        return CAT_FIRMWARE, "fdt"
    if "trx" in desc_lower:
        return CAT_FIRMWARE, "trx"

    # --- Generic data ---
    if mime_lower in ("application/octet-stream", "application/x-dosexec"):
        return CAT_UNKNOWN, "data"

    # Try to infer from MIME top-level type.
    top_level = mime_lower.split("/")[0]
    if top_level == "text":
        return CAT_SCRIPT, "text"

    return CAT_UNKNOWN, mime_lower.split("/")[-1] or "unknown"
