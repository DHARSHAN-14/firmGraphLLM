"""
tests/ingestion/test_ingestion.py
====================================
Unit tests for the firmware ingestion pipeline.

Test philosophy
---------------
- All tests operate on *small, synthetic* files created in a temporary
  directory — the real firmware / Juliet dataset is never touched.
- Tests are isolated: each test function receives a fresh tmp_path fixture.
- The Juliet dataset and any real firmware are explicitly excluded.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import asdict
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module-under-test imports
# ---------------------------------------------------------------------------
from firmware.ingestion.fingerprint import compute_hashes, make_firmware_id
from firmware.ingestion.file_identification import (
    FormatInfo,
    identify_file,
    CAT_EXECUTABLE,
    CAT_ARCHIVE,
    CAT_FIRMWARE,
    CAT_UNKNOWN,
)
from firmware.ingestion.metadata import (
    FirmwareMetadata,
    build_metadata,
    load_metadata,
    save_metadata,
)
from firmware.ingestion.ingest import IngestionError, ingest_firmware


# ===========================================================================
# Helpers
# ===========================================================================


def _write(path: Path, data: bytes) -> Path:
    """Write *data* to *path* and return *path*."""
    path.write_bytes(data)
    return path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# ===========================================================================
# fingerprint.py
# ===========================================================================


class TestComputeHashes:
    """compute_hashes() correctness tests."""

    def test_known_content(self, tmp_path: Path):
        """Hashes must match known values for fixed content."""
        data = b"FirmGraph-LLM test content\x00\xff"
        fw = _write(tmp_path / "sample.bin", data)

        result = compute_hashes(fw)

        assert result["sha256"] == _sha256(data)
        assert result["sha1"] == _sha1(data)
        assert result["md5"] == _md5(data)

    def test_empty_file(self, tmp_path: Path):
        """Empty file should hash to the well-known empty-string digests."""
        fw = _write(tmp_path / "empty.bin", b"")

        result = compute_hashes(fw)

        assert result["sha256"] == hashlib.sha256(b"").hexdigest()
        assert result["sha1"] == hashlib.sha1(b"").hexdigest()
        assert result["md5"] == hashlib.md5(b"").hexdigest()

    def test_large_chunked_read(self, tmp_path: Path):
        """A file larger than the read chunk must still hash correctly."""
        # 3 MiB of pseudo-random-ish bytes (repeating pattern keeps it fast).
        data = (b"\xde\xad\xbe\xef" * 256) * (3 * 1024 // 4)  # ~ 3 MiB
        fw = _write(tmp_path / "large.bin", data)

        result = compute_hashes(fw)

        assert result["sha256"] == _sha256(data)

    def test_returns_all_three_keys(self, tmp_path: Path):
        """Result dict must contain exactly md5, sha1, sha256."""
        fw = _write(tmp_path / "check.bin", b"abc")
        result = compute_hashes(fw)
        assert set(result.keys()) == {"md5", "sha1", "sha256"}

    def test_nonexistent_raises(self, tmp_path: Path):
        """compute_hashes() should propagate FileNotFoundError."""
        with pytest.raises((FileNotFoundError, OSError)):
            compute_hashes(tmp_path / "ghost.bin")


class TestMakeFirmwareId:
    """make_firmware_id() determinism and format tests."""

    def test_deterministic(self):
        """Same SHA-256 → same firmware ID, always."""
        sha = "a" * 64
        assert make_firmware_id(sha) == make_firmware_id(sha)

    def test_different_inputs_differ(self):
        """Different SHA-256 digests must yield different firmware IDs."""
        sha_a = "a" * 64
        sha_b = "b" * 64
        assert make_firmware_id(sha_a) != make_firmware_id(sha_b)

    def test_prefix(self):
        """Firmware IDs must start with 'fw-'."""
        sha = "0123456789abcdef" * 4
        fid = make_firmware_id(sha)
        assert fid.startswith("fw-")

    def test_id_uses_first_16_chars(self):
        """The hex segment of the ID should be the first 16 chars of SHA-256."""
        sha = "fedcba9876543210" + "0" * 48
        fid = make_firmware_id(sha)
        assert fid == "fw-fedcba9876543210"

    def test_invalid_length_raises(self):
        """Digest shorter than 64 characters should raise ValueError."""
        with pytest.raises(ValueError):
            make_firmware_id("abc")

    def test_real_file_deterministic(self, tmp_path: Path):
        """Two ingestions of the identical file must produce the same firmware ID."""
        data = b"firmware content"
        fw = _write(tmp_path / "fw.bin", data)

        h1 = compute_hashes(fw)
        h2 = compute_hashes(fw)
        assert make_firmware_id(h1["sha256"]) == make_firmware_id(h2["sha256"])


# ===========================================================================
# file_identification.py
# ===========================================================================


class TestIdentifyFile:
    """identify_file() category and format detection."""

    def test_elf_binary(self, tmp_path: Path):
        """ELF magic bytes should be identified as executable/elf."""
        # Minimal fake ELF header (4 magic bytes + class byte).
        data = b"\x7fELF\x02" + b"\x00" * 59
        fw = _write(tmp_path / "sample.elf", data)

        info = identify_file(fw)

        assert info.category == CAT_EXECUTABLE
        assert info.format_tag == "elf"

    def test_zip_archive(self, tmp_path: Path):
        """ZIP magic bytes (PK\x03\x04) should map to archive/zip."""
        data = b"PK\x03\x04" + b"\x00" * 256
        fw = _write(tmp_path / "archive.zip", data)

        info = identify_file(fw)

        assert info.category == CAT_ARCHIVE
        assert info.format_tag == "zip"

    def test_gzip_archive(self, tmp_path: Path):
        """GZIP magic bytes (\\x1f\\x8b) → archive/gzip."""
        data = b"\x1f\x8b\x08\x00" + b"\x00" * 100
        fw = _write(tmp_path / "data.tar.gz", data)

        info = identify_file(fw)

        assert info.category == CAT_ARCHIVE

    def test_uboot_firmware(self, tmp_path: Path):
        """U-Boot legacy magic (0x27051956) → firmware_image category."""
        # Big-endian U-Boot magic: 0x27 0x05 0x19 0x56
        data = b"\x27\x05\x19\x56" + b"\x00" * 60
        fw = _write(tmp_path / "uboot.img", data)

        info = identify_file(fw)

        assert info.category == CAT_FIRMWARE

    def test_unknown_binary(self, tmp_path: Path):
        """Truly unknown binary data should return a FormatInfo (not raise)."""
        # Random-looking data with no known magic bytes.
        data = bytes(range(256)) * 4
        fw = _write(tmp_path / "mystery.bin", data)

        info = identify_file(fw)

        assert isinstance(info, FormatInfo)

    def test_empty_file(self, tmp_path: Path):
        """Empty file should return a FormatInfo without raising."""
        fw = _write(tmp_path / "empty.fw", b"")

        info = identify_file(fw)

        assert isinstance(info, FormatInfo)
        # An empty file has no recognisable category; accept unknown.
        assert info.category in (CAT_UNKNOWN, CAT_FIRMWARE, "")

    def test_returns_format_info(self, tmp_path: Path):
        """Return value is always a FormatInfo dataclass instance."""
        fw = _write(tmp_path / "test.bin", b"\x00\x01\x02\x03")
        info = identify_file(fw)
        assert isinstance(info, FormatInfo)
        assert hasattr(info, "mime_type")
        assert hasattr(info, "category")
        assert hasattr(info, "format_tag")


# ===========================================================================
# metadata.py
# ===========================================================================


class TestBuildMetadata:
    """build_metadata() field assignment tests."""

    def _make_meta(self, tmp_path: Path, **overrides) -> FirmwareMetadata:
        fw = _write(tmp_path / "fw.bin", b"test")
        defaults = dict(
            firmware_id="fw-0000000000000001",
            source_path=fw,
            size_bytes=4,
            sha256="a" * 64,
            sha1="b" * 40,
            md5="c" * 32,
            mime_type="application/octet-stream",
            magic_description="data",
            category="unknown",
            format_tag="data",
            identification_source="magic",
        )
        defaults.update(overrides)
        return build_metadata(**defaults)

    def test_firmware_id_set(self, tmp_path: Path):
        meta = self._make_meta(tmp_path)
        assert meta.firmware_id == "fw-0000000000000001"

    def test_filename_extracted(self, tmp_path: Path):
        meta = self._make_meta(tmp_path)
        assert meta.filename == "fw.bin"

    def test_extension_extracted(self, tmp_path: Path):
        meta = self._make_meta(tmp_path)
        assert meta.extension == ".bin"

    def test_size_stored(self, tmp_path: Path):
        meta = self._make_meta(tmp_path, size_bytes=1234)
        assert meta.size_bytes == 1234

    def test_hashes_stored(self, tmp_path: Path):
        meta = self._make_meta(tmp_path, sha256="f" * 64, sha1="e" * 40, md5="d" * 32)
        assert meta.sha256 == "f" * 64
        assert meta.sha1 == "e" * 40
        assert meta.md5 == "d" * 32

    def test_schema_version_present(self, tmp_path: Path):
        meta = self._make_meta(tmp_path)
        assert meta.schema_version == "1"

    def test_status_default(self, tmp_path: Path):
        meta = self._make_meta(tmp_path)
        assert meta.status == "ingested"

    def test_ingested_at_is_iso8601(self, tmp_path: Path):
        from datetime import datetime
        meta = self._make_meta(tmp_path)
        # Should not raise; format: 2026-01-01T00:00:00Z
        dt = datetime.strptime(meta.ingested_at, "%Y-%m-%dT%H:%M:%SZ")
        assert dt.year >= 2025


class TestSaveAndLoadMetadata:
    """save_metadata() / load_metadata() round-trip tests."""

    def _sample_meta(self, tmp_path: Path) -> FirmwareMetadata:
        fw = _write(tmp_path / "sample.bin", b"hello firmware")
        return build_metadata(
            firmware_id="fw-abcdef0123456789",
            source_path=fw,
            size_bytes=14,
            sha256="a" * 64,
            sha1="b" * 40,
            md5="c" * 32,
            mime_type="application/octet-stream",
            magic_description="ASCII text",
            category="unknown",
            format_tag="data",
            identification_source="magic",
        )

    def test_file_created(self, tmp_path: Path):
        meta = self._sample_meta(tmp_path)
        out = tmp_path / "meta_out"
        json_path = save_metadata(meta, out)
        assert json_path.exists()

    def test_filename_uses_firmware_id(self, tmp_path: Path):
        meta = self._sample_meta(tmp_path)
        out = tmp_path / "meta_out"
        json_path = save_metadata(meta, out)
        assert json_path.name == "fw-abcdef0123456789.json"

    def test_json_parseable(self, tmp_path: Path):
        meta = self._sample_meta(tmp_path)
        out = tmp_path / "meta_out"
        json_path = save_metadata(meta, out)
        with open(json_path) as fh:
            data = json.load(fh)
        assert data["firmware_id"] == meta.firmware_id

    def test_round_trip(self, tmp_path: Path):
        meta = self._sample_meta(tmp_path)
        out = tmp_path / "meta_out"
        json_path = save_metadata(meta, out)
        loaded = load_metadata(json_path)
        assert loaded.firmware_id == meta.firmware_id
        assert loaded.sha256 == meta.sha256
        assert loaded.size_bytes == meta.size_bytes
        assert loaded.filename == meta.filename

    def test_output_dir_created(self, tmp_path: Path):
        meta = self._sample_meta(tmp_path)
        deep = tmp_path / "a" / "b" / "c"
        assert not deep.exists()
        save_metadata(meta, deep)
        assert deep.exists()


# ===========================================================================
# ingest.py — integration
# ===========================================================================


class TestIngestFirmware:
    """End-to-end integration tests for ingest_firmware()."""

    def test_nonexistent_file_raises(self, tmp_path: Path):
        """IngestionError must be raised for a path that does not exist."""
        with pytest.raises(IngestionError, match="not found"):
            ingest_firmware(tmp_path / "does_not_exist.bin", output_dir=tmp_path)

    def test_empty_file_ingested(self, tmp_path: Path):
        """An empty file should be ingested successfully."""
        fw = _write(tmp_path / "empty.bin", b"")
        meta = ingest_firmware(fw, output_dir=tmp_path / "out")
        assert meta.firmware_id.startswith("fw-")
        assert meta.size_bytes == 0

    def test_normal_binary_ingested(self, tmp_path: Path):
        """A realistic binary blob should produce a valid metadata record."""
        data = b"\x7fELF\x02\x01\x01\x00" + b"\xca\xfe\xba\xbe" * 100
        fw = _write(tmp_path / "firmware.bin", data)
        meta = ingest_firmware(fw, output_dir=tmp_path / "out")

        assert meta.size_bytes == len(data)
        assert meta.sha256 == _sha256(data)
        assert meta.sha1 == _sha1(data)
        assert meta.md5 == _md5(data)

    def test_original_file_unchanged(self, tmp_path: Path):
        """The original firmware file must not be modified by ingestion."""
        data = b"original firmware bytes"
        fw = _write(tmp_path / "fw.bin", data)
        mtime_before = fw.stat().st_mtime

        ingest_firmware(fw, output_dir=tmp_path / "out")

        assert fw.read_bytes() == data, "File content was modified!"
        assert fw.stat().st_mtime == mtime_before, "File mtime changed!"

    def test_metadata_json_written(self, tmp_path: Path):
        """A JSON metadata file must be created in the output directory."""
        data = b"test fw data"
        fw = _write(tmp_path / "fw.bin", data)
        out_dir = tmp_path / "out"
        meta = ingest_firmware(fw, output_dir=out_dir)

        json_file = out_dir / f"{meta.firmware_id}.json"
        assert json_file.exists()

    def test_deterministic_firmware_id(self, tmp_path: Path):
        """Ingesting the same content twice must yield the same firmware_id."""
        data = b"deterministic content"
        fw1 = _write(tmp_path / "fw1.bin", data)
        fw2 = _write(tmp_path / "fw2.bin", data)

        meta1 = ingest_firmware(fw1, output_dir=tmp_path / "out1")
        meta2 = ingest_firmware(fw2, output_dir=tmp_path / "out2")

        assert meta1.firmware_id == meta2.firmware_id

    def test_different_content_different_id(self, tmp_path: Path):
        """Different file contents must yield different firmware IDs."""
        fw1 = _write(tmp_path / "fw1.bin", b"firmware version A")
        fw2 = _write(tmp_path / "fw2.bin", b"firmware version B")

        meta1 = ingest_firmware(fw1, output_dir=tmp_path / "out1")
        meta2 = ingest_firmware(fw2, output_dir=tmp_path / "out2")

        assert meta1.firmware_id != meta2.firmware_id

    def test_elf_category_detected(self, tmp_path: Path):
        """ELF magic in a .bin file should still be categorised as executable."""
        data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
        fw = _write(tmp_path / "disguised.bin", data)

        meta = ingest_firmware(fw, output_dir=tmp_path / "out")

        assert meta.category == CAT_EXECUTABLE
        assert meta.format_tag == "elf"

    def test_metadata_fields_complete(self, tmp_path: Path):
        """All required metadata fields must be non-empty after ingestion."""
        data = b"some firmware data"
        fw = _write(tmp_path / "fw.fw", data)
        meta = ingest_firmware(fw, output_dir=tmp_path / "out")

        assert meta.firmware_id
        assert meta.filename
        assert meta.source_path
        assert meta.sha256
        assert meta.sha1
        assert meta.md5
        assert meta.ingested_at
        assert meta.status == "ingested"

    def test_unknown_file_type(self, tmp_path: Path):
        """Unknown binary data should ingest without error; category is set."""
        # Data with no recognisable signatures.
        data = bytes([i % 256 for i in range(512)])
        fw = _write(tmp_path / "mystery.fw", data)

        meta = ingest_firmware(fw, output_dir=tmp_path / "out")

        # Must not raise; category must be a non-empty string.
        assert isinstance(meta.category, str)
        assert len(meta.category) > 0


# ===========================================================================
# CLI tests
# ===========================================================================


class TestCLI:
    """Smoke-tests for the CLI entry point."""

    def test_cli_success(self, tmp_path: Path):
        """CLI must exit with code 0 for a valid firmware file."""
        from firmware.ingestion.ingest import main

        data = b"cli test firmware"
        fw = _write(tmp_path / "cli.bin", data)
        rc = main([str(fw), "--output-dir", str(tmp_path / "out")])
        assert rc == 0

    def test_cli_missing_file(self, tmp_path: Path):
        """CLI must exit with code 1 when the file does not exist."""
        from firmware.ingestion.ingest import main

        rc = main([str(tmp_path / "ghost.bin"), "--output-dir", str(tmp_path)])
        assert rc == 1

    def test_cli_json_flag(self, tmp_path: Path, capsys):
        """--json flag should print valid JSON to stdout."""
        from firmware.ingestion.ingest import main

        data = b"json flag test"
        fw = _write(tmp_path / "fw.bin", data)
        rc = main([str(fw), "--output-dir", str(tmp_path / "out"), "--json"])
        assert rc == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "firmware_id" in parsed
        assert "sha256" in parsed
