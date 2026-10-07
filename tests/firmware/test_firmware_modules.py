"""
Tests for firmware extraction, identification, and preprocessing modules.
"""

import pytest
from pathlib import Path
from firmware.identification.architecture import ArchitectureIdentifier, ArchitectureInfo
from firmware.preprocessing.binary_filter import BinaryFilter
from firmware.extraction.extractor import FirmwareExtractor


class TestFirmwareModules:
    def test_architecture_non_elf(self, tmp_path):
        dummy_file = tmp_path / "dummy.txt"
        dummy_file.write_text("hello world this is not an elf")
        arch = ArchitectureIdentifier.identify(dummy_file)
        assert arch.is_elf is False

    def test_architecture_synthetic_elf(self, tmp_path):
        # Create a synthetic 64-bit little-endian ELF header
        elf_file = tmp_path / "synthetic.elf"
        header = bytearray(52)
        header[:4] = b"\x7fELF"
        header[4] = 2   # 64-bit
        header[5] = 1   # little-endian
        header[16:18] = (2).to_bytes(2, "little")   # Executable
        header[18:20] = (0x3E).to_bytes(2, "little") # x86-64
        header[24:32] = (0x401000).to_bytes(8, "little") # entry point
        elf_file.write_bytes(bytes(header))

        arch = ArchitectureIdentifier.identify(elf_file)
        assert arch.is_elf is True
        assert arch.bitness == 64
        assert arch.endianness == "little"
        assert "x86-64" in arch.machine
        assert arch.binary_type == "Executable"

    def test_binary_filter(self, tmp_path):
        elf_file = tmp_path / "app.elf"
        header = bytearray(52)
        header[:4] = b"\x7fELF"
        header[4] = 2
        header[5] = 1
        header[16:18] = (2).to_bytes(2, "little")
        header[18:20] = (0x3E).to_bytes(2, "little")
        elf_file.write_bytes(bytes(header))

        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("notes")

        bf = BinaryFilter()
        targets = bf.scan_directory(tmp_path)
        assert len(targets) == 1
        assert targets[0].name == "app.elf"

    def test_firmware_extractor_file(self, tmp_path):
        src_file = tmp_path / "test.bin"
        src_file.write_text("raw firmware image")
        out_dir = tmp_path / "extracted"

        extractor = FirmwareExtractor(output_base_dir=out_dir)
        extracted_dir = extractor.extract(src_file)
        assert extracted_dir.is_dir()
        files = extractor.list_extracted_files(extracted_dir)
        assert len(files) >= 1
