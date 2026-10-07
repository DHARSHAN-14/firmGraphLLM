"""
firmware.identification.architecture
====================================
Binary Architecture & Target Hardware Identification.

Parses ELF header metadata directly from binary files:
- CPU Architecture (ARM, AArch64, MIPS, x86, x86_64, RISC-V, PowerPC)
- Endianness (Little-Endian / Big-Endian)
- Bitness (32-bit / 64-bit)
- Object Type (Executable, Shared Object, Relocatable)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Standard ELF Machine IDs (e_machine)
ELF_MACHINES = {
    0x02: "SPARC",
    0x03: "x86 (Intel 80386)",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC 64",
    0x28: "ARM (32-bit)",
    0x2A: "SuperH",
    0x32: "IA-64 (Itanium)",
    0x3E: "x86-64 (AMD64 / Intel 64)",
    0xB7: "ARM64 (AArch64)",
    0xF3: "RISC-V",
}

# Standard ELF Object Types (e_type)
ELF_TYPES = {
    1: "Relocatable",
    2: "Executable",
    3: "Shared Object (Library)",
    4: "Core Dump",
}


@dataclass
class ArchitectureInfo:
    is_elf: bool
    machine: str = "Unknown"
    bitness: int = 0          # 32 or 64
    endianness: str = "Unknown"  # "little" or "big"
    binary_type: str = "Unknown"
    entry_point: str = "0x0"


class ArchitectureIdentifier:
    """Inspects binaries and extracts architecture information."""

    @staticmethod
    def identify(file_path: Path) -> ArchitectureInfo:
        path = Path(file_path).resolve()
        if not path.is_file():
            return ArchitectureInfo(is_elf=False)

        try:
            with open(path, "rb") as f:
                header = f.read(52)  # Read up to 32-bit/64-bit ELF header length
        except OSError:
            return ArchitectureInfo(is_elf=False)

        if len(header) < 16 or header[:4] != b"\x7fELF":
            return ArchitectureInfo(is_elf=False)

        # Byte 4: EI_CLASS (1 = 32-bit, 2 = 64-bit)
        ei_class = header[4]
        bitness = 32 if ei_class == 1 else (64 if ei_class == 2 else 0)

        # Byte 5: EI_DATA (1 = little-endian, 2 = big-endian)
        ei_data = header[5]
        endian_str = "<" if ei_data == 1 else (">" if ei_data == 2 else None)
        endianness = "little" if ei_data == 1 else ("big" if ei_data == 2 else "Unknown")

        if not endian_str:
            return ArchitectureInfo(is_elf=True, bitness=bitness, endianness=endianness)

        # e_type at offset 16 (uint16), e_machine at offset 18 (uint16)
        try:
            e_type, e_machine = struct.unpack(f"{endian_str}HH", header[16:20])
            machine_name = ELF_MACHINES.get(e_machine, f"Unknown ({hex(e_machine)})")
            binary_type = ELF_TYPES.get(e_type, f"Unknown ({e_type})")

            # Entry point at offset 24 (uint32 for 32-bit, uint64 for 64-bit)
            if bitness == 32:
                entry = struct.unpack(f"{endian_str}I", header[24:28])[0]
            else:
                entry = struct.unpack(f"{endian_str}Q", header[24:32])[0]
            entry_point_str = hex(entry)

            return ArchitectureInfo(
                is_elf=True,
                machine=machine_name,
                bitness=bitness,
                endianness=endianness,
                binary_type=binary_type,
                entry_point=entry_point_str,
            )
        except Exception:
            return ArchitectureInfo(is_elf=True, bitness=bitness, endianness=endianness)
