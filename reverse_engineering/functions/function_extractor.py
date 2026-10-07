"""
reverse_engineering.functions.function_extractor
================================================
Decompiled Function Parser & Feature Extractor.

Parses decompiled functions, pseudocode bodies, and called APIs to build
standardized FunctionRecord instances for LLM reasoning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from llm.reasoning.conversation import FunctionRecord


class FunctionExtractor:
    """Extracts function records from decompiled C pseudocode or disassembly dumps."""

    # Common C library APIs to detect in pseudocode
    KNOWN_APIS = {
        "system", "popen", "execl", "execle", "execlp", "execv", "execvp", "execvpe",
        "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf", "vsprintf",
        "printf", "fprintf", "vprintf", "vfprintf", "memcpy", "memmove", "memset",
        "gets", "fgets", "scanf", "fscanf", "sscanf", "read", "recv", "recvfrom",
        "getenv", "malloc", "free", "realloc", "strlen"
    }

    def extract_from_pseudocode(
        self,
        func_name: str,
        pseudocode: str,
        binary_name: str = "unknown",
        address: str = "0x0",
        source_apis: Optional[set[str]] = None,
        sink_apis: Optional[set[str]] = None,
        is_source: Optional[bool] = None,
        is_sink: Optional[bool] = None,
    ) -> FunctionRecord:
        """Create a FunctionRecord and automatically flag detected APIs, sources, and sinks."""
        detected_apis = self.find_called_apis(pseudocode)

        sources = source_apis or {"recv", "read", "getenv", "fgets", "scanf"}
        sinks = sink_apis or {"system", "popen", "execl", "strcpy", "strcat", "sprintf", "printf", "memcpy", "gets"}

        flag_source = is_source if is_source is not None else any(api in sources for api in detected_apis)
        flag_sink = is_sink if is_sink is not None else any(api in sinks for api in detected_apis)

        return FunctionRecord(
            name=func_name,
            pseudocode=pseudocode.strip(),
            binary=binary_name,
            address=address,
            is_source=flag_source,
            is_sink=flag_sink,
            source_param=0,
            api_calls=detected_apis,
        )

    def find_called_apis(self, code: str) -> list[str]:
        """Detect standard C API calls present in code string."""
        found = []
        for api in self.KNOWN_APIS:
            # Word boundary regex: e.g. \bsystem\s*\(
            if re.search(rf"\b{re.escape(api)}\s*\(", code):
                found.append(api)
        return found
