"""KG node type definitions."""
from dataclasses import dataclass, field


@dataclass
class FirmwareNode:
    id: str; vendor: str; product: str; version: str
    architecture: str = "unknown"; source: str = "unknown"

@dataclass
class BinaryNode:
    id: str; name: str; firmware_id: str; arch: str = "x86-64"
    size_bytes: int = 0; sha256: str = ""; linked_libs: list[str] = field(default_factory=list)

@dataclass
class FunctionNode:
    id: str; name: str; binary_id: str; address: str = ""
    size_bytes: int = 0; pseudocode: str = ""; embedding: list[float] = field(default_factory=list)
    is_source: bool = False; is_sink: bool = False; api_calls: list[str] = field(default_factory=list)

@dataclass
class APINode:
    id: str; name: str; library: str = "glibc"
    is_sink: bool = False; is_source: bool = False
    sink_params: list[int] = field(default_factory=list)
    source_params: list[int] = field(default_factory=list)
    cwe_associations: list[str] = field(default_factory=list)

@dataclass
class CWENode:
    id: str; name: str; description: str = ""
    severity: str = "Medium"; parent_id: str = ""

@dataclass
class VulnPatternNode:
    id: str; description: str; cwe_id: str
    api_sequence: list[str] = field(default_factory=list)
    occurrence_count: int = 1

@dataclass
class CVENode:
    id: str; description: str = ""; cwe_id: str = ""
    cvss_score: float = 0.0; affected_products: list[str] = field(default_factory=list)
