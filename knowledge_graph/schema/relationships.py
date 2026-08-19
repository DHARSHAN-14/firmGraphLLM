"""KG relationship type definitions."""
from dataclasses import dataclass, field
from enum import Enum


class RelType(str, Enum):
    CONTAINS        = "CONTAINS"         # Firmware → Binary
    HAS_FUNCTION    = "HAS_FUNCTION"     # Binary → Function
    CALLS           = "CALLS"            # Function → Function
    USES            = "USES"             # Function → API
    IMPORTS         = "IMPORTS"          # Binary → API
    SIMILAR_TO      = "SIMILAR_TO"       # Function → Function (weighted)
    ASSOCIATED_WITH = "ASSOCIATED_WITH"  # Function/API → CWE
    VULNERABLE_TO   = "VULNERABLE_TO"   # Function → VulnPattern
    MAPS_TO_CWE     = "MAPS_TO_CWE"     # VulnPattern → CWE
    HAS_CVE         = "HAS_CVE"          # Binary → CVE
    PARENT_OF       = "PARENT_OF"        # CWE → CWE (hierarchy)
    LINKS_TO        = "LINKS_TO"         # Library → API


@dataclass
class Relationship:
    from_id:    str
    to_id:      str
    rel_type:   RelType
    properties: dict = field(default_factory=dict)  # e.g. {"score": 0.89}
