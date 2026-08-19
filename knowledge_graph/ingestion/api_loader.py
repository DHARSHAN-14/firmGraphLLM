"""CWE and known API loaders."""
import logging
from knowledge_graph.schema.nodes import CWENode, APINode
from knowledge_graph.schema.relationships import Relationship, RelType
log = logging.getLogger(__name__)

# ── CWE Loader ────────────────────────────────────────────────────────────────
def load_target_cwes(builder) -> None:
    """Load the 5 target CWEs (78,120,134,190,606) and their parent hierarchy."""
    from knowledge_graph.schema.cypher_setup import CWE_SEED, seed_cwe_data
    seed_cwe_data(builder._driver)
    log.info("Target CWEs loaded into KG")

# ── API Loader ────────────────────────────────────────────────────────────────
KNOWN_APIS = [
    # Sinks
    APINode("system",  "system",  "glibc", is_sink=True,  sink_params=[0],    cwe_associations=["CWE-78"]),
    APINode("execl",   "execl",   "glibc", is_sink=True,  sink_params=[0,1],  cwe_associations=["CWE-78"]),
    APINode("execv",   "execv",   "glibc", is_sink=True,  sink_params=[0,1],  cwe_associations=["CWE-78"]),
    APINode("execlp",  "execlp",  "glibc", is_sink=True,  sink_params=[0,1],  cwe_associations=["CWE-78"]),
    APINode("execvp",  "execvp",  "glibc", is_sink=True,  sink_params=[0,1],  cwe_associations=["CWE-78"]),
    APINode("popen",   "popen",   "glibc", is_sink=True,  sink_params=[0],    cwe_associations=["CWE-78"]),
    APINode("strcpy",  "strcpy",  "glibc", is_sink=True,  sink_params=[0,1],  cwe_associations=["CWE-120"]),
    APINode("strcat",  "strcat",  "glibc", is_sink=True,  sink_params=[0,1],  cwe_associations=["CWE-120"]),
    APINode("gets",    "gets",    "glibc", is_sink=True,  sink_params=[0],    cwe_associations=["CWE-120"]),
    APINode("memcpy",  "memcpy",  "glibc", is_sink=True,  sink_params=[0,1,2],cwe_associations=["CWE-120"]),
    APINode("sprintf", "sprintf", "glibc", is_sink=True,  sink_params=[0,1],  cwe_associations=["CWE-120","CWE-134"]),
    APINode("printf",  "printf",  "glibc", is_sink=True,  sink_params=[0],    cwe_associations=["CWE-134"]),
    APINode("fprintf", "fprintf", "glibc", is_sink=True,  sink_params=[1],    cwe_associations=["CWE-134"]),
    # Sources
    APINode("recv",     "recv",     "glibc", is_source=True, source_params=[1]),
    APINode("recvfrom", "recvfrom", "glibc", is_source=True, source_params=[1]),
    APINode("read",     "read",     "glibc", is_source=True, source_params=[1]),
    APINode("fgets",    "fgets",    "glibc", is_source=True, source_params=[0]),
    APINode("fscanf",   "fscanf",   "glibc", is_source=True, source_params=[2]),
    APINode("scanf",    "scanf",    "glibc", is_source=True, source_params=[1]),
    APINode("getenv",   "getenv",   "glibc", is_source=True, source_params=[-1]),
    APINode("SSL_read", "SSL_read", "libssl",is_source=True, source_params=[1]),
    APINode("BIO_read", "BIO_read", "libssl",is_source=True, source_params=[1]),
]

def load_known_apis(builder) -> None:
    """Load all known sink/source APIs into the KG with CWE associations."""
    for api in KNOWN_APIS:
        builder.add_api(api)
        for cwe_id in api.cwe_associations:
            builder.add_relationship(Relationship(api.id, cwe_id, RelType.ASSOCIATED_WITH))
    log.info(f"Loaded {len(KNOWN_APIS)} known API nodes into KG")
