"""
FirmGraph-LLM — Tests for Knowledge Graph Schema & Node Construction
"""
import pytest
from knowledge_graph.schema.nodes import (
    FirmwareNode,
    BinaryNode,
    FunctionNode,
    APINode,
    CWENode,
    VulnPatternNode,
)
from knowledge_graph.schema.relationships import Relationship, RelType


class TestGraphSchema:
    def test_node_creation(self):
        f = FirmwareNode(id="fw_1", vendor="vendor_a", product="prod_1", version="1.0", architecture="arm")
        assert f.id == "fw_1"
        assert f.vendor == "vendor_a"
        assert f.architecture == "arm"

        b = BinaryNode(id="bin_1", name="httpd", firmware_id="fw_1")
        assert b.name == "httpd"

        c = CWENode(id="CWE-78", name="Command Injection", severity="High")
        assert c.id == "CWE-78"

    def test_relationship_creation(self):
        r = Relationship("bin_1", "fw_1", RelType.CONTAINS)
        assert r.rel_type == RelType.CONTAINS
        assert r.from_id == "bin_1"
        assert r.to_id == "fw_1"
