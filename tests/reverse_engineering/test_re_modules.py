"""
Tests for reverse engineering and call graph modules.
"""

import pytest
from reverse_engineering.functions.function_extractor import FunctionExtractor
from reverse_engineering.call_graph.call_graph_builder import CallGraphBuilder
from reverse_engineering.cfg.cfg import BasicBlock, ControlFlowGraph


class TestReverseEngineeringModules:
    def test_function_extractor(self):
        fe = FunctionExtractor()
        code = """
        void process_packet(int sock) {
            char buf[100];
            recv(sock, buf, 100);
            system(buf);
        }
        """
        record = fe.extract_from_pseudocode("process_packet", code, binary_name="test_bin")
        assert record.name == "process_packet"
        assert record.is_source is True  # Contains recv
        assert record.is_sink is True    # Contains system
        assert "recv" in record.api_calls
        assert "system" in record.api_calls

    def test_call_graph_builder_paths(self):
        fe = FunctionExtractor()
        f_source = fe.extract_from_pseudocode("read_data", "void read_data() { recv(s, b, 10); }", is_source=True)
        f_mid = fe.extract_from_pseudocode("forward_data", "void forward_data() { do_work(); }")
        f_sink = fe.extract_from_pseudocode("exec_data", "void exec_data() { system(cmd); }", is_sink=True)

        cgb = CallGraphBuilder()
        cgb.add_function(f_source)
        cgb.add_function(f_mid)
        cgb.add_function(f_sink)

        cgb.add_call("read_data", "forward_data")
        cgb.add_call("forward_data", "exec_data")

        paths = cgb.find_paths_source_to_sink("read_data", "exec_data")
        assert len(paths) == 1
        assert paths[0] == ["read_data", "forward_data", "exec_data"]

        flows = cgb.build_dangerous_flows("binary_test")
        assert len(flows) >= 1
        assert flows[0].binary_name == "binary_test"
        assert len(flows[0].function_chain) == 3

    def test_control_flow_graph(self):
        cfg = ControlFlowGraph("test_func")
        bb1 = BasicBlock(id="bb1", start_address="0x1000", instructions=["mov eax, 1"])
        bb2 = BasicBlock(id="bb2", start_address="0x1005", instructions=["ret"])
        cfg.add_block(bb1)
        cfg.add_block(bb2)
        cfg.add_edge("bb1", "bb2")

        assert "bb2" in cfg.successors["bb1"]
        assert "bb1" in cfg.predecessors["bb2"]
