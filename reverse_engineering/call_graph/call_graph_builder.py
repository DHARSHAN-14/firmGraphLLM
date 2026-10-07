"""
reverse_engineering.call_graph.call_graph_builder
=================================================
Inter-procedural Call Graph & Dangerous Flow Builder.

Builds function caller-callee graphs and traces potential taint propagation paths
from input sources to dangerous sinks, producing DangerousFlow objects.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

from llm.reasoning.conversation import DangerousFlow, FunctionRecord

log = logging.getLogger(__name__)


class CallGraphBuilder:
    """Builds call graphs and extracts source-to-sink DangerousFlow candidates."""

    def __init__(self):
        # caller -> list of callees
        self.edges: dict[str, list[str]] = defaultdict(list)
        # function_name -> FunctionRecord
        self.functions: dict[str, FunctionRecord] = {}

    def add_function(self, record: FunctionRecord) -> None:
        self.functions[record.name] = record

    def add_call(self, caller: str, callee: str) -> None:
        if callee not in self.edges[caller]:
            self.edges[caller].append(callee)

    def find_paths_source_to_sink(
        self,
        source_name: str,
        sink_name: str,
        max_depth: int = 5,
    ) -> list[list[str]]:
        """Breadth-first search for paths between source_name and sink_name."""
        if source_name not in self.functions or sink_name not in self.functions:
            return []

        paths = []
        queue = deque([[source_name]])

        while queue:
            current_path = queue.popleft()
            if len(current_path) > max_depth:
                continue

            last_node = current_path[-1]
            if last_node == sink_name:
                paths.append(current_path)
                continue

            for neighbor in self.edges.get(last_node, []):
                if neighbor not in current_path:  # Avoid cycles
                    queue.append(current_path + [neighbor])

        return paths

    def build_dangerous_flows(self, binary_name: str) -> list[DangerousFlow]:
        """
        Identify all sources and sinks in the graph and construct
        DangerousFlow objects for any connecting paths.
        """
        sources = [f for f in self.functions.values() if f.is_source]
        sinks = [f for f in self.functions.values() if f.is_sink]

        flows: list[DangerousFlow] = []

        # If a single function contains both source and sink APIs
        for f in self.functions.values():
            if f.is_source and f.is_sink:
                flow_id = f"{binary_name}_{f.name}_self_flow"
                src_api = next((api for api in f.api_calls if api in {"recv", "read", "getenv"}), "source")
                sink_api = next((api for api in f.api_calls if api in {"system", "strcpy", "printf", "memcpy"}), "sink")
                flows.append(
                    DangerousFlow(
                        flow_id=flow_id,
                        binary_name=binary_name,
                        source_func=src_api,
                        source_param=f.source_param,
                        sink_func=sink_api,
                        sink_param=0,
                        expected_cwe="Unknown",
                        function_chain=[f],
                    )
                )

        # Multi-hop paths
        for src in sources:
            for snk in sinks:
                if src.name == snk.name:
                    continue
                paths = self.find_paths_source_to_sink(src.name, snk.name)
                for path in paths:
                    chain = [self.functions[name] for name in path if name in self.functions]
                    if chain:
                        flow_id = f"{binary_name}_{src.name}_to_{snk.name}"
                        flows.append(
                            DangerousFlow(
                                flow_id=flow_id,
                                binary_name=binary_name,
                                source_func=src.name,
                                source_param=src.source_param,
                                sink_func=snk.name,
                                sink_param=0,
                                expected_cwe="Unknown",
                                function_chain=chain,
                            )
                        )

        log.info(f"Generated {len(flows)} DangerousFlow candidates for {binary_name}")
        return flows
