"""
FirmGraph-LLM — Reverse Engineering & Static Analysis Package.
Phase 1: Binary Disassembly, Call Graph Extraction & Dangerous Flow Generation.
"""

from .functions.function_extractor import FunctionExtractor
from .call_graph.call_graph_builder import CallGraphBuilder
from .cfg.cfg import BasicBlock, ControlFlowGraph
from .ghidra.headless_decompile import GhidraDecompiler

__all__ = [
    "FunctionExtractor",
    "CallGraphBuilder",
    "BasicBlock",
    "ControlFlowGraph",
    "GhidraDecompiler",
]
