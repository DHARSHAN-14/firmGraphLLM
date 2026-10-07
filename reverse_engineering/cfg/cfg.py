"""
reverse_engineering.cfg.cfg
===========================
Intra-procedural Control Flow Graph (CFG) Representation.

Defines BasicBlock nodes and directional branch edges for analyzing
conditional branches and sanitization checks within a decompiled function.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BasicBlock:
    id: str
    start_address: str
    instructions: list[str] = field(default_factory=list)
    has_sanitization_check: bool = False


class ControlFlowGraph:
    """Directed graph of basic blocks within a single function."""

    def __init__(self, function_name: str):
        self.function_name = function_name
        self.blocks: dict[str, BasicBlock] = {}
        self.successors: dict[str, list[str]] = {}
        self.predecessors: dict[str, list[str]] = {}

    def add_block(self, block: BasicBlock) -> None:
        self.blocks[block.id] = block
        if block.id not in self.successors:
            self.successors[block.id] = []
        if block.id not in self.predecessors:
            self.predecessors[block.id] = []

    def add_edge(self, from_id: str, to_id: str) -> None:
        if from_id in self.blocks and to_id in self.blocks:
            if to_id not in self.successors[from_id]:
                self.successors[from_id].append(to_id)
            if from_id not in self.predecessors[to_id]:
                self.predecessors[to_id].append(from_id)
