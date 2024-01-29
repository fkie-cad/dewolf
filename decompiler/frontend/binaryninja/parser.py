"""Implements the parser for the binaryninja frontend."""

from logging import info, warning
from typing import Dict, Iterator, List, Tuple

from binaryninja import (
    BasicBlockEdge,
    BranchType,
    Function,
    MediumLevelILBasicBlock,
    MediumLevelILConstPtr,
    MediumLevelILInstruction,
    MediumLevelILJump,
    MediumLevelILJumpTo,
    MediumLevelILTailcallSsa,
    RegisterValueType,
)
from decompiler.frontend.lifter import Lifter
from decompiler.frontend.parser import Parser
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, IndirectEdge, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo import Constant, Instruction
from decompiler.structures.pseudo.complextypes import ComplexTypeMap
from decompiler.structures.pseudo.instructions import Comment


class BinaryninjaParser(Parser):
    """Parser for binary ninja functions in ssa-format."""

    EDGES = {
        BranchType.UnconditionalBranch: UnconditionalEdge,
        BranchType.FalseBranch: FalseCase,
        BranchType.TrueBranch: TrueCase,
        BranchType.IndirectBranch: IndirectEdge,
    }
    ASSEMBLER_TOKEN = {"int3", "lfence", "rfence", "syscall"}

    def __init__(self, lifter: Lifter, report_threshold: int = 3):
        """Set up the parser, providing a binaryninja lifter to use."""
        self._lifter = lifter
        self._unlifted_instructions: List[MediumLevelILInstruction] = []
        self._report_threshold = int(report_threshold)
        self._complex_types = None

    def parse(self, function: Function) -> ControlFlowGraph:
        """Generate a cfg from the given function."""
        cfg = ControlFlowGraph()
        index_to_BasicBlock = dict()
        for basic_block in function.medium_level_il.ssa_form:
            index_to_BasicBlock[basic_block.index] = BasicBlock(basic_block.index, instructions=list(self._lift_instructions(basic_block)))
            cfg.add_node(index_to_BasicBlock[basic_block.index])
        for basic_block in function.medium_level_il.ssa_form:
            self._add_basic_block_edges(cfg, index_to_BasicBlock, basic_block)
        self._complex_types = self._lifter.complex_types
        self._report_lifter_errors()
        return cfg

    @property
    def complex_types(self) -> ComplexTypeMap:
        """Return complex type map for the given function."""
        return self._complex_types

    def _recover_switch_edge_cases(self, edge: BasicBlockEdge, lookup_table: dict):
        """
        If edge.target.source_block.start address is not in lookup table,
        try to recover matching address by inspecting addresses used in edge.target.
        Return matched case list for edge.target.
        """
        possible_matches = set()
        for instruction in edge.target:
            match instruction:
                # tail calls destroy edge address mapping
                case MediumLevelILTailcallSsa(dest=MediumLevelILConstPtr()):
                    possible_matches.add(instruction.dest.constant)
        # we have found exactly one address and that address is used in lookup table.
        if len(possible_matches) == 1 and possible_matches & set(lookup_table):
            return lookup_table[possible_matches.pop()]  # return cases for matched address
        raise KeyError("Can not recover address used in lookup table")

    def _add_basic_block_edges(self, cfg: ControlFlowGraph, vertices: dict, basic_block: MediumLevelILBasicBlock) -> None:
        """Add all outgoing edges of the given basic block to the given cfg."""
        if self._can_convert_single_outedge_to_unconditional(basic_block):
            vertices[basic_block.index].remove_instruction(-1)  # change block condition by removing last jump instruction
            # add unconditional edge:
            edge = basic_block.outgoing_edges[0]
            cfg.add_edge(UnconditionalEdge(vertices[edge.source.index], vertices[edge.target.index]))
        # check if the block ends with a switch statement
        elif lookup_table := self._get_lookup_table(basic_block):
            for edge in basic_block.outgoing_edges:
                if edge.target.source_block.start not in lookup_table:
                    case_list = self._recover_switch_edge_cases(edge, lookup_table)
                else:
                    case_list = lookup_table[edge.target.source_block.start]
                cfg.add_edge(
                    SwitchCase(
                        vertices[edge.source.index],
                        vertices[edge.target.index],
                        case_list,
                    )
                )
        else:
            for edge in basic_block.outgoing_edges:
                edgeclass = self.EDGES.get(edge.type)
                cfg.add_edge(edgeclass(vertices[edge.source.index], vertices[edge.target.index]))

    def _can_convert_single_outedge_to_unconditional(self, block: MediumLevelILBasicBlock) -> bool:
        """
        Check if last block instruction is of type `jmp const ptr`
        """
        if len(block.outgoing_edges) != 1 or not len(block):
            return False
        out_edge = block.outgoing_edges[0]
        jmp_instr = block[-1]
        return (
            isinstance(jmp_instr, MediumLevelILJumpTo)
            and isinstance(jmp_instr.dest, MediumLevelILConstPtr)
            and jmp_instr.dest.constant == out_edge.target.source_block.start
        )

    def _craft_lookup_table(self, block: MediumLevelILBasicBlock) -> Dict[int, List[Constant]]:
        """
        Build a lookup table for use in SwitchCase edges.
        """
        return {edge.target.source_block.start: [Constant(i)] for i, edge in enumerate(block.outgoing_edges)}

    def _get_lookup_table(self, block: MediumLevelILBasicBlock) -> Dict[int, List[Constant]]:
        """Extract the lookup table from ninja to annotate the edges."""
        # check if the last instruction of the block is a jump
        if not len(block) or not isinstance(block[-1], MediumLevelILJumpTo):
            return {}
        # check if binaryninja found a lookup table here
        possible_values = block[-1].dest.possible_values
        if possible_values.type != RegisterValueType.LookupTableValue:
            warning(f"Found indirect jump without lookup table at {block.source_block.end}")
            return self._craft_lookup_table(block)
        # reverse the returned mapping so we can work more efficiently
        lookup: Dict[int, List[Constant]] = {target: [] for target in set(possible_values.mapping.values())}
        for value, target in possible_values.mapping.items():
            lookup[target] += [Constant(value)]
        return lookup

    def _has_undetermined_jump(self, basic_block: MediumLevelILBasicBlock) -> bool:
        """Return True if basic-block is ending in a jump and has no outgoing edges"""
        return bool(len(basic_block) and isinstance(basic_block[-1], MediumLevelILJump) and not basic_block.outgoing_edges)

    def _lift_instructions(self, basic_block: MediumLevelILBasicBlock) -> Iterator[Instruction]:
        """Yield the lifted versions of all instructions in the given basic block."""
        for instruction in basic_block:
            if lifted_instruction := self._lifter.lift(instruction):
                # Check that we don't lift operations without effects
                if not isinstance(lifted_instruction, Instruction):
                    self._unlifted_instructions.append(instruction)
                    continue
                yield lifted_instruction
        if self._has_undetermined_jump(basic_block):
            yield Comment("jump -> undetermined")

    def _report_lifter_errors(self):
        """Report instructions which could not be lifted and reset their counter."""
        if not self._unlifted_instructions:
            return
        warning(f"[{self.__class__.__name__}] Could not lift {len(self._unlifted_instructions)} instructions.")
        if len(self._unlifted_instructions) <= self._report_threshold:
            for instruction in self._unlifted_instructions:
                info(f"[{self.__class__.__name__}]{hex(instruction.address)}: {instruction} ({str(instruction.operation)})")
        else:
            # if we got more unlifted expressions than we want to print individually, check for interesting tokens
            for instruction in self._unlifted_instructions:
                unlifted = str(instruction)
                for token in self.ASSEMBLER_TOKEN:
                    if token in unlifted:
                        info(f"[{self.__class__.__name__}]{hex(instruction.address)}: {instruction} ({str(instruction.operation)})")
                        break
        self._unlifted_instructions = []
