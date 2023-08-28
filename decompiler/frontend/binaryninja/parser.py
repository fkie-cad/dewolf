"""Implements the parser for the binaryninja frontend."""
from logging import info, warning
from typing import Dict, Iterator, List

from binaryninja import (
    BranchType,
    Function,
    MediumLevelILBasicBlock,
    MediumLevelILConstPtr,
    MediumLevelILInstruction,
    MediumLevelILJumpTo,
    RegisterValueType,
)
from decompiler.frontend.lifter import Lifter
from decompiler.frontend.parser import Parser
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, IndirectEdge, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo import Constant, Instruction


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

    def parse(self, function: Function) -> ControlFlowGraph:
        """Generate a cfg from the given function."""
        cfg = ControlFlowGraph()
        index_to_BasicBlock = dict()
        for basic_block in function.medium_level_il.ssa_form:
            index_to_BasicBlock[basic_block.index] = BasicBlock(basic_block.index, instructions=list(self._lift_instructions(basic_block)))
            cfg.add_node(index_to_BasicBlock[basic_block.index])
        for basic_block in function.medium_level_il.ssa_form:
            self._add_basic_block_edges(cfg, index_to_BasicBlock, basic_block)
        self._report_lifter_errors()
        return cfg

    def _add_basic_block_edges(self, cfg: ControlFlowGraph, vertices: dict, basic_block: MediumLevelILBasicBlock) -> None:
        """Add all outgoing edges of the given basic block to the given cfg."""
        if self._can_convert_single_outedge_to_unconditional(basic_block):
            vertices[basic_block.index].remove_instruction(-1)  # change block condition by removing last jump instruction
            # add unconditional edge:
            edge = basic_block.outgoing_edges[0]
            cfg.add_edge(UnconditionalEdge(vertices[edge.source.index], vertices[edge.target.index]))
        # check if the block ends with a switch statement
        elif lookup_table := self._get_lookup_table(basic_block):
            print("LOOKUP", [(hex(key), val) for key, val in lookup_table.items()])
            for edge in basic_block.outgoing_edges:
                # print(edge.target, [i for i in edge.target])
                try:
                    case_list = lookup_table[edge.target.source_block.start]
                except KeyError:
                    # fix lookup addresses
                    addresses_from_successor_instructions = set()
                    case_list = []
                    successor = edge.target
                    for i in successor:
                        # print(i, type(i), i.dest, i.dest.constant)
                        # print("i.dest", hex(i.dest))
                        # edge_address_mapping[(e.source.index, e.target.index)] = i.dest
                        addresses_from_successor_instructions.add(i.dest.constant)
                        if i.dest.constant in lookup_table:
                            print("found!!!", i.dest.constant, hex(i.dest.constant))
                            case_list = lookup_table[i.dest.constant]
                            print("new case list", case_list)
                            # assert False, "always assing last one is wrong"
                            # print("case list", case_list)
                    # breakpoint() 
                    print("intersection", set(lookup_table.keys()).intersection(addresses_from_successor_instructions))
                    print("lookup values", lookup_table.values())
                print("add edge", case_list)
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

    def _get_successors(self, basic_block: MediumLevelILBasicBlock):
        successors = set()
        for edge in basic_block.outgoing_edges:
            successors.add(edge.target)
        return successors

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

    def _is_address_in_range(self, block: MediumLevelILBasicBlock, address: int):
        if not block.function:
            raise ValueError("can not get block.function")
        for r in block.function.address_ranges:
            if r.start <= address <= r.end:
                return True
        return False

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
        # i = block[-1]
        # breakpoint()
        if possible_values.type != RegisterValueType.LookupTableValue:
            warning(f"Found indirect jump without lookup table at {block.source_block.end}")
            return self._craft_lookup_table(block)
        # reverse the returned mapping so we can work more efficiently
        print("poss", possible_values)
        print("poss values", possible_values.mapping.values())
        lookup: Dict[int, List[Constant]] = {target: [] for target in set(possible_values.mapping.values())}
        for value, target in possible_values.mapping.items():
            if not self._is_address_in_range(block, target):
                # check if would raise key error. then fix by tailcall dest
                print("NOT IN RANGE", hex(target))
            lookup[target] += [Constant(value)]
        return lookup

    def _lift_instructions(self, basic_block: MediumLevelILBasicBlock) -> Iterator[Instruction]:
        """Yield the lifted versions of all instructions in the given basic block."""
        for instruction in basic_block:
            if lifted_instruction := self._lifter.lift(instruction):
                # Check that we don't lift operations without effects
                if not isinstance(lifted_instruction, Instruction):
                    self._unlifted_instructions.append(instruction)
                    continue
                yield lifted_instruction

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
