"""Module to handle Register pairs."""
from __future__ import annotations

from collections import namedtuple
from logging import info
from typing import Dict, List, Tuple

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.maps import DefMap, UseMap
from decompiler.structures.pseudo import Integer
from decompiler.structures.pseudo.expressions import Constant, RegisterPair, Variable
from decompiler.structures.pseudo.instructions import Assignment, GenericBranch, Instruction
from decompiler.structures.pseudo.operations import BinaryOperation, OperationType
from decompiler.task import DecompilerTask

DEFAULT_REGISTER_SIZE = 32
BYTE_SIZE = 8


class RegisterPairHandling(PipelineStage):
    """
    This preprocessing stage is responsible for transforming register pairs into variables,
    cause there is no register pair concept in C.
    """

    name = "register-pair-handling"
    instruction_location = namedtuple("InstructionLocation", ["basic_block", "index"])

    def __init__(self):
        self.cfg = None
        self._def_map = None
        self._use_map = None
        self._locations = None
        self._dominator_tree = None

    def run(self, task: DecompilerTask) -> None:
        """Run the task eliminating all register pairs from the given cfg."""
        self.cfg = task.graph
        self._def_map, self._use_map, self._locations = self._parse_cfg(self.cfg)
        self._dominator_tree = self.cfg.dominator_tree
        self._handle_register_pairs()

    @staticmethod
    def _parse_cfg(cfg: ControlFlowGraph) -> Tuple[DefMap, UseMap, Dict[Instruction, RegisterPairHandling.instruction_location]]:
        """
        Helper function generating a def map, a use map and remembering the locations of each instruction.

        Should be implemented as a part of the control flow graph someday.
        """
        def_map = DefMap()
        use_map = UseMap()
        locations = {}
        for basic_block in cfg:
            for index, instruction in enumerate(basic_block.instructions):
                def_map.add(instruction)
                use_map.add(instruction)
                locations[instruction] = RegisterPairHandling.instruction_location(basic_block, index)
        return def_map, use_map, locations

    def _handle_register_pairs(self) -> None:
        """
        Iterate all utilized register pairs, eliminating them with compound variables.

        For each utilized register pair, insert a definition if it is not defined or change its definition.
        Then, replace all usages of the register pair with the newly defined value.
        """
        handled_pairs = set()
        found_pairs: List[RegisterPair] = [
            variable for variable in self._def_map.defined_variables if isinstance(variable, RegisterPair)
        ] + [variable for variable in self._use_map.used_variables if isinstance(variable, RegisterPair)]
        for variable_postfix, register_pair in enumerate(found_pairs):
            if register_pair in handled_pairs:
                continue
            info(f"[{self.name}] eliminate register pair {str(register_pair)}")
            replacement_variable: Variable = self._get_replacement_variable(register_pair, variable_postfix)
            if definition := self._def_map.get(register_pair):
                definition_location = self._locations[definition]
                self._replace_definition_of_register_pair(definition_location.basic_block, definition, replacement_variable)
                self._update_locations(definition_location.basic_block)
            else:
                insert_location = self._find_definition_insert_location(
                    [self._locations[instruction] for instruction in self._use_map.get(register_pair)]
                )
                self._add_definition_for_replacement(insert_location, register_pair, replacement_variable)
                self._update_locations(insert_location.basic_block)
            self._replace_usages_of(register_pair, replacement_variable)
            handled_pairs.add(register_pair)

    def _update_locations(self, basic_block: BasicBlock):
        """Update the location directory's entries of the given basic block."""
        for index, instruction in enumerate(basic_block.instructions):
            self._locations[instruction] = RegisterPairHandling.instruction_location(basic_block, index)

    def _find_definition_insert_location(self, usage_locations: List[RegisterPairHandling.instruction_location]):
        """Find a location to insert a definition given a list of usage locations."""
        blocks = [location.basic_block for location in usage_locations]
        if len(set(blocks)) == 1:
            return min(usage_locations, key=lambda x: x.index)
        dominator_block = self._find_common_dominator(blocks)
        if dominator_block in blocks:
            return min([location for location in usage_locations if location.basic_block == dominator_block], key=lambda x: x.index)
        insertion_index = len(dominator_block.instructions)
        if isinstance(dominator_block.instructions[-1], GenericBranch):
            insertion_index -= 1
        return self.instruction_location(dominator_block, insertion_index)

    def _find_common_dominator(self, basic_blocks: List[BasicBlock]) -> BasicBlock:
        """Find a basic block dominating all blocks given."""
        dominator_guess = next(iter(basic_blocks))
        while dominator_guess:
            if self._is_dominator(dominator_guess, basic_blocks):
                return dominator_guess
            dominator_guess = next(iter(self._dominator_tree.get_predecessors(dominator_guess)), None)

    def _is_dominator(self, dominator_guess: BasicBlock, dominated_blocks: List[BasicBlock]) -> bool:
        """Check whether the given dominator candidate dominates the given basic blocks."""
        return all(self._dominator_tree.has_path(dominator_guess, basicblock) for basicblock in dominated_blocks)

    @staticmethod
    def _get_replacement_variable(register_pair: RegisterPair, counter) -> Variable:
        """Generate a replacement variable for the given register pair."""
        return Variable(f"loc_{counter}", register_pair.type, 0)

    def _replace_definition_of_register_pair(
        self, basic_block: BasicBlock, definition_of_register_pair: Assignment, replacement: Variable
    ) -> None:
        """Definition of register pair is replaced by definition of a variable of the corresponding size
        and definitions of lower and higher registers

        e.g.
        int64 x1:x2 = ...

        is replaced as following:

        int64 loc_n = ..
        int32 x2 = loc_n & 0xffffffff
        int32 x1 = loc_n >> size_in_bits(x1)
        """
        register_pair: RegisterPair = definition_of_register_pair.destination
        renamed_definition_of_register_pair = Assignment(replacement, definition_of_register_pair.value)
        lower_register_definition = Assignment(
            register_pair.low, self._get_lower_register_definition_value(replacement, register_pair.low.type.size)
        )
        higher_register_definition = Assignment(
            register_pair.high, self._get_higher_register_definition_value(replacement, register_pair.high.type.size)
        )
        basic_block.replace_instruction(
            definition_of_register_pair, [renamed_definition_of_register_pair, lower_register_definition, higher_register_definition]
        )
        self._locations[renamed_definition_of_register_pair] = self._locations[definition_of_register_pair]

    def _replace_usages_of(self, replacee: RegisterPair, replacement: Variable) -> None:
        """Replace all uses of register pair with the new variable"""
        for using_instruction in self._use_map.get(replacee):
            former_location = self._locations[using_instruction]
            using_instruction.substitute(replacee, replacement)
            self._locations[using_instruction] = former_location

    @staticmethod
    def _get_higher_register_definition_value(var: Variable, register_size_in_bits: int) -> BinaryOperation:
        """Mask higher register in register pair:
        higher_register = register_pair_variable >> register_size

        e.g.
        ... var_64_bit // represents x1:x2 of size 64 bits, x1 and x2 are 32 bits
        x1 = var_64_bit >> 32 = var_64_bit >> 0x20
        """
        return BinaryOperation(
            OperationType.right_shift, [var, Constant(register_size_in_bits, vartype=Integer(register_size_in_bits, False))]
        )

    @staticmethod
    def _get_lower_register_definition_value(var: Variable, register_size_in_bits: int) -> BinaryOperation:
        """Mask lower register in register pair:
        lower_register = register_pair_variable & 0x(fff...f)

        e.g.
        ... var_64_bit // represents x1:x2 of size 64 bits, x1 and x2 are 32 bits
        x2 = var_64_bit & 0xffffffff // 0xffffffff == 2**32-1
        """
        register_size_mask = 2**register_size_in_bits - 1
        return BinaryOperation(OperationType.bitwise_and, [var, Constant(register_size_mask, vartype=Integer(register_size_in_bits, True))])

    @staticmethod
    def _add_definition_for_replacement(
        location: RegisterPairHandling.instruction_location, register_pair: RegisterPair, replacement_variable: Variable
    ):
        """
        Add a definition for the replacement variable of the given register pair into the given basic block before the index at which the
        register pair is utilized. Easy.
        """
        assignment_of_replacement_variable = Assignment(
            replacement_variable,
            BinaryOperation(
                OperationType.plus,
                [
                    register_pair.low,
                    BinaryOperation(
                        OperationType.left_shift,
                        [
                            register_pair.high,
                            Constant(register_pair.low.type.size, vartype=Integer.uint8_t())
                        ]
                    )
                ],
            ),
        )
        location.basic_block.instructions.insert(location.index, assignment_of_replacement_variable)
