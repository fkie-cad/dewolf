"""Module for handling compiler idioms that have already been marked in BinaryNinja"""
import logging
from dataclasses import dataclass
from typing import List, Optional

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.pseudo.expressions import Constant, Tag, Variable
from decompiler.structures.pseudo.instructions import Assignment, Instruction, Branch
from decompiler.structures.pseudo.operations import BinaryOperation, OperationType
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask


@dataclass
class TaggedIdiom:
    """Dataclass to represent a tagged Idiom with its position in the basic block"""

    pos_start: int
    pos_end: int
    tag: Tag


class CompilerIdiomHandling(PipelineStage):
    """
    The CompilerIdiomHandling replaces instructions that have been marked as compiler idioms in BinaryNinja by the respective high level instruction.
    Basically, for a consecutive sequence of instructions with the identical tag (starting with "compiler_idiom: "), the last instruction will be replaced.
    This stage itself does not recognize nor tag instructions as compiler idiom.

    See https://github.com/fkie-cad/dewolf-idioms for more details.
    """

    name = "compiler-idiom-handling"
    TAG_PREFIX = "compiler_idiom: "

    def run(self, task: DecompilerTask):
        for basic_block in task.graph:
            for tagged_idiom in self._find_tagged_idioms(basic_block.instructions):
                new_instruction = self._get_replacement_instruction(
                    basic_block.instructions, tagged_idiom.tag, tagged_idiom.pos_start, tagged_idiom.pos_end
                )
                if not new_instruction:
                    continue
                basic_block.replace_instruction(basic_block.instructions[tagged_idiom.pos_end], [new_instruction])

    def _find_tagged_idioms(self, instructions: List[Instruction]) -> List[TaggedIdiom]:
        """
        Iterate over a basic block and yield all tagged compiler idioms.
        Return their position in the given basic block and the corresponding tag.
        """
        result = []
        current_tag = None
        first_index_of_instruction_with_tag = None
        for index, instruction in enumerate(instructions):
            if tag := self._get_compiler_idiom_tag_from_instruction(instruction):
                if current_tag == tag:
                    continue
                elif current_tag is not None:
                    result.append(TaggedIdiom(first_index_of_instruction_with_tag, index - 1, current_tag))
                first_index_of_instruction_with_tag = index
                current_tag = tag
            elif current_tag is not None:
                result.append(TaggedIdiom(first_index_of_instruction_with_tag, index - 1, current_tag))
                first_index_of_instruction_with_tag = None
                current_tag = None
        if current_tag:
            result.append(TaggedIdiom(first_index_of_instruction_with_tag, len(instructions) - 1, current_tag))
        return result

    def _get_compiler_idiom_tag_from_instruction(self, instruction: Instruction) -> Optional[Tag]:
        """
        Get the compiler idiom tag from a given instruction.
        Only consider those tags that start with the prefix `compiler-idioms-`
        """
        if instruction.tags:
            for tag in instruction.tags:
                if tag.name.startswith(self.TAG_PREFIX):
                    return tag
        return None

    def _get_replacement_instruction(
        self, instructions: List[Instruction], tag: Tag, first_index: int, last_index: int
    ) -> Optional[Assignment]:
        """
        Create the assignment instruction to replace the compiler idiom with.
        Return None if no constant could be extracted from tag or unable to find dividend variable or last instruction is branch
        """
        var = self._get_variable_from_first_instruction(instructions[first_index], tag)
        const = self._get_constant_from_tag(tag)
        if not var or not const or isinstance(instructions[last_index], Branch):
            return None
        operation_type = self._get_operation_type_from_tag(tag)
        return Assignment(instructions[last_index].destination, BinaryOperation(operation_type, [var, const]))

    def _get_constant_from_tag(self, tag: Tag) -> Constant:
        """
        Create a Constant object from the tag data provided.
        """
        if (idiom_constant := tag.data.split(",")[1]) != "None":
            return Constant(int(idiom_constant), vartype=self._get_constant_type(tag))

    REGISTER_EQUIVALENTS = [
        ["rax", "eax"],
        ["rbx", "ebx"],
        ["rcx", "ecx"],
        ["rdx", "edx"],
        ["rsi", "esi"],
        ["rdi", "edi"],
        ["rbp", "ebp"],
        ["rsp", "esp"],
    ]

    def _get_equivalent_registers(self, register: str) -> List[str]:
        for equivalents in self.REGISTER_EQUIVALENTS:
            if register in equivalents:
                return equivalents
        return [register]

    def _get_variable_from_first_instruction(self, instruction: Instruction, tag: Tag) -> Variable:
        """
        We consider 2 cases:

        1) reg1_x = reg2_x; tag: dividend reg2, constant Y
        and
        2) reg1_x = reg2_x; tag: dividend reg1, constant Y

        In both cases it is a valid dividend, since idiom operates either on register itself (1) or on its copy (2)

        """
        registers = self._get_equivalent_registers(tag.data.split(",")[0])
        for variable in instruction.requirements:
            if any(variable.name.startswith(reg) for reg in registers):
                return variable
            else:
                if variable := self._get_copy_destination_variable(instruction, registers):
                    return variable
        logging.warning(f"Couldn't get the compiler idiom variable [{tag}] from the first instruction {instruction}")

    def _get_copy_destination_variable(self, instruction: Instruction, operand_registers: List[str]) -> Variable:
        """We check if copy destination (variable) contains dividend register name"""
        for variable in instruction.definitions:
            if any(variable.name.startswith(reg) for reg in operand_registers):
                if len(instruction.requirements) == 1:
                    return instruction.requirements[0]

    OPERATION_TYPES = {
        "multiplication": OperationType.multiply,
        "unsigned_multiplication": OperationType.multiply_us,
        "division": OperationType.divide,
        "division unsigned": OperationType.divide_us,
        "modulo": OperationType.modulo,
        "modulo unsigned": OperationType.modulo_us,
    }

    def _get_operation_type_from_tag(self, tag: Tag) -> OperationType:
        """
        Return the corresponding OperationType for the given tag type.
        """
        return self.OPERATION_TYPES[tag.name[len(self.TAG_PREFIX) :]]

    def _get_constant_type(self, tag: Tag) -> Integer:
        if tag.name[len(self.TAG_PREFIX) :].startswith("unsigned_"):
            return Integer.uint32_t()
        return Integer.int32_t()
