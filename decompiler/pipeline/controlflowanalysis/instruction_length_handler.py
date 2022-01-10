from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Optional, Union

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CodeNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Call,
    Constant,
    Expression,
    Instruction,
    ListOperation,
    Operation,
    OperationType,
    Return,
    Type,
    UnaryOperation,
    Variable,
)
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def _get_operands_of_complexity_greater_1(operation: Operation) -> Iterator[Expression]:
    for operand in operation.operands:
        if not isinstance(operand, (Constant, Variable)):
            yield operand


@dataclass
class ComplexityBounds:
    """Dataclass that stores information about the maximum allowed complexity of varíous instruction types."""

    assignment_instr: int = 0
    call_operation: int = 0
    return_instr: int = 0

    @classmethod
    def from_options(cls: ComplexityBounds, options: Options) -> ComplexityBounds:
        cls.assignment_instr = max(options.getint(f"instruction-length-handler.max_assignment_complexity"), 2)
        cls.call_operation = max(options.getint(f"instruction-length-handler.max_call_complexity"), 1)
        cls.return_instr = max(options.getint(f"instruction-length-handler.max_return_complexity"), 2)
        return cls


class Target:
    """Class in charge of holding information about the instruction being simplified and providing convenience methods."""

    def __init__(
        self,
        node: AbstractSyntaxTreeNode,
        instruction: Instruction,
        target_expression: Expression,
        target_complexity: int,
        assignment_complexity: int,
    ):
        self.node = node
        self.instruction = instruction
        self.target = target_expression
        self.target_complexity = target_complexity
        self._assignment_complexity = assignment_complexity
        self._sub_targets: List[Target] = []

    def exceeds_complexity_bounds(self) -> bool:
        """Check whether this target's complexity is above the defined target complexity."""
        return self.target.complexity > self.target_complexity

    def add_sub_target(self, instruction: Instruction, target: Expression):
        """Generates a Target from an instruction and its target expression, finally adding it to the list of sub targets."""
        self._sub_targets.append(
            Target(
                node=self.node,
                instruction=instruction,
                target_expression=target,
                target_complexity=self._assignment_complexity,
                assignment_complexity=self._assignment_complexity,
            )
        )

    def get_tmp_instructions(self) -> Iterator[Instruction]:
        """Yields all temporary instructions necessary to generate the simplified instruction."""
        for sub in self._all_subtargets():
            yield sub.instruction

    def _all_subtargets(self) -> Iterator[Target]:
        """Yields all subtargets of the current Target."""
        for subtarget in self._sub_targets:
            for nested_subtarget in subtarget._all_subtargets():
                yield nested_subtarget
            yield subtarget


class TargetSimplifier:
    """Class in charge of doing the actual simplifying."""

    def __init__(self):
        self._tmp_variable_index: int = 0

    def start_simplification(self, instruction_target: Target):
        """
        Start simplification process for a Target.
        After the target is simplified, all sub targets that may get generated will be simplified, too.

        :param instruction_target: unsimplified target
        """
        self.simplify_target(instruction_target)
        for subtarget in instruction_target._sub_targets:
            self.start_simplification(subtarget)

    def simplify_target(self, instruction_target: Target) -> None:
        """Handle the actual simplification of the Target by choosing an adequate simplfifier for the instruction type."""
        if not instruction_target.exceeds_complexity_bounds():
            return
        if isinstance(instruction_target.target, BinaryOperation):
            self._simplify_binary_operation(instruction_target)
        elif isinstance(instruction_target.target, UnaryOperation):
            self._simplify_unary_operation(instruction_target)
        elif isinstance(instruction_target.target, (ListOperation, Call)):
            self._simplify_operands(instruction_target)

    def _simplify_binary_operation(self, instruction_target: Target):
        """
        Simplifies BinaryOperations by replacing the largest operand with a temporary variable.
            1. if target complexity is 1 we need to substitute the whole operation
            2. if left operand complexity >= right operand complexity: substitute left operand
            3. if operation complexity is still too high, substitute right operand too
        """
        operation: BinaryOperation = instruction_target.target
        if instruction_target.target_complexity == 1:
            self._substitute_subexpression(instruction_target, operation)
        if operation.left.complexity >= operation.right.complexity:
            self._substitute_subexpression(instruction_target, operation.left)
        if operation.complexity > instruction_target.target_complexity:
            self._substitute_subexpression(instruction_target, operation.right)

    def _simplify_unary_operation(self, instruction_target: Target):
        """
        Simplifies UnaryOperations by replacing the expression with the only operand and then passing it to the appropriate handler,
        ignoring ArrayAccesses.
        """
        operation: UnaryOperation = instruction_target.target
        if not (operation.operation == OperationType.dereference and operation.array_info):
            instruction_target.target = operation.operand
            self.simplify_target(instruction_target)

    def _simplify_operands(self, instruction_target: Target):
        """
        Simplifies operands from Return or Call operations in the following way:
            - 1 operand, complexity = 1: substitute whole expression
            - 1 operand, complexity > 1: substitute subexpression
            - m operands, n complexity: substitute each operand until target complexity max(m, n) is reached
        """
        operation: Union[ListOperation, Call] = instruction_target.target
        numb_of_operands = len(operation.operands)

        if numb_of_operands == 1:
            if instruction_target.target_complexity == 1:
                self._substitute_subexpression(instruction_target, operation.operands[0])
            else:
                instruction_target.target = operation.operands[0]
                self.simplify_target(instruction_target)
        else:
            for operand in _get_operands_of_complexity_greater_1(operation):
                self._substitute_subexpression(instruction_target, operand)
                if not instruction_target.exceeds_complexity_bounds():
                    return

    def _substitute_subexpression(self, instruction_target: Target, replacee: Expression):
        """Substitutes replacee in instruction/expression and adds a sub target."""
        tmp_var = self._get_tmp_variable(replacee.type)
        instruction_target.add_sub_target(Assignment(tmp_var, replacee), replacee)
        instruction_target.target.substitute(replacee, tmp_var)

    def _get_tmp_variable(self, var_type: Type) -> Variable:
        tmp_var = Variable(f"tmp_{self._tmp_variable_index}", vartype=var_type)
        self._tmp_variable_index += 1
        return tmp_var


class TargetGenerator:
    """Iterate over AST and generate targets for instructions that exceed the defined complexity bounds."""

    def __init__(self, ast: AbstractSyntaxTree, bounds: ComplexityBounds):
        """
        :param ast: AbstractSyntaxTree for which InstructionTarges will be generated
        :param bounds: Targets will only be generated if instructions exceed complexities defined in bounds
        """
        self._ast = ast
        self._bounds = bounds

    def generate(self) -> Iterator[Target]:
        """Yield targets for instructions that exceed the defined complexity bounds."""
        for node in self._ast.get_code_nodes_topological_order():
            for simp_target in self._from_code_node(node):
                yield simp_target

    def _from_code_node(self, node: CodeNode) -> Target:
        """Yields a target for any instruction exceeding the defined complexity bounds."""
        for instruction in node.instructions:
            if isinstance(instruction, Assignment):
                max_complexity = self._bounds.call_operation if isinstance(instruction.value, Call) else self._bounds.assignment_instr
                if instruction.value.complexity > max_complexity:
                    yield Target(
                        node=node,
                        instruction=instruction,
                        target_expression=instruction.value,
                        target_complexity=max_complexity,
                        assignment_complexity=self._bounds.assignment_instr,
                    )
            elif isinstance(instruction, Return):
                max_complexity = self._bounds.return_instr
                if instruction.complexity > max_complexity:
                    yield Target(
                        node=node,
                        instruction=instruction,
                        target_expression=instruction.values,
                        target_complexity=max_complexity,
                        assignment_complexity=self._bounds.assignment_instr,
                    )


class InstructionLengthHandler(PipelineStage):
    """
    Reduce the length of Instructions to improve readability.

    We reduce the complexity of an instruction that exceeds a defined threshold, by splitting it into smaller parts until the
    desired complexity is reached.
    """

    name = "instruction-length-handler"

    def __init__(self):
        self._bounds: Optional[ComplexityBounds] = None

    def run(self, task: DecompilerTask):
        self._bounds = ComplexityBounds.from_options(task.options)
        target_generator = TargetGenerator(task.syntax_tree, self._bounds)
        target_simplifier = TargetSimplifier()
        for target in target_generator.generate():
            target_simplifier.start_simplification(target)
            self.substitute_in_node(target)

    @staticmethod
    def substitute_in_node(target: Target):
        """
        Identifies the instruction in its node and adds any intermediate instruction needed for the simplified version of this instruction.
        """
        if isinstance(target.node, CodeNode):
            target.node.insert_instruction_list_before(target.get_tmp_instructions(), target.instruction)
        else:
            raise Exception(f"inserting into {type(target.node)} is not implemented")
