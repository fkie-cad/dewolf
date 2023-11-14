from typing import List

from decompiler.pipeline.controlflowanalysis.loop_utility_methods import (
    AstInstruction,
    _find_continuation_instruction,
    _get_variable_initialisation,
    _requirement_without_reinitialization,
    _single_defininition_reaches_node,
)
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import LoopNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import Assignment, Expression, Operation, Variable
from decompiler.task import DecompilerTask


class WhileLoopVariableRenamer:
    """Iterate over While-Loop Nodes and rename their counter variables to counter, counter1, ..."""

    def __init__(self, ast: AbstractSyntaxTree):
        self._ast = ast
        self._variable_counter: int = 0

    def rename(self):
        """
        Iterate over While-Loop Nodes and rename their counter variables to counter, counter1, ...

        Only rename counter variables that suffice the following conditions:
            -> any variable x is used in the loop condition
            -> variable x is set inside the loop body
            -> single definition of variable x reaches loop entry (x is initialized/used only once)
        """

        for loop_node in self._ast.get_while_loop_nodes_topological_order():
            if loop_node.is_endless_loop:
                continue
            for condition_var in loop_node.get_required_variables(self._ast.condition_map):
                if not (variable_init := _get_variable_initialisation(self._ast, condition_var)):
                    continue
                if not _find_continuation_instruction(self._ast, loop_node, condition_var, renaming=True):
                    continue
                if not _single_defininition_reaches_node(self._ast, variable_init, loop_node):
                    continue
                self._replace_variables(loop_node, variable_init)
                break

    def _replace_variables(self, loop_node: LoopNode, variable_init: AstInstruction):
        """
        Rename old variable usages to counter variable in:
            - variable initialization
            - condition/condition map
            - loop body
        Also add a copy instruction if the variable is used after the loop without reinitialization.
        """
        new_variable = Variable(self._get_variable_name(), variable_init.instruction.destination.type)
        self._ast.replace_variable_in_subtree(loop_node, variable_init.instruction.destination, new_variable)
        if _requirement_without_reinitialization(self._ast, loop_node, variable_init.instruction.destination):
            self._ast.add_instructions_after(loop_node, Assignment(variable_init.instruction.destination, new_variable))
        variable_init.node.replace_variable(variable_init.instruction.destination, new_variable)

    def _get_variable_name(self) -> str:
        variable_name = f"counter{self._variable_counter if self._variable_counter > 0 else ''}"
        self._variable_counter += 1
        return variable_name


class ForLoopVariableRenamer:
    """Iterate over ForLoopNodes and rename their variables to i, j, ..., i1, j1, ..."""

    def __init__(self, ast: AbstractSyntaxTree, candidates: list[str]):
        self._ast = ast
        self._iteration: int = 0
        self._variable_counter: int = -1
        self._candidates: list[str] = candidates

    def rename(self):
        """
        Iterate over ForLoopNodes and rename their variables to i, j, k, ...
        We skip renaming for loops that are not initialized in its declaration.
        """
        for loop_node in self._ast.get_for_loop_nodes_topological_order():
            if not isinstance(loop_node.declaration, Assignment):
                continue

            old_variable: Variable = self._get_variable_from_assignment(loop_node.declaration.destination)
            new_variable = Variable(self._get_variable_name(), old_variable.type, ssa_name=old_variable.ssa_name)
            self._ast.replace_variable_in_subtree(loop_node, old_variable, new_variable)

            if _requirement_without_reinitialization(self._ast, loop_node, old_variable):
                self._ast.add_instructions_after(loop_node, Assignment(old_variable, new_variable))

    def _get_variable_name(self) -> str:
        """Return variable names in the form of [i, j, ..., i1, j1, ...]"""
        self._variable_counter += 1
        if self._variable_counter >= len(self._candidates):
            self._variable_counter = 0
            self._iteration += 1
        return f"{self._candidates[self._variable_counter]}{self._iteration if self._iteration > 0 else ''}"

    def _get_variable_from_assignment(self, expr: Expression) -> Variable:
        if isinstance(expr, Variable):
            return expr
        if isinstance(expr, Operation) and len(expr.operands) == 1:
            return expr.operands[0]
        raise ValueError("Did not expect a Constant/Unknown/Operation with more then 1 operand as a ForLoop declaration")


class LoopNameGenerator(PipelineStage):
    """
    Stage which renames while/for-loops to custom names.
    """

    name = "loop-name-generator"

    def run(self, task: DecompilerTask):
        rename_while_loops: bool = task.options.getboolean("loop-name-generator.rename_while_loop_variables", fallback=False)
        for_loop_names: List[str] = task.options.getlist("loop-name-generator.for_loop_variable_names", fallback=[])

        if rename_while_loops:
            WhileLoopVariableRenamer(task._ast).rename()

        if for_loop_names:
            ForLoopVariableRenamer(task._ast, for_loop_names).rename()
