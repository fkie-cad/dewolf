"""Module for finding variable relevant to switch"""
from typing import Optional

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, SwitchCase
from decompiler.structures.maps import DefMap, UseMap
from decompiler.structures.pseudo.expressions import Expression, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, IndirectBranch, Instruction
from decompiler.structures.pseudo.operations import Condition, OperationType, UnaryOperation
from decompiler.task import DecompilerTask


def is_dereference(expression: Expression) -> bool:
    return isinstance(expression, UnaryOperation) and expression.operation == OperationType.dereference


class DummySwitchVariableDetection(PipelineStage):
    name = "dummy-switch-variable-detection"

    def run(self, task: DecompilerTask):
        """
        - iterate through the basic blocks
        - on switch block found:
            if switch block has only one conditional block predecessor:
                find the variable common between first switch block instruction and condition in conditional predecessor
                and substitute the jump variable with the common variable;
                jump table offset calculations become then the dead code and will be removed during
                the dead code elimination stage

        Dummy method won't work if the first instruction in switch basic block is some dead code or
        non-relevant to jump table offset calculation.
        """
        for basic_block in task.graph.nodes:
            if not task.graph.is_switch_node(basic_block) or not (
                predecessor := self._get_conditional_predecessor(task.graph, basic_block)
            ):
                continue

            first_instruction = basic_block.instructions[0]
            switch_related_jump: IndirectBranch = basic_block.instructions[-1]
            # it can later be an expression, but at this stage we expect a variable
            jump_variable: Variable = switch_related_jump.expression
            condition: Branch = predecessor.instructions[-1]
            if common_variable := self._get_shared_variable(condition, first_instruction):
                switch_related_jump.substitute(jump_variable, common_variable)

    def _get_conditional_predecessor(self, cfg: ControlFlowGraph, basic_block: BasicBlock) -> Optional[BasicBlock]:
        """
        Basic block has conditional predecessor if it has the only predecessor which is conditional node

        :param basic_block: basic block for which we are trying to get the parent
        :return: conditional parent if there is one otherwise None
        """
        predecessors = tuple(cfg.get_predecessors(basic_block))
        if len(predecessors) == 1:
            predecessor = predecessors[0]
            if cfg.is_conditional_node(predecessor):
                return predecessor

    @staticmethod
    def _get_shared_variable(instruction_1: Instruction, instruction_2: Instruction) -> Optional[Variable]:
        """Returns a variable being used by both instructions if they have only one variable in common"""
        shared_variables = set(instruction_1.requirements).intersection(set(instruction_2.requirements))
        if len(shared_variables) == 1:
            return shared_variables.pop()


class BackwardSliceSwitchVariableDetection(PipelineStage):
    name = "backward-slice-switch-variable-detection"

    def __init__(self):
        self._def_map: DefMap
        self._use_map: UseMap
        self._dereferences_used_in_branches: set

    def run(self, task: DecompilerTask):
        """
        Replace switch variable containing offset calculations with a "cleaner" predecessor.
        Jump table offset calculations become then the dead code and will be removed during the dead code elimination stage.
        - iterate through the basic blocks
        - on switch block found:
            - track the variable in indirect jump backwards until it matches a replacement criterion:
                a) defined in copy assignment Var1 = Var2
                b) is used in an Assignment with RHS being Condition solely requiring `variable`
                c) is used in Branch with single requirement
                d) if any predecessors of `variable` are used as dereferences in branches
        Overcomes issues with dummy heuristic.
        """
        self._init_map(task.graph)
        for switch_block in {edge.source for edge in task.graph.edges if isinstance(edge, SwitchCase)}:
            self._handle_switch_block(switch_block)

    def _init_map(self, cfg: ControlFlowGraph):
        """Init the def and use maps on the given cfg-"""
        self._use_map, self._def_map, self._dereferences_used_in_branches = UseMap(), DefMap(), set()
        for instruction in cfg.instructions:
            self._def_map.add(instruction)
            self._use_map.add(instruction)
            if isinstance(instruction, Branch) and not instruction.requirements:
                new_expressions = {expr for expr in instruction.condition if is_dereference(expr)}
                self._dereferences_used_in_branches.update(new_expressions)

    def _handle_switch_block(self, basic_block: BasicBlock):
        """Handle the given switch block, rendering jump table calculations dead code."""
        switch_instruction = basic_block.instructions[-1]
        switch_expression = self.find_switch_expression(switch_instruction)
        switch_instruction.substitute(switch_instruction.expression, switch_expression)

    def find_switch_expression(self, switch_instruction: Instruction):
        """Try to deduce the variable utilized for the switch instruction."""
        traced_variable = (
            switch_instruction.expression.requirements[0] if switch_instruction.expression.requirements else switch_instruction.expression
        )
        for variable in self._backwardslice(traced_variable):
            if self._is_bounds_checked(variable):
                return variable
        raise ValueError("No switch variable candidate found.")

    def _is_used_in_condition_assignment(self, value: Variable):
        """
        Check if `value` is used in an Assignment with RHS being Condition solely requiring `value`
        """
        for usage in self._use_map.get(value):
            if isinstance(usage, Assignment) and isinstance(usage.value, Condition) and usage.requirements == [value]:
                return True
        return False

    def _is_used_in_branch(self, value: Variable):
        """
        Check if `value` is used in Branch solely requiring `value`
        """
        for usage in self._use_map.get(value):
            if isinstance(usage, Branch) and usage.requirements == [value]:
                return True
        return False

    def _is_predecessor_dereferenced_in_branch(self, value: Variable) -> bool:
        """
        Check if any predecessors of `value` are used as dereferences in branches.
        """
        if definition := self._def_map.get(value):
            return (
                any(exp in self._dereferences_used_in_branches for exp in definition.value)
                or definition.value in self._dereferences_used_in_branches
            )
        return False

    def _is_copy_assigned(self, value: Variable) -> bool:
        """
        Check if variable is defined in copy assignment of the form Var1 = Var2.
        """
        if definition := self._def_map.get(value):
            return isinstance(definition.value, Variable)
        return False

    def _is_bounds_checked(self, value: Variable) -> bool:
        """
        Check if variable can be used in switch expression.
        """
        return any(
            [
                self._is_copy_assigned(value),
                self._is_used_in_condition_assignment(value),
                self._is_used_in_branch(value),
                self._is_predecessor_dereferenced_in_branch(value),
            ]
        )

    def _backwardslice(self, value: Variable):
        """Do a breadth-first search on variable predecessors."""
        visited = set()
        todo = [value]
        while todo and (current := todo.pop()):
            yield current
            visited.add(current)
            definition = self._def_map.get(current)
            if definition:
                todo.extend([requirement for requirement in definition.requirements if requirement not in visited])
