"""Module implementing various readbility based refinements."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Union

from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    DoWhileLoopNode,
    ForLoopNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    WhileLoopNode,
)
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import Assignment, Condition, Variable
from decompiler.structures.visitors.assignment_visitor import AssignmentVisitor
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def _is_single_instruction_loop_node(loop_node: LoopNode) -> bool:
    """
    Check if the loop body contains only one instruction.

    :param loop_node: LoopNode with a body
    :return: True if body contains only one instruction else False
    """
    body: AbstractSyntaxTreeNode = loop_node.body
    if isinstance(body, CodeNode):
        return len(body.instructions) == 1
    if isinstance(body, LoopNode):
        return _is_single_instruction_loop_node(body)
    if isinstance(body, (SeqNode, SwitchNode)):
        return False
    return False


def _has_deep_requirement(condition_map: Dict[LogicCondition, Condition], node: AbstractSyntaxTreeNode, variable: Variable) -> bool:
    """
    Check if a variable is required in a node or any of its children.

    :param condition_map: logic condition to condition mapping
    :param node: start node
    :param variable: requirement to search for
    :return: True if a requirement was found, else False
    """
    if node is None:
        return False

    if variable in node.get_required_variables(condition_map):
        return True

    if isinstance(node, (SeqNode, SwitchNode, CaseNode)):
        return any([_has_deep_requirement(condition_map, child, variable) for child in node.children])
    elif isinstance(node, ConditionNode):
        return any(
            [
                _has_deep_requirement(condition_map, node.true_branch_child, variable),
                _has_deep_requirement(condition_map, node.false_branch_child, variable),
            ]
        )
    elif isinstance(node, LoopNode):
        return _has_deep_requirement(condition_map, node.body, variable)


def _get_last_definition_index_of(node: CodeNode, variable: Variable) -> int:
    """
    Iterate over CodeNode returning the index of last assignment to variable.

    :param node: node in which to search for last definition of variable
    :param variable: check if definition contains this variable
    :return: index of last definition or -1 if not found
    """
    candidate = -1
    for position, instr in enumerate(node.instructions):
        if variable in instr.definitions:
            candidate = position
    return candidate


def _get_last_requirement_index_of(node: CodeNode, variable: Variable) -> int:
    """
    Iterate over CodeNode returning the index of last instruction using variable.

    :param node: node in which to search for last requirement of variable
    :param variable: check if requirements contains this variable
    :return: index of last definition or -1 if not found
    """
    candidate = -1
    for position, instr in enumerate(node.instructions):
        if variable in instr.requirements:
            candidate = position
    return candidate


def _find_continuation_instruction(
    ast: AbstractSyntaxTree, node: AbstractSyntaxTreeNode, variable: Variable, renaming: bool = False
) -> Optional[AstInstruction]:
    """
    Find a valid continuation instruction for a given variable inside a node. A valid continuation instruction defines the variable without
    having requirements in later instructions.

    If we only want to rename the continuation instruction (instead of converting a while to a for-loop) we can additionally look at
    switch / case nodes.

    :param node: node in which to search for last definition
    :param variable: search instruction defining variable
    :param renaming: continuation assignment for renaming purposes only
    :return: AstInstruction if a definition without later requirement was found, else None
    """
    iter_types = (SeqNode, SwitchNode) if renaming else SeqNode
    if isinstance(node, iter_types):
        for child in node.children[::-1]:
            if instruction := _find_continuation_instruction(ast, child, variable, renaming):
                return instruction
            elif _has_deep_requirement(ast.condition_map, child, variable):
                return None
    elif renaming and isinstance(node, CaseNode):
        return _find_continuation_instruction(ast, node.child, variable, renaming)
    elif isinstance(node, LoopNode):
        return _find_continuation_instruction(ast, node.body, variable, renaming)
    elif isinstance(node, CodeNode):
        last_req_index = _get_last_requirement_index_of(node, variable)
        last_def_index = _get_last_definition_index_of(node, variable)
        if last_req_index <= last_def_index != -1:
            return AstInstruction(node.instructions[last_def_index], last_def_index, node)


def _get_variable_initialisation(ast: AbstractSyntaxTree, variable: Variable) -> Optional[AstInstruction]:
    """
    Iterates over CodeNodes returning the first definition of variable.

    :param ast: AbstractSyntaxTree to search in
    :param variable: find initialization of this variable
    """
    for code_node in ast.get_code_nodes_topological_order():
        for position, instruction in enumerate(code_node.instructions):
            if variable in instruction.definitions:
                return AstInstruction(instruction, position, code_node)


def _single_defininition_reaches_node(ast: AbstractSyntaxTree, variable_init: AstInstruction, target_node: AbstractSyntaxTreeNode) -> bool:
    """
    Check if a variable initialisation is redefined or used before target node.

    If we did not find the target node on the way down we still can assume there was no redefinition or usage.

    :param ast: AbstractSyntaxTree to search in
    :param variable_init: AstInstruction containing the first variable initialisation
    :param target_node: Search for redefinition or usages until this node is reached
    """
    for ast_node in ast.get_reachable_nodes_pre_order(variable_init.node):
        if ast_node is target_node:
            return True

        defined_vars = list(ast_node.get_defined_variables(ast.condition_map))
        required_vars = list(ast_node.get_required_variables(ast.condition_map))
        used_variables = defined_vars + required_vars

        if ast_node is variable_init.node:
            if used_variables.count(variable_init.instruction.destination) > 1:
                return False
        elif variable_init.instruction.destination in used_variables:
            return False
    return True


def _initialization_reaches_loop_node(init_node: AbstractSyntaxTreeNode, usage_node: AbstractSyntaxTreeNode) -> bool:
    """
    Check if init node always reaches the usage node

    This is not the case if:
        - nodes are separated by a LoopNode
        - init-nodes parent is not a sequence node or not on a path from root to usage-node (only initialized under certain conditions)

    :param init_node: node where initialization takes place
    :param usage_node: node that is potentially inside a LoopNode
    :return: True if init and usage node are separated by a LoopNode else False
    """
    init_parent = init_node.parent
    iter_parent = usage_node.parent
    if not isinstance(init_parent, SeqNode):
        return False
    while iter_parent is not init_parent:
        if isinstance(iter_parent, LoopNode):
            return False
        iter_parent = iter_parent.parent
        if iter_parent is None:
            return False
    return True


def _requirement_without_reinitialization(ast: AbstractSyntaxTree, node: AbstractSyntaxTreeNode, variable: Variable) -> bool:
    """
    Check if a variable is used without prior initialization starting at a given node.
    Edge case: definition and requirement in same instruction

    :param ast:
    :param node:
    :param variable:
    :return: True if has requirement that is not prior reinitialized else False
    """

    for ast_node in ast.get_reachable_nodes_pre_order(node):
        assignment_visitor = AssignmentVisitor()
        assignment_visitor.visit(ast_node)
        for assignment in assignment_visitor.assignments:
            if variable in assignment.definitions and variable not in assignment.requirements:
                return False
            elif variable in assignment.definitions and variable in assignment.requirements:
                return True
            elif variable in assignment.requirements:
                return True


def _get_potential_guarded_do_while_loops(ast: AbstractSyntaxTree) -> tuple(Union[DoWhileLoopNode, WhileLoopNode], ConditionNode):
    for loop_node in list(ast.get_loop_nodes_post_order()):
        if isinstance(loop_node, DoWhileLoopNode) and isinstance(loop_node.parent.parent, ConditionNode):
            yield loop_node, loop_node.parent.parent


def remove_guarded_do_while(ast: AbstractSyntaxTree):
    """ Removes a if statement which guards a do-while loop/while loop when:
            -> there is nothing in between the if-node and the do-while-node/while-node 
            -> the if-node has only one branch (true branch)
            -> the condition of the branch is the same as the condition of the do-while-node
        Replacement is a WhileLoop, otherwise the control flow would not be correct
    """
    for do_while_node, condition_node in _get_potential_guarded_do_while_loops(ast):
        if condition_node.false_branch:
            continue

        if do_while_node.condition.is_equal_to(condition_node.condition):
            ast.replace_condition_node_by_single_branch(condition_node)
            ast.substitute_loop_node(do_while_node, WhileLoopNode(do_while_node.condition, do_while_node.reaching_condition))


@dataclass
class AstInstruction:
    instruction: Assignment
    position: int
    node: CodeNode


class WhileLoopReplacer:
    """Convert WhileLoopNodes to ForLoopNodes depending on the configuration.
        -> keep_empty_for_loops will keep empty for-loops in the code
        -> force_for_loops will transform every while-loop into a for-loop, worst case with empty declaration/modification statement
        -> forbidden_condition_types_in_simple_for_loops will not transform trivial for-loop candidates (with only one condition) into for-loops
            if the operator matches one of the forbidden operator list
        -> max_condition_complexity_for_loop_recovery will transform for-loop candidates only into for-loops if the condition complexity is 
            less/equal then the threshold
        -> max_modification_complexity_for_loop_recovery will transform for-loop candidates only into for-loops if the modification complexity is 
            less/equal then the threshold
    """

    def __init__(self, ast: AbstractSyntaxTree, options: Options):
        self._ast = ast
        self._keep_empty_for_loops = options.getboolean("readability-based-refinement.keep_empty_for_loops", fallback=False)
        self._hide_non_init_decl = options.getboolean("readability-based-refinement.hide_non_initializing_declaration", fallback=False)
        self._force_for_loops = options.getboolean("readability-based-refinement.force_for_loops", fallback=False)
        self._forbidden_condition_types = options.getlist("readability-based-refinement.forbidden_condition_types_in_simple_for_loops", fallback=[])
        self._condition_max_complexity = options.getint("readability-based-refinement.max_condition_complexity_for_loop_recovery", fallback=100)
        self._modification_max_complexity = options.getint("readability-based-refinement.max_modification_complexity_for_loop_recovery", fallback=100)

    def run(self):
        """For each WhileLoop in AST check the following conditions:
            -> any variable in loop condition has a valid continuation instruction in loop body
            -> variable is initialized
            -> loop condition complexity < condition complexity 
            -> possible modification complexity < modification complexity
            -> if condition is only a symbol: check condition type for allowed one
        
        If 'force_for_loops' is enabled, the complexity options are ignored and every while loop after the 
        initial transformation will be forced into a for loop with an empty declaration/modification      
        """

        for loop_node in list(self._ast.get_while_loop_nodes_topological_order()):
            if loop_node.is_endless_loop or (not self._keep_empty_for_loops and _is_single_instruction_loop_node(loop_node)) \
            or self._invalid_simple_for_loop_condition_type(loop_node.condition):
                continue

            if not self._force_for_loops and loop_node.condition.get_complexity(self._ast.condition_map) > self._condition_max_complexity:
                continue

            for condition_variable in loop_node.get_required_variables(self._ast.condition_map):
                if not (continuation := _find_continuation_instruction(self._ast, loop_node, condition_variable)):
                    continue
                if not (variable_init := _get_variable_initialisation(self._ast, condition_variable)):
                    continue
                if not self._force_for_loops and continuation.instruction.complexity > self._modification_max_complexity:
                    continue
                self._replace_with_for_loop(loop_node, continuation, variable_init)
                break

        if self._force_for_loops:
            for loop_node in list(self._ast.get_while_loop_nodes_topological_order()):
                self._ast.substitute_loop_node(
                    loop_node,
                    ForLoopNode(
                    declaration=None,
                    condition=loop_node.condition,
                    modification=None,
                    reaching_condition=loop_node.reaching_condition,
                    )
                )

    def _replace_with_for_loop(self, loop_node: WhileLoopNode, continuation: AstInstruction, init: AstInstruction):
        """
        Replaces a given WhileLoopNode with a ForLoopNode.

        If variable is not required between initialization and loop entry it will be moved into the loop declaration. And the continuation
        instruction is moved from the loop body to the loop modification. Otherwise the initialization becomes a single variable and the
        original initialization instruction will remain the same.

        :param loop_node: node to replace with a ForLoopNode
        :param continuation: instruction defining the for-loops modification
        :param init: instruction defining the for-loops declaration
        """

        declaration = None

        if _single_defininition_reaches_node(self._ast, init, loop_node) and _initialization_reaches_loop_node(init.node, loop_node):
            declaration = Assignment(continuation.instruction.destination, init.instruction.value)
            init.node.instructions.remove(init.instruction)
        elif not self._hide_non_init_decl:
            declaration = continuation.instruction.destination

        self._ast.substitute_loop_node(
            loop_node,
            ForLoopNode(
                declaration=declaration,
                condition=loop_node.condition,
                modification=continuation.instruction,
                reaching_condition=loop_node.reaching_condition,
            ),
        )
        continuation.node.instructions.remove(continuation.instruction)
        self._ast.clean_up()
       
    def _invalid_simple_for_loop_condition_type(self, logic_condition) -> bool:
        """ Checks if a logic condition is only a symbol, if true checks condition type of symbol for forbidden ones"""
        if not logic_condition.is_symbol or not self._forbidden_condition_types:
            return False

        if logic_condition.is_negation:
            logic_condition = ~logic_condition

        condition = self._ast.condition_map[logic_condition]
        for forbidden_condition in self._forbidden_condition_types:
            if condition.operation.name == forbidden_condition:
                return True

        return False


class ReadabilityBasedRefinement(PipelineStage):
    """
    The ReadabilityBasedRefinement makes various transformations to improve readability based on the AST.
    Currently implemented transformations:
        1. remove guarded do while loops
        2. while-loop to for-loop transformation

    The AST is cleaned up before the first transformation and after every while- to for-loop transformation.
    """

    name = "readability-based-refinement"

    def run(self, task: DecompilerTask):
        task.syntax_tree.clean_up()

        remove_guarded_do_while(task.syntax_tree)
        WhileLoopReplacer(task.syntax_tree, task.options).run()
