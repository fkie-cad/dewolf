from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from decompiler.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    LoopNode,
    SeqNode,
    SwitchNode,
    WhileLoopNode,
)
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Condition,
    Constant,
    Expression,
    OperationType,
    UnaryOperation,
    Variable,
)
from decompiler.structures.visitors.assignment_visitor import AssignmentVisitor


@dataclass
class AstInstruction:
    instruction: Assignment
    position: int
    node: CodeNode


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


def _get_equalizable_last_definitions(loop_node: WhileLoopNode, continuation: AstInstruction) -> List[CodeNode]:
    """
    Finds equalizable last definitions of the continuation instruction in the code nodes of a while loop containing continue statements.

    :param loop_node: While-loop to search in
    :param continuation: Instruction defining the for-loops modification
    :return: List of equalizable last definitions, Empty list if no continue nodes or no equalizable nodes
    :return: None if at least one continue node does not match the requirements
    """
    if not (
        continue_nodes := [
            node for node in loop_node.body.get_descendant_code_nodes_interrupting_ancestor_loop() if node.does_end_with_continue
        ]
    ):
        return continue_nodes

    if not (_is_assignment_with_simple_binary_operation(continuation.instruction)):
        return None

    equalizable_nodes = []
    for code_node in continue_nodes:
        if (last_definition_index := _get_last_definition_index_of(code_node, continuation.instruction.destination)) == -1:
            return None

        last_definition = code_node.instructions[last_definition_index]
        if not (isinstance(last_definition.value, Constant) or _is_assignment_with_simple_binary_operation(last_definition)):
            return None

        _unify_binary_operation_in_assignment(continuation.instruction)
        equalizable_nodes.append(last_definition)
    return equalizable_nodes


def _is_assignment_with_simple_binary_operation(assignment: Assignment) -> bool:
    """
    Checks if an assignment has a simple binary operation as value and the used and defined variable is the same. A simple binary
    operation means that it includes a variable and a constant and uses plus or minus as operation type.
    """
    return (
        isinstance(assignment.value, BinaryOperation)
        and assignment.value.operation in {OperationType.plus, OperationType.minus}
        and any(isinstance(operand, Constant) or _is_negated_constant_variable(operand, Constant) for operand in assignment.value.operands)
        and any(isinstance(operand, Variable) or _is_negated_constant_variable(operand, Variable) for operand in assignment.value.operands)
        and assignment.destination == _get_variable_in_binary_operation(assignment.value)
    )


def _is_negated_constant_variable(operand: Expression, expression: Constant | Variable) -> bool:
    """Checks if an operand (constant or variable) is negated."""
    return isinstance(operand, UnaryOperation) and operand.operation == OperationType.negate and isinstance(operand.operand, expression)


def _get_variable_in_binary_operation(binaryoperation: BinaryOperation) -> Variable:
    """Returns the used variable of a binary operation if available."""
    for operand in binaryoperation.operands:
        if isinstance(operand, Variable):
            return operand
        if _is_negated_constant_variable(operand, Variable):
            return operand.operand
    return None


def _unify_binary_operation_in_assignment(assignment: Assignment):
    """Brings a simple binary operation of an assignment into a unified representation like 'var = -var + const' instead of 'var = const - var'."""
    if not assignment.value.operation == OperationType.plus:
        assignment.substitute(
            assignment.value,
            BinaryOperation(OperationType.plus, [assignment.value.left, UnaryOperation(OperationType.negate, [assignment.value.right])]),
        )

    if any(isinstance(operand, Constant) for operand in assignment.value.left.subexpressions()):
        assignment.substitute(assignment.value, BinaryOperation(OperationType.plus, [assignment.value.right, assignment.value.left]))


def _substract_continuation_from_last_definition(last_definition: Assignment, continuation: AstInstruction):
    """
    Substracts the value of the continuation instruction from the last definition, which must be a simple binary operation or a constant,
    defining the same value as the continuation instruction in the given code node.

    :param last_definition: Last definition that is to be changed
    :param continuation: Instruction defining the for-loops modification
    """
    substracted_binary_operation = BinaryOperation(OperationType.minus, [last_definition.value, continuation.instruction.value.right])
    if _is_negated_constant_variable(continuation.instruction.value.left, Variable):
        last_definition.substitute(last_definition.value, UnaryOperation(OperationType.negate, [substracted_binary_operation]))
    else:
        last_definition.substitute(last_definition.value, substracted_binary_operation)
