"""Module implementing various readability based refinements."""
from __future__ import annotations

from typing import Union

from decompiler.pipeline.controlflowanalysis.loop_utility_methods import (
    AstInstruction,
    _find_continuation_instruction,
    _get_variable_initialisation,
    _initialization_reaches_loop_node,
    _is_single_instruction_loop_node,
    _single_defininition_reaches_node,
)
from decompiler.pipeline.stage import PipelineStage
from decompiler.structures.ast.ast_nodes import ConditionNode, DoWhileLoopNode, ForLoopNode, WhileLoopNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.pseudo import Assignment
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def _get_potential_guarded_do_while_loops(ast: AbstractSyntaxTree) -> tuple(Union[DoWhileLoopNode, WhileLoopNode], ConditionNode):
    for loop_node in list(ast.get_loop_nodes_post_order()):
        if isinstance(loop_node, DoWhileLoopNode) and isinstance(loop_node.parent.parent, ConditionNode):
            yield loop_node, loop_node.parent.parent


def remove_guarded_do_while(ast: AbstractSyntaxTree):
    """Removes a if statement which guards a do-while loop/while loop when:
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
        self._restructure_for_loops = options.getboolean("readability-based-refinement.restructure_for_loops", fallback=True)
        self._keep_empty_for_loops = options.getboolean("readability-based-refinement.keep_empty_for_loops", fallback=False)
        self._hide_non_init_decl = options.getboolean("readability-based-refinement.hide_non_initializing_declaration", fallback=False)
        self._force_for_loops = options.getboolean("readability-based-refinement.force_for_loops", fallback=False)
        self._forbidden_condition_types = options.getlist(
            "readability-based-refinement.forbidden_condition_types_in_simple_for_loops", fallback=[]
        )
        self._condition_max_complexity = options.getint(
            "readability-based-refinement.max_condition_complexity_for_loop_recovery", fallback=100
        )
        self._modification_max_complexity = options.getint(
            "readability-based-refinement.max_modification_complexity_for_loop_recovery", fallback=100
        )

    def run(self):
        """For each WhileLoop in AST check the following conditions:
            -> any variable in loop condition has a valid continuation instruction in loop body
            -> variable is initialized
            -> loop condition complexity < condition complexity
            -> possible modification complexity < modification complexity
            -> if condition is only a symbol: check condition type for allowed one
            -> has a continue statement which must and can be equalized

        If 'force_for_loops' is enabled, the complexity options are ignored and every while loop after the
        initial transformation will be forced into a for loop with an empty declaration/modification
        """
        if not self._restructure_for_loops:
            return
        for loop_node in list(self._ast.get_while_loop_nodes_topological_order()):
            if (
                loop_node.is_endless_loop
                or (not self._keep_empty_for_loops and _is_single_instruction_loop_node(loop_node))
                or self._invalid_simple_for_loop_condition_type(loop_node.condition)
            ):
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
                if (equalizable_continue_nodes := self._get_continue_nodes_with_equalizable_definition(loop_node, continuation, variable_init)) is None:
                    break
                for node in equalizable_continue_nodes:
                    self._substract_continuation_from_last_definition(node, continuation, variable_init)
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
                    ),
                )

    def _get_continue_nodes_with_equalizable_definition(self, loop_node: WhileLoopNode, continuation: AstInstruction, variable_init: AstInstruction) -> List[CodeNode]:
        """
        Finds code nodes of a while loop containing continue statements and a definition of the continuation instruction, which can be easily equalized.

        :param loop_node: While-loop to search in
        :param continuation: Instruction defining the for-loops modification
        :param variable_init: Instruction defining the for-loops declaration
        :return: List of continue code nodes that has equalizable definitions, None if at least one continue node does not match the requirements
        """
        equalizable_nodes = []
        for code_node in (node for node in loop_node.body.get_descendant_code_nodes_interrupting_ancestor_loop() if node.does_end_with_continue):
            if not self._is_expression_simple_binary_operation(continuation.instruction.value):
                return None
            if (last_definition_index := _get_last_definition_index_of(code_node, variable_init.instruction.destination)) == -1:
                return None
            if not (
                isinstance(code_node.instructions[last_definition_index].value, Constant)
                or self._is_expression_simple_binary_operation(code_node.instructions[last_definition_index].value)
                and self._get_variable_in_binary_operation(continuation.instruction.value)
                == self._get_variable_in_binary_operation(code_node.instructions[last_definition_index].value)
            ):
                return None

            self._unify_binary_operation(continuation.instruction.value)
            if not isinstance(code_node.instructions[last_definition_index].value, Constant):
                self._unify_binary_operation(code_node.instructions[last_definition_index].value)

            equalizable_nodes.append(code_node)
        return equalizable_nodes

    def _is_expression_simple_binary_operation(self, expression: Expression) -> bool:
        """Checks if an expression is a simple binary operation. Meaning it includes a variable and a constant and uses plus or minus as operation type."""
        return (
            isinstance(expression, BinaryOperation)
            and expression.operation in {OperationType.plus, OperationType.minus}
            and any(isinstance(operand, Constant) for operand in expression.subexpressions())
            and any(isinstance(operand, Variable) for operand in expression.subexpressions())
        )

    def _get_variable_in_binary_operation(self, binaryoperation: BinaryOperation) -> Variable:
        """Returns the used variable of a binary operation if available."""
        for operand in binaryoperation.subexpressions():
                if isinstance(operand, Variable):
                    return operand
        return None

    def _count_unaryoperations_negations(self, expression: Expression) -> int:
        """Counts the amount of UnaryOperation negations of an expression."""
        negations = 0
        for subexpression in expression.subexpressions():
            if isinstance(subexpression, UnaryOperation) and subexpression.operation == OperationType.negate:
                negations += 1
        return negations

    def _unify_binary_operation(self, binaryoperation: BinaryOperation):
        """Brings a simple binary operation into a unified representation like 'var + const'."""
        print(binaryoperation)
        if not binaryoperation.operation == OperationType.plus:
            binaryoperation.operation = OperationType.plus
            binaryoperation.substitute(binaryoperation.right, UnaryOperation(OperationType.negate, [binaryoperation.right]))

        if any(isinstance(operand, Constant) for operand in binaryoperation.left.subexpressions()):
            binaryoperation.swap_operands()

    def _substract_continuation_from_last_definition(self, code_node: CodeNode, continuation: AstInstruction, variable_init: AstInstruction):
        """
        Substracts the value of the continuation instruction from the last definition, which must be a simple binary operation or a constant,
        defining the same value as the continuation instruction in the given code node.

        :param code_node: Code node whose last instruction is to be changed
        :param continuation: Instruction defining the for-loops modification
        :param variable_init: Instruction defining the for-loops declaration
        """
        last_definition = code_node.instructions[_get_last_definition_index_of(code_node, variable_init.instruction.destination)]
        last_definition.substitute(last_definition.value, BinaryOperation(OperationType.minus, [last_definition.value, continuation.instruction.value.right]))

        if self._count_unaryoperations_negations(continuation.instruction.value.left) % 2 != 0:
            last_definition.substitute(last_definition.value, UnaryOperation(OperationType.negate, [last_definition.value]))

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
        """Checks if a logic condition is only a symbol, if true checks condition type of symbol for forbidden ones"""
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
