from dataclasses import dataclass
from typing import Iterator, Optional, Set, Tuple

from decompiler.pipeline.controlflowanalysis.restructuring_options import LoopBreakOptions, RestructuringOptions
from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, CaseNode, FalseNode, SwitchNode, TrueNode
from decompiler.structures.ast.condition_symbol import ConditionHandler
from decompiler.structures.ast.switch_node_handler import ExpressionUsages
from decompiler.structures.ast.syntaxforest import AbstractSyntaxForest
from decompiler.structures.logic.logic_condition import LogicCondition, PseudoLogicCondition
from decompiler.structures.pseudo import Condition, Constant, Expression, OperationType


@dataclass
class CaseNodeCandidate:
    """
    Class for possible case nodes.

    -> node is the AST node that we want to have as a case node
    -> The condition that the new case node should get.
    """

    node: AbstractSyntaxTreeNode
    expression: Optional[ExpressionUsages]
    condition: LogicCondition

    def construct_case_node(self, expression: Expression) -> CaseNode:
        """Construct Case node for itself with the given switch expression."""
        return CaseNode(expression, Constant("unknown"), self.condition.copy())

    def __eq__(self, other) -> bool:
        """
        We want to be able to compare CaseNodeCandidates with AST-nodes, more precisely,
        we want that an CaseNodeCandidate 'case_node' is equal to the AST node 'case_node.node'.
        """
        if isinstance(other, CaseNodeCandidate):
            return self.node == other.node
        return self.node == other

    def __hash__(self) -> int:
        return hash(self.node)

    @property
    def get_head(self):
        """
        Return the condition-node, if the case-node is a branch, else the node itself.

        This is the node that is a sibling of the switch resp. the child of the sequence node we currently consider.
        """
        if isinstance(self.node.parent, (TrueNode, FalseNode)):
            return self.node.parent.parent
        return self.node

    def update_reaching_condition_for_insertion(self):
        if isinstance(self.node.parent, (TrueNode, FalseNode)):
            self.node.reaching_condition &= self.node.parent.branch_condition
        self.node.reaching_condition.substitute_by_true(self.condition)


class BaseClassConditionAwareRefinement:
    """Base Class in charge of logic and condition related things we need during the condition aware refinement."""

    def __init__(self, asforest: AbstractSyntaxForest, options: RestructuringOptions):
        self.asforest: AbstractSyntaxForest = asforest
        self.condition_handler: ConditionHandler = asforest.condition_handler
        self.options: RestructuringOptions = options
        self.updated_switch_nodes: Set[SwitchNode] = set()

    def _get_constant_equality_check_expressions_and_conditions(
        self, condition: LogicCondition
    ) -> Iterator[Tuple[ExpressionUsages, LogicCondition]]:
        """
        Check whether the given condition is a simple comparison of an expression with one or more constants + perhaps a conjunction
        with another condition.

        - If this is the case, then we return the expression with which we compare the constants as well as the condition itself.
        - Note that a reaching condition can have more than one possible expression, i.e., the reaching condition (a == 3 and b == 4).
          Therefore, we return a list of all possible constant-equality checks. In this case [(a, a==3), (b, b == 4)].
        """
        if condition.is_conjunction:
            for disjunction in condition.operands:
                if expression := self._get_const_eq_check_expression_of_disjunction(disjunction):
                    yield expression, disjunction
        elif expression := self._get_const_eq_check_expression_of_disjunction(condition):
            yield expression, condition

    def _get_const_eq_check_expression_of_disjunction(self, condition: LogicCondition) -> Optional[ExpressionUsages]:
        """
        Check whether the given condition is a composition of comparisons of the same expression with constants.

        - Only works for disjunctions, i.e., Or-formulas or literals!!!
        - If the given condition is a literal that is expr == const, then we return expr
        - If the given condition is a disjunction of literals like expr == const, where the compared expression expr is always the same,
          then we return expr.
        - Otherwise, we return None.
        """
        if condition.is_literal:
            return self._get_expression_compared_with_constant(condition)

        operands = condition.operands
        if not condition.is_disjunction or any(not literal.is_literal for literal in operands):
            return None

        compared_expressions = [self._get_expression_compared_with_constant(literal) for literal in operands]
        if len(set(compared_expressions)) != 1 or compared_expressions[0] is None:
            return None
        return compared_expressions[0]

    def _get_expression_compared_with_constant(self, reaching_condition: LogicCondition) -> Optional[ExpressionUsages]:
        """
        Check whether the given reaching condition, which is a literal, i.e., a z3-symbol or its negation is of the form `expr == const`.
        If this is the case, then we return the expression `expr`.
        """
        return self.asforest.switch_node_handler.get_potential_switch_expression(reaching_condition)

    def _get_constant_compared_with_expression(self, reaching_condition: LogicCondition) -> Optional[Constant]:
        """
        Check whether the given reaching condition, which is a literal, i.e., a z3-symbol or its negation is of the form `expr == const`.
        If this is the case, then we return the constant `const`.
        """
        return self.asforest.switch_node_handler.get_potential_switch_constant(reaching_condition)

    def _convert_to_z3_condition(self, condition: LogicCondition) -> PseudoLogicCondition:
        return PseudoLogicCondition.initialize_from_formula(condition, self.condition_handler.get_z3_condition_map())

    def _z3_condition_of_literal(self, literal: LogicCondition) -> PseudoLogicCondition:
        """Return for a literal the corresponding z3-condition."""
        assert literal.is_literal, f"The input must be a literal, but it is {literal}"
        if literal.is_symbol:
            return self.condition_handler.get_z3_condition_of(literal)
        return ~self.condition_handler.get_z3_condition_of(~literal)

    def _condition_is_redundant_for_switch_node(self, switch_node: AbstractSyntaxTreeNode, condition: LogicCondition) -> bool:
        """
        1. Check whether the given node is a switch node.
        2. If this is the case then we check whether condition is always fulfilled when one of the switch cases is fulfilled
           and return the switch node. Otherwise, we return None.

        - If the switch node has a default case, then we can not add any more cases.
        """
        if not isinstance(switch_node, SwitchNode) or switch_node.default:
            return False
        cmp_condition = PseudoLogicCondition.initialize_from_formula(condition, self.condition_handler.get_z3_condition_map())
        for child in switch_node.children:
            case_condition = PseudoLogicCondition.initialize_from_condition(
                Condition(OperationType.equal, [switch_node.expression, child.constant]), self.condition_handler.logic_context
            )
            if not case_condition.does_imply(cmp_condition):
                return False
        return True

    def _contains_no_violating_loop_break(self, ast_node: AbstractSyntaxTreeNode) -> bool:
        """Check whether is violates the loop-break property."""
        return (
            not ast_node.is_break_node and self.options.loop_break_strategy == LoopBreakOptions.structural_variable
        ) or not ast_node._has_descendant_code_node_breaking_ancestor_loop()
