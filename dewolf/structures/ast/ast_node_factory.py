from typing import TYPE_CHECKING, List, Literal, Optional, Union

from dewolf.structures.ast.ast_nodes import (
    CaseNode,
    CodeNode,
    ConditionNode,
    DoWhileLoopNode,
    FalseNode,
    ForLoopNode,
    SeqNode,
    SwitchNode,
    TrueNode,
    VirtualRootNode,
    WhileLoopNode,
)
from dewolf.structures.logic.logic_condition import LogicCondition
from dewolf.structures.pseudo import Assignment, Constant, Expression, Instruction

if TYPE_CHECKING:
    from dewolf.structures.ast.syntaxgraph import AbstractSyntaxInterface


class ASTNodeFactory:
    """Class in charge of create AST-nodes for an AST."""

    def __init__(self, context, ast: "AbstractSyntaxInterface"):
        """Create a new ast-node factory with a context for the logic conditions and the AST for which it generates nodes."""
        self._logic_context = context
        self.ast: AbstractSyntaxInterface = ast

    @property
    def logic_context(self):
        """Return the logic context."""
        return self._logic_context

    def create_virtual_node(self, reaching_condition: Optional[LogicCondition] = None) -> VirtualRootNode:
        """
        Create a virtual node, which is a node that is always the root and can be used to point to the root of an AST or the root of the
        current tree of an abstract forest.
        """
        return VirtualRootNode(self._get_reaching_condition(reaching_condition), self.ast)

    def create_seq_node(self, reaching_condition: Optional[LogicCondition] = None) -> SeqNode:
        """Create a new sequence-node."""
        return SeqNode(self._get_reaching_condition(reaching_condition), self.ast)

    def create_code_node(self, stmts: List[Instruction], reaching_condition: Optional[LogicCondition] = None) -> CodeNode:
        """Create a new code node given a list of instructions."""
        return CodeNode(stmts, self._get_reaching_condition(reaching_condition), self.ast)

    def create_condition_node(self, condition: LogicCondition, reaching_condition: Optional[LogicCondition] = None) -> ConditionNode:
        """Create a new conditional node with the given condition."""
        return ConditionNode(condition, self._get_reaching_condition(reaching_condition), self.ast)

    def create_true_node(self, reaching_condition: Optional[LogicCondition] = None) -> TrueNode:
        """Create a node true-node, i.e., a node representing the true-branch of a condition node."""
        return TrueNode(self._get_reaching_condition(reaching_condition), self.ast)

    def create_false_node(self, reaching_condition: Optional[LogicCondition] = None) -> FalseNode:
        """Create a node false-node, i.e., a node representing the false-branch of a condition node."""
        return FalseNode(self._get_reaching_condition(reaching_condition), self.ast)

    def create_while_loop_node(self, condition: LogicCondition, reaching_condition: Optional[LogicCondition] = None) -> WhileLoopNode:
        """Create a new while loop node with the given loop condition."""
        return WhileLoopNode(condition, self._get_reaching_condition(reaching_condition), self.ast)

    def create_endless_loop_node(self, reaching_condition: Optional[LogicCondition] = None) -> WhileLoopNode:
        """Create a new while loop node with the given loop condition."""
        return WhileLoopNode(LogicCondition.initialize_true(self.logic_context), self._get_reaching_condition(reaching_condition), self.ast)

    def create_do_while_loop_node(self, condition: LogicCondition, reaching_condition: Optional[LogicCondition] = None) -> DoWhileLoopNode:
        """Create a new do-while loop node with the given loop condition."""
        return DoWhileLoopNode(condition, self._get_reaching_condition(reaching_condition), self.ast)

    def create_for_loop_node(
        self,
        declaration: Assignment,
        condition: LogicCondition,
        modification: Assignment,
        reaching_condition: Optional[LogicCondition] = None,
    ) -> ForLoopNode:
        """Create a new for loop node with the given declaration, condition and modification."""
        return ForLoopNode(declaration, condition, modification, self._get_reaching_condition(reaching_condition), self.ast)

    def create_switch_node(self, expression: Expression, reaching_condition: Optional[LogicCondition] = None) -> SwitchNode:
        """Create a new switch node with the given expression."""
        return SwitchNode(expression, self._get_reaching_condition(reaching_condition), self.ast)

    def create_case_node(
        self,
        expression: Expression,
        constant: Union[Constant, Literal["default"]],
        reaching_condition: Optional[LogicCondition] = None,
        break_case: bool = False,
    ) -> CaseNode:
        """Create a new case node with the expression of the corresponding switch, the case-constants and whether it ends with break."""
        return CaseNode(expression, constant, self._get_reaching_condition(reaching_condition), break_case, self.ast)

    def _get_reaching_condition(self, reaching_condition: Optional[LogicCondition]) -> LogicCondition:
        """Returns the given reaching condition if it is not None and otherwise the reaching condition TRUE."""
        if reaching_condition is None:
            reaching_condition = LogicCondition.initialize_true(self.logic_context)
        return reaching_condition
