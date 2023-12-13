from typing import Any, Tuple, TypeVar, Union

from decompiler.backend.cexpressiongenerator import CExpressionGenerator
from decompiler.structures import pseudo as expressions
from decompiler.structures.ast import ast_nodes as ast_nodes
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Comment,
    Condition,
    Constant,
    Float,
    Integer,
    OperationType,
    UnaryOperation,
    Variable,
)
from decompiler.structures.pseudo.operations import COMMUTATIVE_OPERATIONS, NON_COMPOUNDABLE_OPERATIONS
from decompiler.structures.visitors.interfaces import ASTVisitorInterface
from decompiler.task import DecompilerTask

ConditionVar = TypeVar("ConditionVar", Constant, Variable, LogicCondition)


class CodeVisitor(ASTVisitorInterface, CExpressionGenerator):
    """Visits all nodes in the AST and produce C code."""

    def __init__(self, task: DecompilerTask):
        """Initialize this CodeVisitor with a specific DecompilerTask."""
        super().__init__()
        self._condition_map = task.syntax_tree.condition_map if task.syntax_tree else {}
        self.complexity_bound: int = task.options.getint("code-generator.max_complexity")
        self._use_increment_int: bool = task.options.getboolean("code-generator.use_increment_int")
        self._use_increment_float: bool = task.options.getboolean("code-generator.use_increment_float")
        self._use_compound_assignment: bool = task.options.getboolean("code-generator.use_compound_assignment")
        self._byte_format: str = task.options.getstring("code-generator.byte_format", fallback="char")
        self._byte_format_hint: str = task.options.getstring("code-generator.byte_format_hint", fallback="none")
        self._int_repr_scope: int = task.options.getint("code-generator.int_representation_scope", fallback=256)
        self._neg_hex_as_twos_complement: bool = task.options.getboolean("code-generator.negative_hex_as_twos_complement", fallback=True)
        self._aggressive_array_detection: bool = task.options.getboolean("code-generator.aggressive_array_detection", fallback=False)
        self.task = task

    def visit_seq_node(self, node: ast_nodes.SeqNode) -> str:
        """Concatenate nodes in a SeqNode."""
        return "".join(map(self.visit, node.children))

    def visit_loop_node(self, node: ast_nodes.LoopNode) -> str:
        """Generate code for loops."""
        loop_after = ""

        if node.is_endless_loop and isinstance(node, ast_nodes.DoWhileLoopNode):
            loop_type = "while (true)"
        elif isinstance(node, ast_nodes.DoWhileLoopNode):
            loop_type = "do"
            loop_condition = self._condition_string(node.condition)
            loop_after = f"while ({loop_condition});"
        elif isinstance(node, ast_nodes.ForLoopNode):
            for_declaration = self.visit(node.declaration) if node.declaration else " "
            for_modification = self.visit(node.modification) if node.modification else ""
            loop_type = f"{node.loop_type.value} ({for_declaration}; {self._condition_string(node.condition)}; {for_modification})"
        else:
            assert isinstance(node, ast_nodes.WhileLoopNode)
            loop_condition = self._condition_string(node.condition)
            loop_type = f"{node.loop_type.value} ({loop_condition})"
        return f"{loop_type}{{{self.visit(node.body)}}}{loop_after}"

    def visit_condition_node(self, node: ast_nodes.ConditionNode) -> str:
        """Generate code for a conditional."""
        true_str = self.visit(node.true_branch_child)
        if node.false_branch is None:
            return f"if ({self._condition_string(node.condition)}) {{{true_str}}}"
        false_str = self.visit(node.false_branch_child)
        if isinstance(node.true_branch_child, ast_nodes.ConditionNode) or isinstance(node.false_branch_child, ast_nodes.ConditionNode):
            negate_condition = isinstance(node.true_branch_child, ast_nodes.ConditionNode) and (
                    not isinstance(node.false_branch_child, ast_nodes.ConditionNode) or len(false_str) > len(true_str)
            )

            condition = node.condition
            if negate_condition:
                true_str, false_str = false_str, true_str
                condition = ~condition

            return f"if ({self._condition_string(condition)}) {{{true_str}}} else {false_str}"
        else:
            return f"if ({self._condition_string(node.condition)}) {{{true_str}}} else {{{false_str}}}"

    def visit_true_node(self, node: ast_nodes.TrueNode) -> str:
        """Generate code for the given TrueNode by evaluating its child (Wrapper)."""
        return self.visit(node.child)

    def visit_false_node(self, node: ast_nodes.FalseNode) -> str:
        """Generate code for the given TrueNode by evaluating its child (Wrapper)."""
        return self.visit(node.child)

    def visit_root_node(self, node: ast_nodes.VirtualRootNode) -> str:
        """Generate code for the given VirtualRootNode by evaluating its child (Wrapper)."""
        return self.visit(node.child)

    def visit_switch_node(self, node: ast_nodes.SwitchNode) -> str:
        """Generate code for a switch."""
        cases = "\n".join(self.visit(c) for c in node.children)
        return f"switch({node.expression}){{{cases}}}"

    def visit_case_node(self, node: ast_nodes.CaseNode) -> str:
        """Generate case label and body."""
        body = "".join(map(self.visit, node.children))
        if isinstance(node.constant, expressions.Constant):
            fall = "break;" if node.break_case else ""
            if isinstance(node.constant.type, Integer):
                return f"case {self._format_integer_literal(node.constant.type, node.constant.value)}:{body}{fall}"
            return f"case {node.constant}:{body}{fall}"
        else:  # "default"
            return f"default:{body}"

    def visit_code_node(self, node: ast_nodes.CodeNode) -> str:
        """Generate code for a sequence of statements."""

        def stmt_string(stmt: Any) -> str:
            """ToString for any instruction/expression/operation of pseudo"""
            if isinstance(stmt, Comment):
                return f"{self.visit(stmt)}"
            return f"{self.visit(stmt)};"

        return "\n".join(map(stmt_string, node.instructions))

    def visit_assignment(self, instr: Assignment) -> str:
        """Generate compound/increment assignments if enabled by the task."""
        if self._use_compound_assignment and self._is_compoundable(instr):
            target_operand = instr.value.left if instr.destination == instr.value.right else instr.value.right
            if self._is_incrementable(instr, target_operand):
                return self._get_increment_syntax(instr, target_operand)
            return self._get_compound_syntax(instr, target_operand)
        return super(CodeVisitor, self).visit_assignment(instr)

    def visit_unary_operation(self, op: UnaryOperation) -> str:
        """
        Visit unary operation; visits array element access based on task options
        """
        if self._is_array_element_access(op):
            return self._visit_array_element_access(op)
        return super(CodeVisitor, self).visit_unary_operation(op)

    def _visit_array_element_access(self, array_elem_access: UnaryOperation) -> str:
        """
        Transform *(base+offset){array_base=ssa_base, array_index=ssa_index} to base[index]
        :param array_elem_access: *(base+offset)
        :return string in form base[index]
        """
        base, index = self._parse_array_element_access_attributes(array_elem_access)
        result = f"{base}[{index}]"
        if array_elem_access.array_info.confidence or self._aggressive_array_detection:
            return result
        array_elem_access.array_info = None
        return f"{super(CodeVisitor, self).visit_unary_operation(array_elem_access)}/*{result}*/"

    @staticmethod
    def _parse_array_element_access_attributes(
        array_elem_access: UnaryOperation,
    ) -> Tuple[str, Union[int, str]]:
        """
        UnaryOperation updates ArrayInfo on .substitue(...)
        Therefore we can directly read base and index from UnaryOperation.ArrayInfo
        """
        if array_elem_access.array_info is None:
            raise ValueError("Parsing array access, but ArrayInfo is None")
        base = array_elem_access.array_info.base
        index = array_elem_access.array_info.index
        if isinstance(index, int):
            return base.name, index
        return base.name, index.name

    @staticmethod
    def _is_compoundable(instr: Assignment) -> bool:
        """Check if the assignment is compoundable (e.g. x = x + y <=> x += y)."""
        return (
            isinstance(instr.value, BinaryOperation)
            and instr.value.operation not in NON_COMPOUNDABLE_OPERATIONS
            and (
                instr.destination == instr.value.left
                or (instr.destination == instr.value.right and instr.value.operation in COMMUTATIVE_OPERATIONS)
            )
        )

    def _is_incrementable(self, instr: Assignment, target_operand: expressions.Expression) -> bool:
        """Check if the assignment is incrementable (e.g. x = x + 1 -> x++)."""
        return (
            isinstance(instr.value, BinaryOperation)
            and (instr.value.operation == OperationType.plus or instr.value.operation == OperationType.minus)
            and isinstance(target_operand, expressions.Constant)
            and (
                (isinstance(target_operand.type, Float) and self._use_increment_float)
                or (isinstance(target_operand.type, Integer) and self._use_increment_int)
            )
            and (target_operand.value == 0x1 or target_operand.value == -0x1)
        )

    def _get_compound_syntax(self, instr: Assignment, target_operand: expressions.Expression) -> str:
        """Generate compound syntax and represent operator in C syntax."""
        return f"{self.visit(instr.destination)} {self.C_SYNTAX[instr.value.operation]}= {self.visit(target_operand)}"

    def _get_increment_syntax(self, instr: Assignment, target_operand: expressions.Expression) -> str:
        """Generate increment syntax and simplify instruction if possible (e.g. x = x - (-1) -> x++)"""
        if instr.value.operation == OperationType.minus:
            return f"{self.visit(instr.destination)}{'++' if target_operand.value < 0 else '--'}"
        return f"{self.visit(instr.destination)}{'--' if target_operand.value < 0 else '++'}"

    def _condition_string(self, condition: ConditionVar) -> str:
        """Derive the correct condition to print."""
        if isinstance(condition, expressions.Constant):
            return self.visit(condition)
        if condition is None:  # TODO: handle
            return f"{condition}"
        condition = condition.simplify_to_shortest(self.complexity_bound)

        if condition.is_true:
            return "true"
        elif condition.is_false:
            return "false"
        elif condition.is_symbol:
            return f"{self.visit(self._condition_map[condition])}"
        elif condition.is_negation:
            original_condition = self._condition_map[~condition]
            if not isinstance(original_condition, Condition):
                return f"{self.C_SYNTAX[OperationType.logical_not]}({self.visit(original_condition)})"
            return f"{self.visit(original_condition.negate())}"
        elif condition.is_disjunction:
            if len(operands := condition.operands) >= 1:
                return f" {self.C_SYNTAX[OperationType.logical_or]} ".join([f"({self._condition_string(x)})" for x in operands])
            return self._condition_string(condition)
        elif condition.is_conjunction:
            if len(operands := condition.operands) > 1:
                return f" {self.C_SYNTAX[OperationType.logical_and]} ".join([f"({self._condition_string(x)})" for x in operands])
            return self._condition_string(condition)
        raise ValueError("Condition {condition} couldn't be printed correctly.")

    def _format_integer_literal(self, type_info: Integer, value: int) -> str:
        """Format the integer based on the codegenerators settings."""

        byte_format_handler = {"char": lambda x: f"'{chr(x)}'", "hex": lambda x: f"{hex(x)}", "dec": lambda x: f"{x}"}
        if self._possibly_char_in_ascii_range(type_info, value):
            if value_handler := byte_format_handler.get(self._byte_format, None):
                if hint_handler := byte_format_handler.get(self._byte_format_hint, None):
                    return f"{value_handler(value)} /*{hint_handler(value)}*/"
                return value_handler(value)
        if self._int_repr_scope == 0 or abs(value) > self._int_repr_scope:
            return self._hex_representation_of(value, type_info.size)
        return super(CodeVisitor, self)._format_integer_literal(type_info, value)

    def _hex_representation_of(self, value: int, size: int) -> str:
        """
        Return a hex-string representation of the given integer literal.

        :param value: integer to be represented as hex
        :param size: integer size in bits
        :return: hex representation of an integer. If the integer is negative, the corresponding
                 two's complement is used for hex representation.
        """
        if value >= 0 or not self._neg_hex_as_twos_complement:
            return hex(value)
        dec_bytes = value.to_bytes(int(size / 8), byteorder="big", signed=True)
        return f"0x{dec_bytes.hex()}"

    @staticmethod
    def _possibly_char_in_ascii_range(type_info: Integer, value: int):
        """
        Check whether the given char value is printable.

        :param type_info: type of tested constant
        :param value: value of tested constant
        :return: true if type is of byte size and value lies in printable characters range
        """
        return type_info.size == 8 and (ord(" ") <= value < ord("~"))
