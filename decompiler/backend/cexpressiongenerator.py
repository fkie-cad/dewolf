import logging
from ctypes import c_byte, c_int, c_long, c_short, c_ubyte, c_uint, c_ulong, c_ushort
from itertools import chain, repeat
from typing import Union

from decompiler.structures import pseudo as expressions
from decompiler.structures.pseudo import Float, Integer, OperationType, Pointer
from decompiler.structures.pseudo import instructions as instructions
from decompiler.structures.pseudo import operations as operations
from decompiler.structures.visitors.interfaces import DataflowObjectVisitorInterface


class CExpressionGenerator(DataflowObjectVisitorInterface):
    """Generate C code for Expressions.

    This is a separate class from CodeVisitor as it does not depend on a DecompilerTask.
    As such, it can be used to print expressions separately.
    """

    # For code generation
    C_SYNTAX = {
        OperationType.minus: "-",
        OperationType.minus_with_carry: "-",
        OperationType.minus_float: "-",
        OperationType.plus: "+",
        OperationType.plus_with_carry: "+",
        OperationType.plus_float: "+",
        OperationType.negate: "-",
        OperationType.left_shift: "<<",
        OperationType.right_shift: ">>",
        OperationType.right_shift_us: ">>",
        # Handled in code
        # OperationType.left_rotate: "l_rot",
        # OperationType.right_rotate: "r_rot",
        # OperationType.right_rotate_carry: "r_rot_carry",
        # OperationType.left_rotate_carry: "l_rot_carry",
        OperationType.multiply: "*",
        OperationType.multiply_us: "*",
        OperationType.multiply_float: "*",
        OperationType.divide: "/",
        OperationType.divide_us: "/",
        OperationType.divide_float: "/",
        OperationType.modulo: "%",
        OperationType.modulo_us: "%",
        # TODO: unhandled
        # OperationType.power: "**",
        # Logical and bitwise operations cannot be distinguished in lifter.
        # Although we use the bitwise notation, they are prefixed with logical_ for consistency.
        OperationType.bitwise_or: "|",
        OperationType.bitwise_and: "&",
        OperationType.bitwise_xor: "^",
        OperationType.bitwise_not: "~",
        OperationType.logical_or: "||",
        OperationType.logical_and: "&&",
        OperationType.logical_not: "!",
        OperationType.equal: "==",
        OperationType.not_equal: "!=",
        OperationType.less: "<",
        OperationType.less_us: "<",
        OperationType.greater: ">",
        OperationType.greater_us: ">",
        OperationType.less_or_equal: "<=",
        OperationType.less_or_equal_us: "<=",
        OperationType.greater_or_equal: ">=",
        OperationType.greater_or_equal_us: ">=",
        OperationType.dereference: "*",
        OperationType.address: "&",
        # Handled in code
        # OperationType.cast: "cast",
        # OperationType.pointer: "point",
        # OperationType.low: "low",
        OperationType.ternary: "?",
        # Handled in code
        # OperationType.call: "func",
        # TODO: unhandled
        # OperationType.field: "->",
        # Handled in code
        # OperationType.list_op: "list",
        # OperationType.adc: "adc",
    }

    SIGNED_FORMATS = {
        8: lambda x: c_byte(x).value,
        16: lambda x: c_short(x).value,
        32: lambda x: c_int(x).value,
        64: lambda x: c_long(x).value,
    }

    UNSIGNED_FORMATS = {
        8: lambda x: c_ubyte(x).value,
        16: lambda x: c_ushort(x).value,
        32: lambda x: c_uint(x).value,
        64: lambda x: c_ulong(x).value,
    }

    """
    Precedence used for correctly generating brackets.
    Higher precedence is more tightly binding.
    """
    PRECEDENCE = {
        OperationType.minus: 120,
        OperationType.minus_with_carry: 120,
        OperationType.minus_float: 120,
        OperationType.plus: 120,
        OperationType.plus_with_carry: 120,
        OperationType.plus_float: 120,
        OperationType.negate: 140,
        OperationType.left_shift: 110,
        OperationType.right_shift: 110,
        OperationType.right_shift_us: 110,
        OperationType.left_rotate: 150,  # Not in C
        OperationType.right_rotate: 150,  # Not in C
        OperationType.right_rotate_carry: 150,  # Not in C
        OperationType.left_rotate_carry: 150,  # Not in C
        OperationType.multiply: 130,
        OperationType.multiply_us: 130,
        OperationType.multiply_float: 130,
        OperationType.divide: 130,
        OperationType.divide_us: 130,
        OperationType.divide_float: 130,
        OperationType.modulo: 130,
        OperationType.modulo_us: 130,
        OperationType.power: 135,  # Not in C
        OperationType.bitwise_or: 40,
        OperationType.bitwise_and: 50,
        OperationType.bitwise_xor: 70,
        OperationType.bitwise_not: 140,
        OperationType.logical_or: 40,
        OperationType.logical_and: 50,
        OperationType.logical_not: 140,
        OperationType.equal: 90,
        OperationType.not_equal: 90,
        OperationType.less: 100,
        OperationType.less_us: 100,
        OperationType.greater: 100,
        OperationType.greater_us: 100,
        OperationType.less_or_equal: 100,
        OperationType.less_or_equal_us: 100,
        OperationType.greater_or_equal: 100,
        OperationType.greater_or_equal_us: 100,
        OperationType.dereference: 140,
        OperationType.address: 140,
        OperationType.cast: 140,
        # TODO: I don't know what these are exactly. We'll get to it.
        # OperationType.pointer: "point",
        # OperationType.low: "low",
        OperationType.ternary: 30,
        OperationType.call: 150,
        OperationType.field: 150,
        OperationType.list_op: 10,
        # TODO: Figure out what these are / how to handle this
        # OperationType.adc: "adc",
    }

    def visit_unknown_expression(self, expr: expressions.UnknownExpression) -> str:
        """Return the error message for this UnknownExpression."""
        return expr.msg

    def visit_constant(self, expr: expressions.Constant) -> str:
        """Return constant in a format that will be parsed correctly by a compiler."""
        if isinstance(expr.type, Integer) and not isinstance(expr.type, (Float, Pointer)):
            value = self._get_integer_literal_value(expr)
            return self._format_integer_literal(expr.type, value)
        return self._format_string_literal(expr)

    def visit_variable(self, expr: expressions.Variable) -> str:
        """Return a string representation of the variable."""
        return f"{expr.name}" if (label := expr.ssa_label) is None else f"{expr.name}_{label}"

    def visit_register_pair(self, expr: expressions.Variable) -> str:
        """Return a string representation of the register pair and log."""
        logging.error(f"generated code for register pair {expr}")
        return f"{expr}"

    def visit_list_operation(self, op: operations.ListOperation) -> str:
        """Return a string representation of a list operation (weird calling conventions only)."""
        return ", ".join([self.visit(expr) for expr in op])

    def visit_unary_operation(self, op: operations.UnaryOperation) -> str:
        """Return a string representation of the given unary operation (e.g. !a or &a)."""
        operand = self._visit_bracketed(op.operand) if self._has_lower_precedence(op.operand, op) else self.visit(op.operand)
        if op.operation == OperationType.cast and op.contraction:
            return f"({int(op.type.size / 8)}: ){operand}"
        if op.operation == OperationType.cast:
            if op.type == op.operand.type:
                return operand
            elif isinstance(op.type, Integer) and isinstance(op.operand.type, Integer):
                if isinstance(op.operand, expressions.Constant):
                    value = self._get_integer_literal_value(op.operand)
                    eliminated_val = expressions.Constant(value, op.type)
                    try:
                        if self._get_integer_literal_value(eliminated_val) == value:
                            return self.visit(eliminated_val)
                    except ValueError:
                        pass
            return f"({op.type}){operand}"
        return f"{self.C_SYNTAX[op.operation]}{operand}"

    def visit_binary_operation(self, op: operations.BinaryOperation) -> str:
        """Return a string representation of the given binary operation (e.g. a + b)."""
        lhs = self._visit_bracketed(op.left) if self._has_lower_precedence(op.left, op) else self.visit(op.left)
        rhs = self._visit_bracketed(op.right) if self._has_lower_precedence(op.right, op) else self.visit(op.right)

        if op.operation == OperationType.left_rotate or op.operation == OperationType.left_rotate_carry:
            return f"(({lhs} << {rhs}) | ({lhs} >> ({op.left.type.size} - {rhs})))"
        elif op.operation == OperationType.right_rotate or op.operation == OperationType.right_rotate_carry:
            return f"(({lhs} >> {rhs}) | ({lhs} << ({op.left.type.size} - {rhs})))"
        else:
            return f"{lhs} {self.C_SYNTAX[op.operation]} {rhs}"

    def visit_call(self, op: operations.Call) -> str:
        """
        Generate string of function call with argument labels if they exist in meta_data:
        'function(/* label1 */ arg1, /* label2 */ arg2, arg_without_label)'
        Generic labels starting with 'arg' e.g. 'arg1', 'arg2' are being filtered.
        Additionally we filter ellipsis argument '...' that is lifted from type string.
        """
        func_name = self.visit(op.function)
        if isinstance(op.function, expressions.Constant):
            func_name = func_name.strip('"')
        output = f"{func_name}("
        if op.meta_data is not None:
            parameter_names = op.meta_data.get("param_names", [])
            is_tailcall = op.meta_data.get("is_tailcall")
        else:
            parameter_names = []
            is_tailcall = False
        at_least_one = False
        for parameter, name in zip(op.parameters, chain(parameter_names, repeat(""))):
            if at_least_one:
                output += ", "
            if name.startswith("arg") or name == "...":
                name = ""  # filter generic argument labels
            output += f"/* {name} */ " if name else ""
            output += f"{self.visit(parameter)}"
            at_least_one = True
        output += ")"
        if is_tailcall:
            return f"return {output}"
        return output

    def visit_condition(self, op: operations.Condition) -> str:
        """Return a string representation of the given condition (e.g. a < b)."""
        return self.visit_binary_operation(op)

    def visit_ternary_expression(self, op: operations.TernaryExpression) -> str:
        """Return a string representation of the given inline conditional (e.g. a if b else c)."""
        return f"{self.visit(op.condition)} ? {self.visit(op.true)} : {self.visit(op.false)}"

    def visit_comment(self, instr: instructions.Comment) -> str:
        """Return a string representation of the given comment instruction."""
        return f"{instr}"

    def visit_assignment(self, instr: instructions.Assignment) -> str:
        """Return a string representation of the given assignment (e.g. a = x)."""
        # See Assignment.__str__
        if isinstance(instr.destination, operations.ListOperation) and not instr.destination.operands:
            return f"{self.visit(instr.value)}"
        elif isinstance(op := instr.destination, operations.UnaryOperation) and op.operation == OperationType.cast and op.contraction:
            return f"{self.visit(op.operand)} = {self.visit(instr.value)}"
        return f"{self.visit(instr.destination)} = {self.visit(instr.value)}"

    def visit_generic_branch(self, instr: instructions.GenericBranch) -> str:
        """Return a string representation of a branch. Only included for completeness."""
        return f"{instr}"

    def visit_return(self, instr: instructions.Return) -> str:
        """Return a string representation of return instruction with or without argument."""
        return_value = self.visit(instr.values)
        return f"return {return_value}" if return_value else "return"

    def visit_break(self, instr: instructions.Break) -> str:
        """ "Return the string 'break'."""
        return f"{instr}"

    def visit_continue(self, instr: instructions.Continue) -> str:
        """ "Return the string 'continue'."""
        return f"{instr}"

    def visit_phi(self, instr: instructions.Phi) -> str:
        """Return a string representation of a phi instruction. Only included for completeness."""
        return f"{instr}"

    def visit_mem_phi(self, instr: instructions.MemPhi) -> str:
        """Return a string representation of a mem phi instruction. Only included for completeness."""
        return f"{instr}"

    def _get_integer_literal_value(self, literal: expressions.Constant[Integer]) -> Union[float, int]:
        """
        Return the right integer value for the given type, assuming that the
        re-compilation host has the same sizes as the decompilation host.
        """
        if isinstance(literal.type, Float):
            return literal.value
        if literal.type.is_signed:
            if handler := self.SIGNED_FORMATS.get(literal.type.size, None):
                return handler(literal.value)
        elif literal.value < 0:
            if handler := self.UNSIGNED_FORMATS.get(literal.type.size, None):
                return handler(literal.value)
        return literal.value

    @staticmethod
    def _interpret_integer_literal_type(value: int) -> Integer:
        """Return the type that a C compiler would use for a literal of this value."""
        # Precedence: int -> uint -> long -> ulong -> ll -> ull (i32, u32, i64, u64)
        if -(2**31) <= value < 2**31:
            return Integer.int32_t()
        elif 0 <= value < 2**32:
            return Integer.uint32_t()
        elif -(2**63) <= value < 2**63:  # i64
            return Integer.int64_t()
        else:
            return Integer.uint64_t()

    def _format_integer_literal(self, type_info: Integer, value: int) -> str:
        """Format integer literal for parsing by a C compiler."""
        interpreted_type = self._interpret_integer_literal_type(value)
        # no need to cast char/short due to implicit casting
        need_cast = type_info.size == 64 and interpreted_type.size == 32
        hint_unsigned = not type_info.is_signed and (interpreted_type.is_signed or need_cast)
        return f"{value}{'U' if hint_unsigned else ''}{'L' if need_cast else ''}"

    def _visit_bracketed(self, expr: expressions.Expression) -> str:
        """Return a bracketed version of the given expression."""
        return f"({self.visit(expr)})"

    @classmethod
    def _expr_precedence(cls, expr: expressions.Expression) -> int:
        """Return an integer precedence value for the given expression deciding over bracketing."""
        if isinstance(expr, operations.Operation):
            return cls.PRECEDENCE[expr.operation]
        # TODO: Might have to deal with other forms of expressions.
        #       For now, assume other forms of expression are "atomic" (i.e. constants and vars don't need brackets)
        return cls.PRECEDENCE[OperationType.call]  # Call has the precedence of brackets (highest precedence)

    @classmethod
    def _has_lower_precedence(cls, lhs: expressions.Expression, rhs: expressions.Expression) -> bool:
        """Check whether the first argument has a lower precedence than the second argument expression."""
        return cls._expr_precedence(lhs) < cls._expr_precedence(rhs)

    @staticmethod
    def _is_array_element_access(operation: operations.UnaryOperation) -> bool:
        """
        Test if unary operation is an array element access: if it is of type dereference and
        corresponding fields (array access/array_type_size) are set.
        :param operation: unary operation to be tested
        :return: true if array element access false otherwise
        """
        return operation.operation == OperationType.dereference and operation.array_info is not None and operation.operand.complexity > 1

    @staticmethod
    def _format_string_literal(constant: expressions.Constant) -> str:
        """Return an escaped version of the given string literal."""
        string_representation = str(constant)
        if string_representation.startswith('"') and string_representation.endswith('"'):
            string_representation = str(constant)[1:-1]
        if '"' in string_representation:
            escaped = string_representation.replace('"', '\\"')
            return f'"{escaped}"'
        return f"{constant}"
