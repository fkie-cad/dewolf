import logging
from itertools import chain, repeat

from decompiler.structures import pseudo as expressions
from decompiler.structures.pseudo import (
    ArrayType,
    CustomType,
    Float,
    FunctionTypeDef,
    GlobalVariable,
    Integer,
    OperationType,
    Pointer,
    Type,
)
from decompiler.structures.pseudo import instructions as instructions
from decompiler.structures.pseudo import operations as operations
from decompiler.structures.pseudo.complextypes import Struct
from decompiler.structures.pseudo.operations import MemberAccess
from decompiler.structures.visitors.interfaces import DataflowObjectVisitorInterface
from decompiler.util.integer_util import normalize_int

MAX_GLOBAL_INIT_LENGTH = 128
INLINE_STRUCT_STRINGS = True
DETECT_STRUCT_STRINGS = True


def get_struct_string_address_offset(vartype) -> int | None:
    """This function return the offset of its address field if the vartype is a "struct string".
    Otherwise it returns None.

    struct strings are structs comprising of a length and a pointer to string data.
    The code does not assume whether data or length comes first. The loop is for determining the order.
    """
    if not isinstance(vartype, Struct):
        return None
    if len(vartype.members) != 2:
        return None
    address_offset = None
    length_offset = None
    for offset, member in vartype.members.items():
        match member.type:
            case Pointer(type=Integer(size=8)):
                address_offset = offset
            case Integer():
                length_offset = offset
            case _:
                return None
    if address_offset is None or length_offset is None:
        return None
    return address_offset


def is_struct_string(vartype) -> bool:
    """Checks if a vartype represents a "struct string" (i.e. a struct comprising of a length and a pointer to string data) or not."""
    if not DETECT_STRUCT_STRINGS:
        return False
    return get_struct_string_address_offset(vartype) is not None


def get_data_of_struct_string(variable) -> GlobalVariable:
    """Returns the data of a "struct string" (i.e. a struct comprising of a length and a pointer to string data)."""
    address_offset = get_struct_string_address_offset(variable.type)
    address = variable.initial_value.value[address_offset]
    return address


def inline_global_variable(var) -> bool:
    """Decides whether or not to inline a global variable."""
    if not var.is_constant:
        return False
    match var.type:
        case ArrayType():
            if var.type.type in [Integer.char(), CustomType.wchar16(), CustomType.wchar32()]:
                return True
        case Struct():
            if INLINE_STRUCT_STRINGS and is_struct_string(var.type):
                return True
        case _:
            return False
    return False


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
        OperationType.member_access: ".",
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
        OperationType.member_access: 150,
        OperationType.list_op: 10,
        # TODO: Figure out what these are / how to handle this
        # OperationType.adc: "adc",
    }

    ESCAPE_TABLE = str.maketrans(
        {"\\": r"\\", '"': r"\"", "'": r"\'", "\n": r"\n", "\r": r"\r", "\t": r"\t", "\v": r"\v", "\b": r"\b", "\f": r"\f", "\0": r"\0"}
    )

    def visit_unknown_expression(self, expr: expressions.UnknownExpression) -> str:
        """Return the error message for this UnknownExpression."""
        return expr.msg

    def visit_constant(self, expr: expressions.Constant) -> str:
        """Return constant in a format that will be parsed correctly by a compiler."""
        if isinstance(expr, expressions.NotUseableConstant):
            return expr.value
        if isinstance(expr, expressions.Symbol):
            return expr.name
        if isinstance(expr.type, Integer):
            value = self._get_integer_literal_value(expr)
            return self._format_integer_literal(expr.type, value)
        if isinstance(expr.type, Pointer):
            match (expr.value):
                case (
                    str()
                ):  # Technically every string will be lifted as an ConstantArray. Will still leave this, if someone creates a string as a char*
                    string = expr.value if len(expr.value) <= MAX_GLOBAL_INIT_LENGTH else expr.value[:MAX_GLOBAL_INIT_LENGTH] + "..."
                    match expr.type.type:
                        case CustomType(text="wchar16") | CustomType(text="wchar32"):
                            return f'L"{string}"'
                        case _:
                            return f'"{string}"'
                case bytes():
                    val = "".join("\\x{:02x}".format(x) for x in expr.value)
                    return f'"{val}"' if len(val) <= MAX_GLOBAL_INIT_LENGTH else f'"{val[:MAX_GLOBAL_INIT_LENGTH]}..."'
        if isinstance(expr.type, ArrayType):
            match expr.type.type:
                case CustomType(text="wchar16") | CustomType(text="wchar32"):
                    val = "".join(expr.value).translate(self.ESCAPE_TABLE)
                    return f'L"{val}"' if len(val) <= MAX_GLOBAL_INIT_LENGTH else f'L"{val[:MAX_GLOBAL_INIT_LENGTH]}..."'
                case Integer(size=8, signed=False):
                    val = "".join([f"\\x{x:02X}" for x in expr.value][:MAX_GLOBAL_INIT_LENGTH])
                    return f'"{val}"' if len(val) <= MAX_GLOBAL_INIT_LENGTH else f'"{val[:MAX_GLOBAL_INIT_LENGTH]}..."'
                case Integer(8):
                    val = "".join(expr.value[:MAX_GLOBAL_INIT_LENGTH]).translate(self.ESCAPE_TABLE)
                    return f'"{val}"' if len(val) <= MAX_GLOBAL_INIT_LENGTH else f'"{val[:MAX_GLOBAL_INIT_LENGTH]}..."'
                case _:
                    return f'{", ".join([self.visit_constant(expressions.Constant(x, expr.type.type)) for x in expr.value]).translate(self.ESCAPE_TABLE)}'  # Todo: Should we print every member? Could get pretty big

        return self._format_string_literal(expr)

    def visit_variable(self, expr: expressions.Variable) -> str:
        """Return a string representation of the variable."""
        return f"{expr.name}" if (label := expr.ssa_label) is None else f"{expr.name}_{label}"

    def visit_global_variable(self, expr: expressions.GlobalVariable):
        """Inline a global variable if its initial value is constant and not of void type"""
        if inline_global_variable(expr):
            if is_struct_string(expr.type):
                return self.visit(get_data_of_struct_string(expr))
            return self.visit(expr.initial_value)
        return expr.name

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
        if op.operation == OperationType.address and isinstance(op.operand, GlobalVariable) and isinstance(op.operand.type, ArrayType):
            return operand
        if isinstance(op, MemberAccess):
            operator_str = "->" if isinstance(op.struct_variable.type, Pointer) else self.C_SYNTAX[op.operation]
            return f"{operand}{operator_str}{op.member_name}"
        if op.operation == OperationType.cast and op.contraction:
            return f"({int(op.type.size / 8)}: ){operand}"
        if op.operation == OperationType.cast:
            if op.type == op.operand.type:
                return operand
            elif isinstance(op.operand, expressions.Constant):
                if isinstance(op.type, Integer) and isinstance(op.operand.type, Integer):
                    value = self._get_integer_literal_value(op.operand)
                    eliminated_val = expressions.Constant(value, op.type)
                    try:
                        if self._get_integer_literal_value(eliminated_val) == value:
                            return self.visit(eliminated_val)
                    except ValueError:
                        pass
                elif isinstance(op.type, Float) and isinstance(op.operand.type, Float):
                    return self.visit(op.operand)
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
        func_expr_str = self._visit_bracketed(op.function) if self._has_lower_precedence(op.function, op) else self.visit(op.function)

        output = f"{func_expr_str}("
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

    def _get_integer_literal_value(self, literal: expressions.Constant) -> int:
        """
        Return the right integer value for the given type, assuming that the
        re-compilation host has the same sizes as the decompilation host.
        """
        return normalize_int(literal.value, literal.type.size, literal.type.is_signed)

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

    @staticmethod
    def format_variables_declaration(var_type: Type, var_names: list[str]) -> str:
        """Return a string representation of variable declarations."""
        match var_type:
            case Pointer(type=FunctionTypeDef() as fun_type):
                parameter_names = ", ".join(str(parameter) for parameter in fun_type.parameters)
                declarations_without_return_type = [f"(* {var_name})({parameter_names})" for var_name in var_names]
                return f"{fun_type.return_type} {', '.join(declarations_without_return_type)}"
            case ArrayType():
                return f"{var_type.type}* {', '.join(var_names)}"
            case _:
                return f"{var_type} {', '.join(var_names)}"
