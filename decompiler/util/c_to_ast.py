import tempfile
from pathlib import Path
from subprocess import PIPE, Popen
from typing import Callable, Dict, List, Optional, Type, Union

from decompiler.structures.ast.ast_nodes import (
    AbstractSyntaxTreeNode,
    CaseNode,
    CodeNode,
    ConditionNode,
    ForLoopNode,
    SeqNode,
    SwitchNode,
    WhileLoopNode,
)
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Break,
    Call,
    Condition,
    Constant,
    Continue,
    FunctionSymbol,
    ImportedFunctionSymbol,
    Instruction,
    Integer,
    ListOperation,
    OperationType,
    Pointer,
    Return,
    Type,
    TypeParser,
    UnaryOperation,
    Variable,
)
from decompiler.structures.pseudo.operations import ArrayInfo
from decompiler.task import DecompilerTask
from pycparser import CParser, c_ast


OPERATION_MAPPING = {
    "-": OperationType.minus,
    "f-": OperationType.minus_float,
    "+": OperationType.plus,
    "f+": OperationType.plus_float,
    "<<": OperationType.left_shift,
    ">>": OperationType.right_shift,
    "u>>": OperationType.right_shift_us,
    "l_rot": OperationType.left_rotate,
    "r_rot": OperationType.right_rotate,
    "r_rot_carry": OperationType.right_rotate_carry,
    "l_rot_carry": OperationType.left_rotate_carry,
    "*": OperationType.multiply,
    "u*": OperationType.multiply_us,
    "f*": OperationType.multiply_float,
    "/": OperationType.divide,
    "u/": OperationType.divide_us,
    "f/": OperationType.divide_float,
    "%": OperationType.modulo,
    "u%": OperationType.modulo_us,
    "**": OperationType.power,
    "|": OperationType.bitwise_or,
    "&": OperationType.bitwise_and,
    "^": OperationType.bitwise_xor,
    "~": OperationType.bitwise_not,
    "||": OperationType.logical_or,
    "&&": OperationType.logical_and,
    "!": OperationType.logical_not,
    "==": OperationType.equal,
    "!=": OperationType.not_equal,
    "<": OperationType.less,
    "u<": OperationType.less_us,
    ">": OperationType.greater,
    "u>": OperationType.greater_us,
    "<=": OperationType.less_or_equal,
    "u<=": OperationType.less_or_equal_us,
    ">=": OperationType.greater_or_equal,
    "u>=": OperationType.greater_or_equal_us,
    "cast": OperationType.cast,
    "point": OperationType.pointer,
    "low": OperationType.low,
    "?": OperationType.ternary,
    "func": OperationType.call,
    "->": OperationType.field,
    "list": OperationType.list_op,
    "adc": OperationType.adc,
}
COMPOUND_OPERATIONS = {
    "+=": OperationType.plus,
    "-=": OperationType.minus,
    "*=": OperationType.multiply,
    "/=": OperationType.divide,
    ">>=": OperationType.right_rotate,
}
UNARY_OPERATIONS = {
    "&": OperationType.address,
    "*": OperationType.dereference,
    "!": OperationType.logical_not,
    "-": OperationType.negate,
    "sizeof": OperationType.sizeof,
}


def _code_preprocessing(code: str) -> str:
    file_in = tempfile.NamedTemporaryFile("w", delete=False, suffix=".c")
    file_in.writelines(code)
    file_in.close()

    proc = Popen(["gcc", "-fpreprocessed", "-dD", "-E", file_in.name], stdout=PIPE)
    output, error = proc.communicate()

    result_code = ""
    for line in output.decode("utf-8").splitlines():
        if not line.startswith("#"):
            result_code += line.strip()
    return result_code


def _pyc_ast_from_code(code: str) -> c_ast.FileAST:
    return CParser().parse(_code_preprocessing(code), filename="<none>")


def _get_defined_function_symbols(file_ast: c_ast.FileAST) -> Dict[str, FunctionSymbol]:
    return {func.decl.name: FunctionSymbol(func.decl.name, func.coord) for func in file_ast.ext if isinstance(func, c_ast.FuncDef)}


def _get_function_definition(ast: c_ast.FileAST, function_name: str) -> c_ast.FuncDef:
    for external in ast.ext:
        if isinstance(external, c_ast.FuncDef) and external.decl.name == function_name:
            return external
    raise Exception(f"function '{function_name}' is not contained in code")


class PycASTVisitor:
    """Custom PycAST visitor class"""

    def __init__(self):
        self.mapping: Dict[Type[c_ast.Node], Callable] = {
            c_ast.ID: self.visit_id,
            c_ast.IdentifierType: self.visit_identifier_type,
            c_ast.FileAST: self.visit_file_ast,
            c_ast.FuncDef: self.visit_function_definition,
            c_ast.FuncDecl: self.visit_function_declaration,
            c_ast.Decl: self.visit_declaration,
            c_ast.TypeDecl: self.visit_type_declaration,
            c_ast.PtrDecl: self.visit_pointer_declaration,
            c_ast.Compound: self.visit_compound,
            c_ast.Return: self.visit_return,
            c_ast.Continue: self.visit_continue,
            c_ast.Constant: self.visit_constant,
            c_ast.If: self.visit_condition_node,
            c_ast.ParamList: self.visit_parameter_list,
            c_ast.ExprList: self.visit_expression_list,
            c_ast.Assignment: self.visit_assignment,
            c_ast.FuncCall: self.visit_function_call,
            c_ast.UnaryOp: self.visit_unary_operation,
            c_ast.BinaryOp: self.visit_binary_operation,
            c_ast.For: self.visit_for_loop,
            c_ast.DeclList: self.visit_declaration_list,
            c_ast.While: self.visit_while_loop,
            c_ast.Switch: self.visit_switch_node,
            c_ast.Case: self.visit_case_node,
            c_ast.Default: self.visit_case_node,
            c_ast.Break: self.visit_break,
            c_ast.ArrayDecl: self.visit_array_declaration,
            c_ast.ArrayRef: self.visit_array_ref,
            c_ast.Struct: self.visit_struct_declaration,
            c_ast.StructRef: self.visit_struct_ref,
            c_ast.Typename: self.visit_type_name,
        }

    def visit(self, node: c_ast.Node, **kwargs):
        if (handler := self.mapping.get(type(node))) is not None:
            return handler(node, **kwargs)

    def visit_id(self, node: c_ast.ID, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_identifier_type(self, node: c_ast.IdentifierType, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_file_ast(self, node: c_ast.FileAST, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_function_definition(self, node: c_ast.FuncDef, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_function_declaration(self, node: c_ast.FuncDecl, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_declaration(self, node: c_ast.Decl, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_type_declaration(self, node: c_ast.TypeDecl, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_pointer_declaration(self, node: c_ast.PtrDecl, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_compound(self, node: c_ast.Compound, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_return(self, node: c_ast.Return, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_continue(self, node: c_ast.Continue, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_constant(self, node: c_ast.Constant, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_condition_node(self, node: c_ast.If, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_parameter_list(self, node: c_ast.ParamList, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_expression_list(self, node: c_ast.ExprList, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_assignment(self, node: c_ast.Assignment, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_function_call(self, node: c_ast.FuncCall, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_unary_operation(self, node: c_ast.UnaryOp, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_binary_operation(self, node: c_ast.BinaryOp, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_for_loop(self, node: c_ast.For, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_declaration_list(self, node: c_ast.DeclList, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_while_loop(self, node: c_ast.While, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_switch_node(self, node: c_ast.Switch, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_case_node(self, node: c_ast.Case, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_break(self, node: c_ast.Break, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_array_declaration(self, node: c_ast.ArrayDecl, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_array_ref(self, node: c_ast.ArrayRef, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_struct_declaration(self, node: c_ast.Struct, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_struct_ref(self, node: c_ast.StructRef, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")

    def visit_type_name(self, node: c_ast.Typename, **kwargs):
        raise NotImplementedError(f"visitor for '{type(node)}' is not implemented")


class C2ASTConverter(PycASTVisitor):
    """TODO: add docstring"""

    def __init__(self):
        super().__init__()
        self.type_parser: TypeParser = TypeParser()
        self.syntax_tree: Optional[AbstractSyntaxTree] = None
        self.condition_map: Dict[LogicCondition, Condition] = {}
        self.declared_variables: Dict[str, Variable] = {}
        self.declared_function_symbols: Dict[str, FunctionSymbol] = {}
        self.declared_arrays: Dict[str, ArrayInfo] = {}

    def from_file(self, path: Path, function_name: str) -> DecompilerTask:
        """
        Generate a DecompilerTask from the given file and function name.

        :param path: path to a c file
        :param function_name: name of the target function
        :return: DecompilerTask generated from code and function name
        """

        with path.open("r") as f:
            return self.from_code("\n".join(f.readlines()), function_name)

    def from_code(self, code: str, function_name: str) -> DecompilerTask:
        """
        Generate a DecompilerTask from the given code and function name.

        :param code: C-code as string
        :param function_name: name of the target function
        :return: DecompilerTask generated from code and function name
        """

        pyc_ast = _pyc_ast_from_code(code)
        func_def = _get_function_definition(pyc_ast, function_name)

        function_return_type = self.visit(func_def.decl.type.type, decl_only=True)

        function_parameters = None
        if func_params := func_def.decl.type.args:
            function_parameters = self.visit(func_params)

        true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
        self.syntax_tree = AbstractSyntaxTree(root=SeqNode(true_value), condition_map=self.condition_map)

        if root := self.visit(func_def.body):
            self.syntax_tree._add_edge(self.syntax_tree._root, root)

        return DecompilerTask(
            cfg=None,
            options=None,
            ast=self.syntax_tree,
            name=func_def.decl.name,
            function_parameters=function_parameters,
            function_return_type=function_return_type,
        )

    # auxiliary

    def _combine_nodes(self, block_items: List[Union[Instruction, AbstractSyntaxTreeNode]]) -> AbstractSyntaxTreeNode:
        """
        Iterates over all block items (Instructions and SyntaxTreeNodes). Consecutive instructions are combined into a single CodeNode.
        If necessary, resulting SyntaxTreeNodes are added to a SeqNode.

        :param block_items: list of Instructions and AbstractSyntaxTreeNodes
        :return: AbstractSyntaxTreeNode
        """
        generated_nodes: List[AbstractSyntaxTreeNode] = []
        active_code_node: Optional[CodeNode] = None

        for item in block_items:
            if isinstance(item, Instruction):
                if active_code_node:
                    active_code_node.instructions.append(item)
                else:
                    active_code_node = CodeNode([item], LogicCondition.initialize_true(LogicCondition.generate_new_context()))
            elif isinstance(item, AbstractSyntaxTreeNode):
                if active_code_node:
                    generated_nodes.append(active_code_node)
                    active_code_node = None
                generated_nodes.append(item)

        if active_code_node:
            generated_nodes.append(active_code_node)

        if len(generated_nodes) == 1:
            self.syntax_tree._add_node(generated_nodes[0])
            return generated_nodes[0]

        self.syntax_tree._add_node(block_root := SeqNode(LogicCondition.initialize_true(LogicCondition.generate_new_context())))
        for node in generated_nodes:
            self.syntax_tree._add_node(node)
            self.syntax_tree._add_edge(block_root, node)
        return block_root

    def _add_condition(self, cond: Condition) -> LogicCondition:
        """Generate a LogicCondition for a Condition, add it to the condition map and return the condition symbol."""
        cond_symb = LogicCondition.initialize_symbol(f"x{len(self.condition_map)}")
        self.condition_map[cond_symb] = cond
        return cond_symb

    # visitor methods

    def visit(self, node: c_ast.Node, **kwargs):
        return super().visit(node, **kwargs)

    def visit_file_ast(self, node: c_ast.FileAST, **kwargs):
        pass

    def visit_compound(self, node: c_ast.Compound, **kwargs) -> AbstractSyntaxTreeNode:
        return self._combine_nodes([self.visit(block, **kwargs) for block in node.block_items] if node.block_items else [])

    def visit_id(self, node: c_ast.ID, **kwargs):
        if kwargs.get("func_call"):
            return self.declared_function_symbols.get(node.name)
        return self.declared_variables.get(node.name)

    def visit_declaration(self, node: c_ast.Decl, **kwargs) -> Union[Variable, Assignment]:
        """
        Visit variable/assignment or array declarations. In case type visiting returns a variable (array declaration) we use it directly.
        If a declaration has an initialization property we return an Assignment.
        """

        declaration_type = self.visit(node.type, **kwargs)

        if isinstance(declaration_type, Variable):
            self.declared_variables[node.name] = declaration_type
        elif isinstance(declaration_type, Assignment):
            self.declared_variables[node.name] = declaration_type.destination
            return declaration_type
        else:
            variable = Variable(node.name, declaration_type)
            self.declared_variables[node.name] = variable
            if node.init:
                return Assignment(variable, self.visit(node.init, **kwargs))
            return variable

    def visit_function_declaration(self, node: c_ast.FuncDecl, **kwargs):
        return self.visit(node.type, **kwargs), self.visit(node.args, **kwargs) if node.args else None

    def visit_function_definition(self, node: c_ast.FuncDef, **kwargs):
        if kwargs.get("decl_only", False):
            return self.visit(node.decl, **kwargs)

    def visit_function_call(self, node: c_ast.FuncCall, **kwargs) -> Union[Assignment, Call]:
        if not (function_symbol := self.visit(node.name, func_call=True, **kwargs)):
            function_symbol = ImportedFunctionSymbol(node.name.name, 0)
        call = Call(function_symbol, parameter=self.visit(node.args, **kwargs) if node.args else [])
        if kwargs.get("no_assignment"):
            return call
        return Assignment(ListOperation([]), call)

    def visit_pointer_declaration(self, node: c_ast.PtrDecl, **kwargs) -> Pointer:
        return Pointer(self.visit(node.type, **kwargs))

    def visit_type_declaration(self, node: c_ast.TypeDecl, **kwargs) -> Type:
        return self.visit(node.type, **kwargs)

    def visit_identifier_type(self, node: c_ast.IdentifierType, **kwargs) -> Type:
        return self.type_parser.parse(" ".join(node.names))

    def visit_parameter_list(self, node: c_ast.ParamList, **kwargs) -> List[Variable]:
        return [self.visit(param, **kwargs) for param in node.params]

    def visit_expression_list(self, node: c_ast.ExprList, **kwargs):
        return [self.visit(expr, **kwargs) for expr in node.exprs]

    def visit_unary_operation(self, node: c_ast.UnaryOp, **kwargs) -> Union[UnaryOperation, Assignment]:
        if node.op.startswith("p"):
            variable = self.visit(node.expr, **kwargs)
            return Assignment(variable, BinaryOperation(OPERATION_MAPPING[node.op[-1]], [variable, Constant(1, Integer.int32_t())]))
        elif op := UNARY_OPERATIONS.get(node.op):
            return UnaryOperation(op, [self.visit(node.expr, **kwargs)])

    def visit_binary_operation(self, node: c_ast.BinaryOp, **kwargs) -> Union[BinaryOperation, Condition]:
        if kwargs.get("condition"):
            return Condition(OPERATION_MAPPING[node.op], [self.visit(node.left, **kwargs), self.visit(node.right, **kwargs)])
        return BinaryOperation(OPERATION_MAPPING[node.op], [self.visit(node.left, **kwargs), self.visit(node.right, **kwargs)])

    def visit_assignment(self, node: c_ast.Assignment, **kwargs) -> Assignment:
        left_operand = self.visit(node.lvalue, **kwargs)
        right_operand = self.visit(node.rvalue, no_assignment=True, **kwargs)
        if operation := COMPOUND_OPERATIONS.get(node.op):
            return Assignment(left_operand, BinaryOperation(operation, [left_operand, right_operand]))
        if isinstance(right_operand, Call):
            return Assignment(ListOperation([left_operand]), right_operand)
        return Assignment(left_operand, right_operand)

    def visit_constant(self, node: c_ast.Constant, **kwargs):
        const_type = self.type_parser.parse(node.type)

        # TODO: still hacky
        if str(const_type) == "string":
            const_type = Pointer(Integer.char())

        const_value = node.value
        if isinstance(const_value, str):
            const_value = const_value.strip('"')
        if isinstance(const_type, Integer):
            const_value = int(const_value)
        return Constant(const_value, const_type)

    def visit_return(self, node: c_ast.Return, **kwargs):
        return Return([self.visit(node.expr, no_assignment=True, **kwargs)] if node.expr else [])

    def visit_continue(self, node: c_ast.Continue, **kwargs):
        return Continue()

    def visit_condition_node(self, node: c_ast.If, **kwargs) -> ConditionNode:
        condition = self._add_condition(self.visit(node.cond, condition=True, **kwargs))
        true_branch = self.visit(node.iftrue, **kwargs) if node.iftrue else None
        false_branch = self.visit(node.iffalse, **kwargs) if node.iffalse else None
        return self.syntax_tree._add_condition_node_with(condition, true_branch, false_branch)

    def visit_for_loop(self, node: c_ast.For, **kwargs):
        init = self.visit(node.init, **kwargs)
        condition = self.visit(node.cond, condition=True, **kwargs)
        modification = self.visit(node.next, **kwargs)
        body = self.visit(node.stmt, **kwargs)

        for_loop_node = ForLoopNode(init[0], self._add_condition(condition), modification)
        self.syntax_tree._add_node(for_loop_node)
        self.syntax_tree._add_edge(for_loop_node, body)
        return for_loop_node

    def visit_declaration_list(self, node: c_ast.DeclList, **kwargs):
        return [self.visit(decl, **kwargs) for decl in node.decls]

    def visit_while_loop(self, node: c_ast.While, **kwargs):
        condition = self.visit(node.cond, condition=True, **kwargs)
        body = self.visit(node.stmt, **kwargs)

        while_loop = WhileLoopNode(self._add_condition(condition))
        self.syntax_tree._add_node(while_loop)
        self.syntax_tree._add_edge(while_loop, body)

        return while_loop

    def visit_switch_node(self, node: c_ast.Switch, **kwargs) -> SwitchNode:
        self.syntax_tree._add_node(switch_node := SwitchNode(switch_expression := self.visit(node.cond, **kwargs)))
        for case_node in node.stmt.block_items:
            self.syntax_tree._add_edge(switch_node, self.visit(case_node, switch_expression=switch_expression, **kwargs))
        return switch_node

    def visit_case_node(self, node: Union[c_ast.Case, c_ast.Default], **kwargs) -> CaseNode:
        """Handles c_ast Case and Default nodes"""

        case_stmts = [self.visit(stmt, **kwargs) for stmt in node.stmts]
        is_break_node = any(isinstance(n, Break) for n in case_stmts)
        case_child = self._combine_nodes([instr for instr in case_stmts if not isinstance(instr, Break)])
        case_node = CaseNode(
            expression=kwargs.get("switch_expression"),
            constant=self.visit(node.expr, **kwargs) if isinstance(node, c_ast.Case) else "default",
            break_case=is_break_node,
        )
        self.syntax_tree._add_node(case_node)
        self.syntax_tree._add_edge(case_node, case_child)
        return case_node

    def visit_break(self, node: c_ast.Break, **kwargs) -> Break:
        return Break()

    def visit_array_declaration(self, node: c_ast.ArrayDecl, **kwargs):
        """Stores the declared array as variable"""
        decl_name = node.type.declname
        base_type = self.visit(node.type)
        dim = self.visit(node.dim)

        destination = Variable(decl_name, vartype=Pointer(base_type), ssa_name=Variable(decl_name, base_type, ssa_label=0))
        operation_sizeof = UnaryOperation(OperationType.sizeof, [Constant(base_type)])
        memory_block_size = BinaryOperation(OperationType.multiply, [dim, operation_sizeof])

        return Assignment(destination, Call(ImportedFunctionSymbol("malloc", 0), [memory_block_size]))

    def visit_array_ref(self, node: c_ast.ArrayRef, **kwargs):
        """This could be called without prior array declaration in case of dynamically generated arrays: 'malloc(sizeof(int) * 10)'"""
        base_variable: Variable = self.visit(node.name, **kwargs)
        subscript: Union[int, Variable] = self.visit(node.subscript)
        return UnaryOperation(
            OperationType.dereference,
            [BinaryOperation(OperationType.plus, [base_variable, subscript])],
            # array_info=ArrayInfo(base=base_variable, index=subscript, confidence=True),
        )

    def visit_struct_declaration(self, node: c_ast.Struct, **kwargs):
        # return [self.visit(dcl, **kwargs) for dcl in node.decls]
        raise NotImplementedError("Structs are not supported")

    def visit_struct_ref(self, node: c_ast.StructRef, **kwargs):
        raise NotImplementedError("Structs are not supported")

    def visit_type_name(self, node: c_ast.Typename, **kwargs) -> Constant:
        """Returns a Constant representation of a type e.g. int. This is used for sizeof(type) UnaryOperation."""
        return Constant(self.visit(node.type, **kwargs))
