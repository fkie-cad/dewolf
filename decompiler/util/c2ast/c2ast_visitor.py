from enum import Enum, auto
from typing import Any, Dict, Union

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, VirtualRootNode
from decompiler.structures.ast.condition_symbol import ConditionHandler
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo import (
    SHORTHANDS,
    Assignment,
    BinaryOperation,
    Break,
    Call,
    Condition,
    Constant,
    Continue,
    CustomType,
    Expression,
    Float,
    FunctionSymbol,
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
from pycparser import c_ast
from pycparser.c_ast import NodeVisitor

OPERATIONS: dict[str, OperationType] = {v: k for k, v in SHORTHANDS.items()} # reverse dict to get from a string to DeWolf Operation
OPERATIONS_COMPOUND: dict[str, OperationType] = {
    "+=": OperationType.plus,
    "-=": OperationType.minus,
    "*=": OperationType.multiply,
    "/=": OperationType.divide,
    ">>=": OperationType.right_rotate,
}

"""
C Unary Operations:
    - Increment: ++x, x++
    - Decrement: --x, x--
    - Address: &x
    - Indirection: *x
    - Positive: +x
    - Negative: -x
    - Complement (one): ~x
    - Negation: !x
    - Sizeof: sizeof(x)
    - Cast: (type) x <== not used by PyCParser (will generate a Cast Node, hopefully?)
"""

OPERATIONS_UNARY: dict[str, OperationType] = {
    "p++": OperationType.plus,
    "++": OperationType.plus,
    "p--": OperationType.minus,
    "--": OperationType.minus,
    "&": OperationType.address,
    "*": OperationType.dereference,
    "+": OperationType.plus,
    "-": OperationType.minus,
    "~": OperationType.negate,
    "!": OperationType.logical_not,
    "sizeof": OperationType.sizeof
}

def _resolve_constant(type: Type, value: str) -> Constant:
    """Resolve PyCAST constant:
        - the value will always be a string (e.G. 'int', 'float'... JUST WHY)
        - the type is already converted by the TypeParser
    """
    realValue = "Not_resolved"

    if isinstance(type, Float):
        realValue = float(value)

    if isinstance(type, Integer):
        bases = [8, 16, 10] # Octal, Hex, Dez
        for base in bases:
            try:
                realValue = int(value, base)
                break
            except ValueError:
                continue
    
    if isinstance(type, CustomType):
        realValue = value

    return Constant(realValue, type)


def _combine_logic_conditions(condA: LogicCondition, condB: LogicCondition, operation: OperationType) -> LogicCondition:
    match(operation):
        case OperationType.logical_and:
            return condA & condB
        case OperationType.logical_or:
            return condA | condB
        case _:
            raise ValueError(f"OperationType {operation} not supported")


class PyCNodeVisitor(NodeVisitor):
    """Visitor for nodes from PyCParser.
        - should only be used for one method of the PyCParserAST, therefore an caller should start calling visit with an `FuncDef` node
        - after visiting an DeWolf AST will be available for use

        PyCParser NodeVisitor notes:
        - visitor methods are called by there respective class after the `visit_` identifier (by `NodeVisitor.visit`)
        - if no visitor method exists for a class, then all children of that class will be visited by `NodeVisitor.generic_visit` (not recommended)
    """

    def __init__(self):
        self._condition_handler: ConditionHandler = ConditionHandler()
        self._ast: AbstractSyntaxTree = AbstractSyntaxTree(VirtualRootNode(self._condition_handler.get_true_value()), self._condition_handler.get_condition_map()) 

        self._function_name = None
        self._function_params: list[Variable] = []
        self._return_type = None

        self._declared_variables: Dict[str, Variable] = {}
        self._typedefs: Dict[str, Type] = {}

        # Temp variables 
        self._switch_condition: Expression = None # Needed because no parent reference + case needs switch statement


    def _resolve_condition(self, cond: Any) -> Condition:
        """Resolve/Repair visited C conditions so they work with Logic"""
        if isinstance(cond, Condition):
            return cond
        if isinstance(cond, Constant): # if(true/false/0/1.../42.069)
            return Condition(OperationType.not_equal, [cond, Constant(0)]) # maybe a better representation?
        if isinstance(cond, UnaryOperation): # if(!var)
            return Condition(OperationType.equal, [cond.operands[0], Constant(0)])
        if isinstance(cond, Variable): # if(var)
            return Condition(OperationType.not_equal, [cond, Constant(0)]) # maybe a better representation?
        raise ValueError(f"No resolving for fake condition with type {type(cond)}")


    def _get_symbol_for_condition(self, cond: Any) -> LogicCondition:
        """Resolve into real condition + return symbol it receives"""
        return self._condition_handler.add_condition(self._resolve_condition(cond))


    def _resolve_binary_operation(self, cond: BinaryOperation):
        """Recursively resolve a given BinaryOperation into a statement of condition symbols (e.G. x1 & x2)"""
        operands = []
        for expr in cond:
            if isinstance(expr, BinaryOperation):
                operands.append(self._resolve_binary_operation(expr))
            else:
                operands.append(expr)

        # Case missing: both variables

        # 1. If all expressions, make a new condition and return the symbol
        if all(isinstance(operand, Expression) for operand in operands):
            newCond = Condition(cond.operation, operands)
            symbol = self._condition_handler.add_condition(newCond)
            return symbol
        # 2. If only one is a symbol, the other one must be convertible to a symbol
        if isinstance(operands[0], Expression):
            operands[0] = self._get_symbol_for_condition(operands[0])
        elif isinstance(operands[1], Expression):
            operands[1] = self._get_symbol_for_condition(operands[1])
        # 3. If both symbols, combine symbols to new one
        if all(isinstance(operand, LogicCondition) for operand in operands):
            return _combine_logic_conditions(operands[0], operands[1], cond.operation)
        raise ValueError("What just happened?")

    
    def _resolve_condition_and_get_logic_condition(self, cond: Any) -> LogicCondition:
        """Resolve condition + add into condition handler + return symbol"""
        if isinstance(cond, BinaryOperation):
            return self._resolve_binary_operation(cond)
        return self._condition_handler.add_condition(self._resolve_condition(cond))


    def _merge_instructions_and_nodes(self, stmts: list[Union[AbstractSyntaxTreeNode, Instruction]], parent: AbstractSyntaxTreeNode): # fertig
        """Merge a list of Instructions/ASTNodes with respect to order:
            - multiple instructions will be merged into CodeNodes
            - DeWolf AST nodes will simply be added
        """
        instructions = []

        for stmt in stmts:
            if isinstance(stmt, Instruction):
                instructions.append(stmt)
                continue
            if isinstance(stmt, AbstractSyntaxTreeNode):
                if len(instructions) > 0:
                    codeNode = self._ast.factory.create_code_node([instr for instr in instructions]) # real copy
                    self._ast._add_node(codeNode)
                    instructions.clear()
                    self._ast._add_edge(parent, codeNode)
                self._ast._add_edge(parent, stmt)

        if len(instructions) > 0:
            codeNode = self._ast.factory.create_code_node([instr for instr in instructions]) # real copy
            self._ast._add_node(codeNode)
            self._ast._add_edge(parent, codeNode)


    def visit_ArrayDecl(self, node: c_ast.ArrayDecl): # To do
        """Visit array declaration. Properties: [type*, dim*, dim_quals]"""
        return None


    def visit_ArrayRef(self, node: c_ast.ArrayRef): # To do
        """Visit array reference. Properties: [name*, subscript*]"""
        return None
    

    def visit_Assignment(self, node: c_ast.Assignment): # fertig
        """Visit assignment. Properties: [op, lvalue*, rvalue*]"""
        left = self.visit(node.lvalue)
        right = self.visit(node.rvalue)
        if operation := OPERATIONS_COMPOUND.get(node.op):
            return Assignment(left, BinaryOperation(operation, [left, right]))
        if isinstance(right, Call):
            return Assignment(ListOperation([left]), right)
        return Assignment(left, right)


    def visit_Alignas(self, node: c_ast.Alignas):
        """Visit alignas specifier. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_BinaryOp(self, node: c_ast.BinaryOp): # fertig
        """Visit binary operation. Properties: [op, left*, right*]"""
        return BinaryOperation(OPERATIONS[node.op], [self.visit(node.left), self.visit(node.right)])


    def visit_Break(self, _: c_ast.Break): # fertig
        """Visit break node. Properties: []"""
        return Break()


    def visit_Case(self, node: c_ast.Case): # fertig
        """Visit case node. Properties: [expr*, stmts**]"""
        stmts = [self.visit(stmt) for stmt in node.stmts] if node.stmts else []
        caseNode = self._ast.factory.create_case_node(self._switch_condition, self.visit(node.expr), break_case=any(isinstance(item, Break) for item in stmts))
        seqNode = self._ast.factory.create_seq_node() 
        self._ast._add_nodes_from([caseNode, seqNode])
        self._ast._add_edge(caseNode, seqNode)
        self._merge_instructions_and_nodes(stmts, seqNode)
        return caseNode


    def visit_Cast(self, node: c_ast.Cast): # fertig 
        """Visit cast. Properties: [to_type*, expr*]"""
        return UnaryOperation(OperationType.cast, [self.visit(node.expr)], self.visit(node.to_type))


    def visit_Compound(self, node: c_ast.Compound): # fertig
        """Visit compound (Block of instructions). Properties: [block_items**]"""
        seqNode = self._ast.factory.create_seq_node()
        self._ast._add_node(seqNode)
        stmts = [self.visit(stmt) for stmt in node.block_items] if node.block_items else []
        self._merge_instructions_and_nodes(stmts, seqNode)
        return seqNode


    def visit_CompoundLiteral(self, node: c_ast.CompoundLiteral):
        """Visit compound literatl. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_Constant(self, node: c_ast.Constant): # fertig
        """Visit constant. Properties: [type, value]"""
        return _resolve_constant(TypeParser().parse(node.type), node.value)


    def visit_Continue(self, _: c_ast.Continue): # fertig
        """Visit continue. Properties: []"""
        return Continue()


    def visit_Decl(self, node: c_ast.Decl): # fertig
        """Visit declaration. Properties: [name, quals, align, storage, funcspec, type*, init*, bitsize*]""" 
        var = Variable(node.name, self.visit(node.type))
        self._declared_variables[node.name] = var

        if node.init:
            return Assignment(var, self.visit(node.init))
        
        return None


    def visit_DeclList(self, node: c_ast.DeclList): # fertig
        """Visit list of declarations. Properties: [decls**]"""
        return [self.visit(delc) for delc in node.decls]


    def visit_Default(self, node: c_ast.Default): # to do Switch Condition into case
        """Visit default node. Properties: [stmts**]"""
        stmts = [self.visit(stmt) for stmt in node.stmts] if node.stmts else []
        defaultNode = self._ast.factory.create_case_node(self._switch_condition, "default" , break_case=any(isinstance(item, Break) for item in stmts)) # Fix condition switch
        self._ast._add_node(defaultNode)
        self._merge_instructions_and_nodes(stmts, defaultNode)
        return defaultNode


    def visit_DoWhile(self, node: c_ast.DoWhile): # Fertig
        """Visit do while node. Properties: [cond*, stmt*]""" 
        doWhileNode = self._ast.factory.create_do_while_loop_node(self._resolve_condition_and_get_logic_condition(self.visit(node.cond)))
        self._ast._add_node(doWhileNode)
        self._ast._add_edge(doWhileNode, self.visit(node.stmt))
        return doWhileNode


    def visit_EllipsisParam(self, node: c_ast.EllipsisParam):
        """Visit ellipsis params (... argument in printf for example). Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_EmptyStatement(self, node: c_ast.EmptyStatement): # fertig
        """Visit empty statement (;). Properties: []"""
        return None


    def visit_Enum(self, node: c_ast.Enum):
        """Visit enumeration. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_Enumerator(self, node: c_ast.Enumerator):
        """Visit enumeration values. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_EnumeratorList(self, node: c_ast.EnumeratorList):
        """Visit list of enumerations. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_ExprList(self, node: c_ast.ExprList):
        """Visit list of expressions (expr1, expr2, ...). Properties: [exprs**]"""
        return [self.visit(expr) for expr in node.exprs]


    def visit_FileAST(self, _: c_ast.FileAST):
        """Visit whole file. Not supported"""
        raise ValueError("visitor only works for specified methods")


    def visit_For(self, node: c_ast.For): # fertig, washed
        """Visit for loop. Properties: [init*, cond*, next*, stmt*]"""
        decl = self.visit(node.init) if node.init else None # always a list if at least one item, else None
        cond = self.visit(node.cond) if node.cond else Constant(0, Integer.uint32_t()) # Empty conditions are allowed, we need to fix this manually
        modi = self.visit(node.next) if node.next else None # Will be a instruction (if one modification) or a list if more then one or None (WHYY)

        if isinstance(modi, Instruction):
            modi = [modi]

        loop_decl = decl.pop() if decl else None
        loop_modi = modi.pop() if modi else None

        loopNode = self._ast.factory.create_for_loop_node(loop_decl, self._resolve_condition_and_get_logic_condition(cond), loop_modi)
        self._ast._add_node(loopNode)
        body = self.visit(node.stmt)
        self._ast._add_edge(loopNode, body)
        if modi: # If more then one modification, append them at body; No guarantee that modification is same variable as init
            self._merge_instructions_and_nodes(modi, body)
        return loopNode


    def visit_FuncCall(self, node: c_ast.FuncCall): # To do
        """Visit function call. Properties: [name*, args*]"""
        return Assignment(ListOperation([]), Call(FunctionSymbol(self.visit(node.name), 0), self.visit(node.args)))


    def visit_FuncDecl(self, node: c_ast.FuncDecl):
        """Visit function declaration. Properties: [args*, type*]"""
        self._function_params = self.visit(node.args)
        self._return_type = self.visit(node.type)
        return None # This visitor only supports visiting one function, therefore there can be only one declaration


    def visit_FuncDef(self, node: c_ast.FuncDef):
        """Visit function definition + body. Properties: [decl*, param_decls*, body*]"""
        self.visit(node.decl)
        self._ast._add_edge(self._ast.root, self.visit(node.body))
        self._ast.clean_up() # Clean up empty seq nodes etc.
        self._ast.condition_map = self._condition_handler.get_condition_map() # lazy conditionmap update
        return None # Same as above 


    def visit_Goto(self, node: c_ast.Goto):
        """Visit goto. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_ID(self, node: c_ast.ID): # fertig
        """Visit variable usage (which was already declared). Properties: [name]"""
        return self._declared_variables.get(node.name, node.name) # If defined return variable, if not, return name (string)


    def visit_IdentifierType(self, node: c_ast.IdentifierType): # Names can be a list with signed stuff (signed char)
        """Visit built in types or typedefs. Properties: [names]"""
        return TypeParser().parse(*node.names)


    def visit_If(self, node: c_ast.If): # fertig
        """Visit if node. Properties: [cond*, iftrue*, iffalse*]"""
        ifNode = self._ast.factory.create_condition_node(self._resolve_condition_and_get_logic_condition(self.visit(node.cond)))
        self._ast._add_node(ifNode)

        childs = [(node.iftrue, self._ast.factory.create_true_node()), (node.iffalse, self._ast.factory.create_false_node())]
        childs = [x for x in childs if x[0] is not None] # remove empty node tuple

        for pyCBranchNode, DeWolfBranch in childs:
            self._ast._add_node(DeWolfBranch)
            self._ast._add_edge(ifNode, DeWolfBranch)
            body = self.visit(pyCBranchNode)
            if isinstance(body, AbstractSyntaxTreeNode):
                self._ast._add_node(body)
                self._ast._add_edge(DeWolfBranch, body)
            else:
                self._merge_instructions_and_nodes([body], DeWolfBranch)
                
        return ifNode


    def visit_InitList(self, node: c_ast.InitList): # To do x = y = 0;?
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_Label(self, node: c_ast.Label):
        """Visit label. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_NamedInitializer(self, node): # ???
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_ParamList(self, node: c_ast.ParamList): # fertig
        """Visit function params. Properties: [params**]"""
        return [self.visit(param) for param in node.params]

    
    def visit_Pragma(self, node: c_ast.Pragma):
        """Visit pragma. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_PtrDecl(self, node: c_ast.PtrDecl): # fertig
        """Visit pointer declaration. Properties: [quals, type*]"""
        return Pointer(self.visit(node.type))


    def visit_Return(self, node: c_ast.Return): # fertig
        """Visit return statement. Properties: [expr*]"""
        codeNode = self._ast.factory.create_code_node([Return([self.visit(node.expr)])])
        self._ast._add_node(codeNode)
        return codeNode


    def visit_StaticAssert(self, node: c_ast.StaticAssert):
        """Visit static assert. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_Struct(self, node: c_ast.Struct):
        """Visit struct. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_StructRef(self, node: c_ast.StructRef):
        """Visit struct reference. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_Switch(self, node: c_ast.Switch): # fertig, condition, 
        """Visit switch node. Properties: [cond*, stmt*]"""
        switchNode = self._ast.factory.create_switch_node(self._resolve_condition(self.visit(node.cond)))
        self._ast._add_node(switchNode)
        if body := self.visit(node.stmt): # Body will always be a SeqNode (CompoundNode) (which has only case nodes als childs) or nothing
            [self._ast._add_edge(switchNode, child) for child in body.children]
            self._ast._remove_node(body)
        return switchNode


    def visit_TernaryOp(self, node: c_ast.TernaryOp): # to do
        """Visit ternary operation (short if). Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_TypeDecl(self, node: c_ast.TypeDecl): # fertig
        """Visit type declaration. Properties: [declname, quals, align, type*]"""
        return self.visit(node.type)


    def visit_Typedef(self, node: c_ast.Typedef): # fertig
        """Visit typedef. Properties: [name, quals, storage, type*]"""
        self._typedefs[node.name] = self.visit(node.type)


    def visit_Typename(self, node: c_ast.Typename): # fertig
        """Visit type name (in casts). Properties: [name, quals, align, type*]"""
        return self.visit(node.type)


    def visit_UnaryOp(self, node: c_ast.UnaryOp): # fertig
        """Visit unary operation. Properties: [op, expr*]"""
        variable: Variable = self.visit(node.expr)
        if node.op.startswith("p"): # pre/post increment (++x, x++)
            return Assignment(self.visit(node.expr), BinaryOperation(OPERATIONS_UNARY[node.op], [variable, Constant(1, Integer.int32_t())], variable.type))
        if node.op == "+" or node.op == "-": # not a assignment, just a statement
            return UnaryOperation(OPERATIONS_UNARY[node.op], [variable, Constant(1, Integer.int32_t())], variable.type)
        return UnaryOperation(OPERATIONS_UNARY[node.op], [variable], variable.type)


    def visit_Union(self, node: c_ast.Union):
        """Visit union. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")


    def visit_While(self, node: c_ast.While):
        """Visit while loop. Properties: [cond*, stmt*]"""
        whileNode = self._ast.factory.create_while_loop_node(self._resolve_condition_and_get_logic_condition(self.visit(node.cond)))
        self._ast._add_node(whileNode)
        body = self.visit(node.stmt)
        self._ast._add_edge(whileNode, body)
        return whileNode
