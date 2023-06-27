from typing import Dict, Union, Any

from decompiler.structures.ast.ast_nodes import AbstractSyntaxTreeNode, SeqNode
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

OPERATIONS_UNARY: dict[str, OperationType] = {
    "&": OperationType.address,
    "*": OperationType.dereference,
    "!": OperationType.logical_not,
    "-": OperationType.negate,
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
        self._ast: AbstractSyntaxTree = AbstractSyntaxTree(SeqNode(self._condition_handler.get_true_value()), self._condition_handler.get_condition_map())

        self._function_name = None
        self._function_params: list[Variable] = []
        self._return_type = None

        self._declared_variables: Dict[str, Variable] = {}


    def _resolve_condition(self, cond: Any) -> Condition:
        """Resolve/Repair visited C conditions into DeWolf conditions"""
        if isinstance(cond, Condition):
            return cond
        if isinstance(cond, Constant): # if(true/false/0/1.../42.069)
            return Condition(OperationType.not_equal, [Constant(0), cond])
        if isinstance(cond, BinaryOperation): # if(a < b)
            return Condition(cond.operation, [cond.left, cond.right], cond.type)
        if isinstance(cond, UnaryOperation):
            return Condition(OperationType.not_equal, [cond.operands[0], Constant(0)])
        if isinstance(cond, Variable): # if(var)
            return Condition(OperationType.equal, [cond, Constant(1)]) # make it to true
        raise ValueError(f"No resolving for fake condition with type {type(cond)}")

    
    def _resolve_condition_and_get_logic_condition(self, cond: Any) -> LogicCondition:
        """Resolve condition + add into condition handler + return symbol"""
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
        return Pointer(self.visit(node.type)) # Looses the dimensions etc, do we have a arraytype (except offset ref)?

    def visit_ArrayRef(self, node: c_ast.ArrayRef): # To do
        """Visit array reference. Properties: [name*, subscript*]"""
        return None # To do # visit array at index x 
    
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
        caseNode = self._ast.factory.create_case_node(None, self.visit(node.expr), break_case=any(isinstance(item, Break) for item in stmts)) # Fix condition switch
        self._ast._add_node(caseNode)
        seqNode = self._ast.factory.create_seq_node() 
        self._ast._add_node(seqNode)
        self._ast._add_edge(caseNode, seqNode)
        self._merge_instructions_and_nodes(stmts, seqNode)
        return caseNode

    def visit_Cast(self, node: c_ast.Cast): # to do test typedefs 
        """Visit cast. Properties: [to_type*, expr*]"""
        variable: Variable = self.visit(node.expr)
        return UnaryOperation(OperationType.cast, [variable], variable.type)

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

        if node.init: # Func params will always have no init, therefore will always be not returned
            return Assignment(var, self.visit(node.init))
        
        return None

    def visit_DeclList(self, node: c_ast.DeclList): # fertig
        """Visit list of declarations. Properties: [decls**]"""
        return [self.visit(delc) for delc in node.decls]

    def visit_Default(self, node: c_ast.Default): # to do Switch Condition into case
        """Visit default node. Properties: [stmts**]"""
        stmts = [self.visit(stmt) for stmt in node.stmts] if node.stmts else []
        defaultNode = self._ast.factory.create_case_node(None, "default" , break_case=any(isinstance(item, Break) for item in stmts)) # Fix condition switch
        self._ast._add_node(defaultNode)
        self._merge_instructions_and_nodes(stmts, defaultNode)
        return defaultNode

    def visit_DoWhile(self, node: c_ast.DoWhile): # Fertig
        """Visit do while node. Properties: [cond*, stmt*]"""
        
        doWhileNode = self._ast.factory.create_do_while_loop_node(self._resolve_condition_and_get_logic_condition(self.visit(node.cond)))
        self._ast._add_node(doWhileNode)
        body = self.visit(node.stmt)
        self._ast._add_edge(doWhileNode, body)
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

    def visit_FileAST(self, node: c_ast.FileAST):
        """Visit whole file. Not supported"""
        raise ValueError("visitor only works for specified methods")

    def visit_For(self, node: c_ast.For): # To do
        """Visit for loop. Properties: [init*, cond*, next*, stmt*]"""
        decl = self.visit(node.init) if node.init else None # is a list if there are one (multiple declarations are allowed in for)
        cond = self.visit(node.cond) # can be a constant or any other valid C condition
        modi = self.visit(node.next) if node.next else None # C does allow multiple ones?

        loop_decl = decl[0] if decl else None

        loopNode = self._ast.factory.create_for_loop_node(loop_decl, self._resolve_condition_and_get_logic_condition(self.visit(node.cond)), modi)
        # Fix multiple declaration + create condition if it is not a real one
        self._ast._add_node(loopNode)
        body = self.visit(node.stmt)
        self._ast._add_edge(loopNode, body)
        return loopNode

    def visit_FuncCall(self, node: c_ast.FuncCall): # To do
        """Visit function call. Properties: [name*, args*]"""
        return Call(FunctionSymbol(self.visit(node.name), 0), [self.visit(node.args)])

    def visit_FuncDecl(self, node: c_ast.FuncDecl):
        """Visit function declaration. Properties: [args*, type*]"""
        self._function_params = self.visit(node.args)
        self._return_type = self.visit(node.type)
        return None # This visitor only supports one function, therefore there can be only one declaration

    def visit_FuncDef(self, node: c_ast.FuncDef):
        """Visit function definition + body. Properties: [decl*, param_decls*, body*]"""
        self.visit(node.decl) # Again visitor only works on one function
        self._ast._add_edge(self._ast.root, self.visit(node.body)) # we have an empty seq node as a root 
        self._ast.clean_up() # clean up will remove it and point to the body (other seqNode)
        return None

    def visit_Goto(self, node: c_ast.Goto):
        """Visit goto. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")

    def visit_ID(self, node: c_ast.ID): # fertig, Undeclared stuff?
        """Visit variable usage (which was already declared). Properties: [name]"""
        return self._declared_variables.get(node.name, node.name)

    def visit_IdentifierType(self, node: c_ast.IdentifierType):
        """Visit built in types or typedefs. Properties: [names]"""
        return TypeParser().parse(*node.names)

    def visit_If(self, node: c_ast.If): # fertig, fix condition
        """Visit if node. Properties: [cond*, iftrue*, iffalse*]"""
        ifNode = self._ast.factory.create_condition_node(self._resolve_condition_and_get_logic_condition(self.visit(node.cond)))
        self._ast._add_node(ifNode)
        if node.iftrue: # hier
            trueNode = self._ast.factory.create_true_node()
            body = self.visit(node.iftrue)
            if body:
                self._ast._add_node(trueNode)
                self._ast._add_edge(ifNode, trueNode)
                if isinstance(body, AbstractSyntaxTreeNode):
                    self._ast._add_node(body)
                    self._ast._add_edge(trueNode, body)
                else:
                    self._merge_instructions_and_nodes([body], trueNode)


        if node.iffalse:
            falseNode = self._ast.factory.create_false_node()
            body = self.visit(node.iffalse)
            if body:
                self._ast._add_node(falseNode)
                self._ast._add_edge(ifNode, falseNode)
                if isinstance(body, AbstractSyntaxTreeNode):
                    self._ast._add_node(body)
                    self._ast._add_edge(falseNode, body)
                else: 
                    self._merge_instructions_and_nodes([body], falseNode)
                
        return ifNode

    def visit_InitList(self, node: c_ast.InitList): # To do x = y = 0;?
        pass

    def visit_Label(self, node: c_ast.Label):
        """Visit label. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")

    def visit_NamedInitializer(self, node): # ???
        pass

    def visit_ParamList(self, node: c_ast.ParamList): # fertig
        """Visit function params. Properties: [params**]"""
        return [self.visit(param) for param in node.params]

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
        # very ugly assumption but it's always true: stmt is a Compound with only Case nodes as childs
        switchNode = self._ast.factory.create_switch_node(self._resolve_condition(self.visit(node.cond)))
        self._ast._add_node(switchNode)
        for caseNode in node.stmt.block_items:
            self._ast._add_edge(switchNode, self.visit(caseNode))
        #body = self.visit(node.stmt)
        #self._ast._add_node(switchNode)
        #self._ast._add_edge(switchNode, body)
        return switchNode

    def visit_TernaryOp(self, node: c_ast.TernaryOp): # to do
        pass

    def visit_TypeDecl(self, node: c_ast.TypeDecl): # fertig
        """Visit type declaration. Properties: [declname, quals, align, type*]"""
        return self.visit(node.type)

    def visit_Typedef(self, node: c_ast.Typedef): # ?
        pass

    def visit_Typename(self, node: c_ast.Typename): # ?
        pass

    def visit_UnaryOp(self, node: c_ast.UnaryOp): # To do
        """Visit unary operation. Properties: [op, expr*]"""
        if op := OPERATIONS.get(node.op, None):
            variable: Variable = self.visit(node.expr)
            return UnaryOperation(op, [variable], variable.type)
        pass

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

    def visit_Pragma(self, node: c_ast.Pragma):
        """Visit pragma. Not supported"""
        raise ValueError(f"visitor for '{type(node)}' is not supported")
