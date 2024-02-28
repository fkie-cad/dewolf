from decompiler.pipeline.preprocessing import GetFunctionPointer
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo import (
    Assignment,
    Call,
    Condition,
    Constant,
    ImportedFunctionSymbol,
    Integer,
    ListOperation,
    OperationType,
    Variable,
)
from decompiler.structures.pseudo.instructions import Branch, Return
from decompiler.structures.pseudo.typing import FunctionPointer, Pointer
from decompiler.task import DecompilerTask


def test_set_variable_to_function_pointer():
    """
    Test the change of a variable type to FunctionPointer if there is a call on this variable.

    a = 0x0804c020
    b = 1
    if (a == 0)
        return b
    else
        a()
    """
    cfg = ControlFlowGraph()
    var_a = Variable("a", Integer.int32_t())
    var_b = Variable("b", Integer.int32_t())
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[Assignment(var_a, Constant(0x0804C020)), Assignment(var_b, Constant(1))]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [var_a, Constant(0)]))]),
            n2 := BasicBlock(2, instructions=[Return([var_b])]),
            n3 := BasicBlock(3, instructions=[Assignment(ListOperation([]), Call(var_a, []))]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3)])
    GetFunctionPointer().run(DecompilerTask("test", cfg))
    assert var_a.type == Pointer(FunctionPointer(32, Integer.int32_t(), ()))


def test_set_variable_to_function_pointer_with_parameters():
    """
    Test the change of a variable type to FunctionPointer if there is a call on this variable with parameters.

    a = 0x0804c020
    b = 1
    if (a == 0)
        return b
    else
        a(c, d)
    """
    cfg = ControlFlowGraph()
    var_a = Variable("a", Integer.int32_t())
    var_b = Variable("b", Integer.int32_t())
    var_c = Variable("c", Integer.int32_t())
    var_d = Variable("d", Integer.int32_t())
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[Assignment(var_a, Constant(0x0804C020)), Assignment(var_b, Constant(1))]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [var_a, Constant(0)]))]),
            n2 := BasicBlock(2, instructions=[Return([var_b])]),
            n3 := BasicBlock(3, instructions=[Assignment(ListOperation([]), Call(var_a, [var_c, var_d]))]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3)])
    GetFunctionPointer().run(DecompilerTask("test", cfg))
    assert var_a.type == Pointer(FunctionPointer(32, Integer.int32_t(), (var_c, var_d)))


def test_skip_set_variable_to_function_pointer():
    """
    Test the skip of a change of a variable type to FunctionPointer if there is a call without a variable.

    a = 0x0804c020
    b = 1
    if (a == 0)
        return b
    else
        printf("%d\n", a)
    """
    cfg = ControlFlowGraph()
    var_a = Variable("a", Integer.int32_t())
    var_b = Variable("b", Integer.int32_t())
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[Assignment(var_a, Constant(0x0804C020)), Assignment(var_b, Constant(1))]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [var_a, Constant(0)]))]),
            n2 := BasicBlock(2, instructions=[Return([var_b])]),
            n3 := BasicBlock(
                3, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("printf", 0), [Constant("%d\n"), var_a]))]
            ),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3)])
    GetFunctionPointer().run(DecompilerTask("test", cfg))
    assert not any(isinstance(variable.type, Pointer) for variable in cfg.get_variables())
