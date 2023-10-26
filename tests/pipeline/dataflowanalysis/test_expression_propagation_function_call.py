import copy
from typing import List

from decompiler.pipeline.dataflowanalysis import ExpressionPropagationFunctionCall
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, Expression, FunctionSymbol, GlobalVariable, Variable
from decompiler.structures.pseudo.instructions import Assignment, Return
from decompiler.structures.pseudo.operations import Call, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

int32 = Integer.int32_t()
int64 = Integer.int64_t()
global_x = GlobalVariable("global_x")
x = Variable("x")
y = Variable("y")
z = Variable("z")


def test_function_propagation():
    """
    +----------+
    |    0.    |
    | x = f(y) |
    | return x |
    +----------+


    +-------------+
    |     0.      |
    |   x = 0x0   |
    | return f(y) |
    +-------------+
    """
    cfg = ControlFlowGraph()
    return_values = ListOperation([x])
    function_call = _func("f", [y])
    cfg.add_node(BasicBlock(0, [_assign(return_values, function_call), Return([x])]))
    _run_expression_propagation(cfg)
    node = cfg.nodes[0]
    assert node.instructions == [_assign(return_values, Constant(0x0)), Return([_func("f", [y])])]


def test_function_propagation_no_list_op():
    """
    Test if we do not crash when LHS is not of type ListOperation, but GlobalVariable.
    This can happen due to pipeline stages destroying assumption made for the lifter.
    Note: currently propagation into global variables is prohibited.

    +----------+
    |    0.    |
    | x = f(y) | LHS is of type GlobalVariable
    | return x |
    +----------+


    +----------+
    |    0.    |
    | x = f(y) | Nothing is propagated
    | return x |
    +----------+
    """
    cfg = ControlFlowGraph()
    return_values = global_x
    function_call = _func("f", [y])
    cfg.add_node(BasicBlock(0, [_assign(return_values, function_call), Return([global_x])]))
    _run_expression_propagation(cfg)
    node = cfg.nodes[0]
    assert node.instructions == [_assign(return_values, function_call), Return([global_x])]


def test_no_propagation_on_mult_return():
    """
    +------------+
    |     0.     |
    | x,z = f(y) |
    |  return x  |
    +------------+


    +------------+
    |     0.     |
    | x,z = f(y) |
    |  return x  |
    +------------+
    """
    cfg = ControlFlowGraph()
    return_values = ListOperation([x, z])
    function_call = _func("f", [y])
    cfg.add_node(BasicBlock(0, [_assign(return_values, function_call), Return([x])]))
    _run_expression_propagation(cfg)
    node = cfg.nodes[0]
    assert node.instructions == [_assign(return_values, function_call), Return([x])]


def test_no_propagation_on_mult_uses():
    """
    +----------+
    |    0.    |
    | x = f(y) |
    |  z = x   |
    | return x |
    +----------+


    +----------+
    |    0.    |
    | x = f(y) |
    |  z = x   |
    | return x |
    +----------+
    """
    cfg = ControlFlowGraph()
    return_values = ListOperation([x])
    function_call = _func("f", [y])
    cfg.add_node(BasicBlock(0, [_assign(return_values, function_call), _assign(z, x), Return([x])]))
    _run_expression_propagation(cfg)
    node = cfg.nodes[0]
    assert node.instructions == [_assign(return_values, function_call), _assign(z, x), Return([x])]


def test_no_propagation_on_unsafe_memory_use_between_definition_and_target():
    """
    +-------------+
    |     0.      |
    |   x = f()   |
    | y = g(&(x)) |
    |  return x   |
    +-------------+


    +-------------+
    |     0.      |
    |   x = f()   |
    | y = g(&(x)) |
    |  return x   |
    +-------------+
    """
    cfg = ControlFlowGraph()
    return_x = ListOperation([x])
    return_y = ListOperation([y])
    function_call1 = _func("f", [])
    function_call2 = _func("g", [UnaryOperation(OperationType.address, [x])])
    cfg.add_node(BasicBlock(0, [_assign(return_x, function_call1), _assign(return_y, function_call2), Return([x])]))
    _run_expression_propagation(cfg)
    node = cfg.nodes[0]
    assert node.instructions == [_assign(return_x, function_call1), _assign(return_y, function_call2), Return([x])]


def test_multiple_propagations():
    """
    +----------+
    |    0.    |
    | x = f()  |
    | y = g(x) |
    | return y |
    +----------+


    +---------------+
    |      0.       |
    |    x = 0x0    |
    |    y = 0x0    |
    | return g(f()) |
    +---------------+
    """
    cfg = ControlFlowGraph()
    return_x = ListOperation([x])
    return_y = ListOperation([y])
    function_call1 = _func("f", [])
    function_call2 = _func("g", [x])
    cfg.add_node(BasicBlock(0, [_assign(return_x, function_call1), _assign(return_y, function_call2), Return([y])]))
    _run_expression_propagation(cfg)
    node = cfg.nodes[0]
    assert node.instructions == [_assign(return_x, Constant(0x0)), _assign(return_y, Constant(0x0)), Return([_func("g", [_func("f", [])])])]


def test_single_instruction_multiple_propagations():
    """
    Test that functions are not propagated if they occur multiple times in a single instruction.

    +-------------+
    |    0.       |
    | x = f()     |
    | y = g(x, x) |
    | return y    |
    +-------------+


    +-------------+
    |    0.       |
    | x = f()     |
    | y = g(x, x) |
    | return y    |
    +-------------+
    """

    instructions = [_assign(x, _func("f", [])), Return([_func("g", [x, x])])]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, copy.deepcopy(instructions)))

    _run_expression_propagation(cfg)

    assert cfg.nodes[0].instructions == instructions


def _func(name: str, parameters: List):
    return Call(FunctionSymbol(name, 0), parameters, writes_memory=1)


def _assign(x: Expression, y: Expression) -> Assignment:
    return Assignment(x, y)


def _run_expression_propagation(cfg: ControlFlowGraph) -> None:
    options = Options()
    options.set("expression-propagation-function-call.maximum_instruction_complexity", 10)
    options.set("expression-propagation-function-call.maximum_branch_complexity", 10)
    options.set("expression-propagation-function-call.maximum_call_complexity", 10)
    options.set("expression-propagation-function-call.maximum_assignment_complexity", 10)
    task = DecompilerTask("test", cfg, options=options)
    ExpressionPropagationFunctionCall().run(task)
