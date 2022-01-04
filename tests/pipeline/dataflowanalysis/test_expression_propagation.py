from typing import Dict, List, Optional

from dewolf.pipeline.dataflowanalysis import ExpressionPropagation
from dewolf.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from dewolf.structures.pseudo.expressions import Constant, Expression, GlobalVariable, ImportedFunctionSymbol, UnknownExpression, Variable
from dewolf.structures.pseudo.instructions import Assignment, Branch, Phi, Relation, Return
from dewolf.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation
from dewolf.structures.pseudo.operations import OperationType
from dewolf.structures.pseudo.operations import OperationType as op
from dewolf.structures.pseudo.operations import UnaryOperation
from dewolf.structures.pseudo.typing import CustomType, Integer, Pointer, Type, UnknownType
from dewolf.task import DecompilerTask
from dewolf.util.options import Options

int32 = Integer.int32_t()
int64 = Integer.int64_t()


def test_contraction_propagation():
    """
    +--------------------+
    |         0.         |
    |  (1: ) x#0 = y#0   |
    | *(y#0) = (1: ) x#0 | <- we can propagate y#0 here
    +--------------------+

    +-----------------+
    |       0.        |
    | (1: ) x#0 = y#0 |
    |  *(y#0) = y#0   |
    +-----------------+

    """
    x = vars("x", 2)
    y = vars("y", 2)
    z = vars("y", 2)
    cfg = ControlFlowGraph()
    cfg.add_node(
        BasicBlock(
            0,
            [
                _assign(_cast(Integer.int8_t(), x[0], contraction=True), y[0]),
                _assign(_deref(z[0]), _cast(Integer.int8_t(), x[0], contraction=True)),
            ],
        )
    )
    _run_expression_propagation(cfg, _generate_options(branch=1))
    node = [n for n in cfg.nodes][0]
    assert node.instructions == [_assign(_cast(Integer.int8_t(), x[0], contraction=True), y[0]), _assign(_deref(z[0]), y[0])]


def test_copy_assignments_always_propagated_regardless_of_limit_1():
    """
    +---------------+
    |      0.       |
    |   x#1 = x#0   |
    | if(y#0 > x#1) |<--- even if limit 1 (do not propagate) we still can propagate copy, as it does not change the complexity of target
    +---------------+

    +---------------+
    |      0.       |
    |   x#1 = x#0   |
    | if(y#0 > x#0) |
    +---------------+
    """
    x = vars("x", 2)
    y = vars("y", 1)
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [_assign(x[1], x[0]), _if(op.greater, y[0], x[1])]))
    _run_expression_propagation(cfg, _generate_options(branch=1))
    node = [n for n in cfg][0]
    assert node.instructions == [_assign(x[1], x[0]), _if(op.greater, y[0], x[0])]


def test_no_assignments_with_dereference_subexpressions_on_rhs_are_propagated():
    """
    +-------------------------------------+
    |                 0.                  |
    | x#0 = (long) *(ptr#0 + (x#1 * 0x4)) |
    |    func_modifying_pointer(ptr#0)    |
    |             return x#0              |
    +-------------------------------------+

    +-------------------------------------+
    |                 0.                  |
    | x#0 = (long) *(ptr#0 + (x#1 * 0x4)) |
    |    func_modifying_pointer(ptr#0)    |
    |             return x#0              |
    +-------------------------------------+

    """
    input_cfg, output_cfg = graphs_with_cast_dereference_assignments()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_cast_dereference_assignments():
    x = vars("x", 2)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0,
        [
            _assign(x[0], _cast(int64, _deref(_add(ptr[0], _mul(x[1], Constant(4)))))),
            _call("func_modifying_pointer", [], [ptr[0]]),
            _ret(x[0]),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0,
            [
                _assign(x[0], _cast(int64, _deref(_add(ptr[0], _mul(x[1], Constant(4)))))),
                _call("func_modifying_pointer", [], [ptr[0]]),
                _ret(x[0]),
            ],
        )
    )
    return in_cfg, out_cfg


def test_no_dereference_assignments_propagated():
    """
    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 + (x#1 * 0x4))  |
    | func_modifying_pointer(ptr#0) |
    |          return x#0           |
    +-------------------------------+

    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 + (x#1 * 0x4))  |
    | func_modifying_pointer(ptr#0) |
    |          return x#0           |
    +-------------------------------+
    """
    input_cfg, output_cfg = graphs_with_dereference_assignments()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_dereference_assignments():
    x = vars("x", 2)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0, [_assign(x[0], _deref(_add(ptr[0], _mul(x[1], Constant(4))))), _call("func_modifying_pointer", [], [ptr[0]]), _ret(x[0])]
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0, [_assign(x[0], _deref(_add(ptr[0], _mul(x[1], Constant(4))))), _call("func_modifying_pointer", [], [ptr[0]]), _ret(x[0])]
        )
    )
    return in_cfg, out_cfg


def test_propagation_in_empty_graph_does_not_crash():
    input_cfg = ControlFlowGraph()
    input_cfg.add_node(BasicBlock(0, []))
    output_cfg = ControlFlowGraph()
    output_cfg.add_node(BasicBlock(0, []))
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def test_no_copy_by_reference():
    """Test that expression propagation utilizes copies for propagation, not references"""
    a, b, c = Variable("a", ssa_label=0), Variable("b", ssa_label=1), Variable("c", ssa_label=3)
    inst_1 = Branch(Condition(OperationType.less_or_equal, [BinaryOperation(OperationType.plus, [a, Constant(0x2)]), Constant(0x7)]))
    inst_2 = Assignment(b, UnaryOperation(OperationType.dereference, [BinaryOperation(OperationType.plus, [a, Constant(0x2)])]))
    inst_1.substitute(a, c)
    assert str(inst_1) == "if((c#3 + 0x2) <= 0x7)"
    assert str(inst_2) == "b#1 = *(a#0 + 0x2)"


def test_phi_functions_not_propagated():
    """
    +------------------+
    |        0.        |
    | z#2 = ϕ(z#0,z#1) |
    | x#2 = ϕ(0x5,x#1) |
    |    print(x#2)    |
    |    return z#2    |
    +------------------+

    +------------------+
    |        0.        |
    | z#2 = ϕ(z#0,z#1) |
    | x#2 = ϕ(0x5,x#1) |
    |    print(x#2)    |
    |    return z#2    |
    +------------------+

    """
    input_cfg, output_cfg = graphs_phi_functions_not_propagated()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_phi_functions_not_propagated():
    x = vars("x", 6)
    z = vars("z", 6)
    c = const(10)
    in_n0 = BasicBlock(0, [_phi(z[2], z[0], z[1]), _phi(x[2], c[5], x[1]), _call("print", [], [x[2]]), _ret(z[2])])
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_n0 = BasicBlock(0, [_phi(z[2], z[0], z[1]), _phi(x[2], c[5], x[1]), _call("print", [], [x[2]]), _ret(z[2])])
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_n0)
    return in_cfg, out_cfg


def test_assignments_containing_aliased_not_propagated():
    """
    +-----------------+
    |       0.        |
    |    x#0 = z#0    |
    |    x#1 = x#0    |
    |   print(x#1)    |
    |    z#1 = z#0    |
    | x#2 = z#1 + 0x5 |
    |   print(x#2)    |
    |    z#3 = 0x4    |
    |    x#3 = z#3    |
    |    x#4 = x#3    |
    |   print(x#4)    |
    +-----------------+

    +-----------------+
    |       0.        |
    |    x#0 = z#0    |
    |    x#1 = x#0    |
    |   print(x#0)    |
    |    z#1 = z#0    |
    | x#2 = z#1 + 0x5 |
    |   print(x#2)    |
    |    z#3 = 0x4    |
    |    x#3 = z#3    |
    |    x#4 = x#3    |
    |   print(x#3)    |
    +-----------------+

    """
    input_cfg, output_cfg = graphs_no_aliased_propagation()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_no_aliased_propagation():
    x = vars("x", 6)
    z = vars("z", 6, aliased=True)
    c = const(10)
    in_n0 = BasicBlock(
        0,
        [
            _assign(x[0], z[0]),
            _assign(x[1], x[0]),
            _call("print", [], [x[1]]),
            _assign(z[1], z[0]),
            _assign(x[2], _add(z[1], c[5])),
            _call("print", [], [x[2]]),
            _assign(z[3], c[4]),
            _assign(x[3], z[3]),
            _assign(x[4], x[3]),
            _call("print", [], [x[4]]),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_n0 = BasicBlock(
        0,
        [
            _assign(x[0], z[0]),
            _assign(x[1], x[0]),
            _call("print", [], [x[0]]),
            _assign(z[1], z[0]),
            _assign(x[2], _add(z[1], c[5])),
            _call("print", [], [x[2]]),
            _assign(z[3], c[4]),
            _assign(x[3], z[3]),
            _assign(x[4], x[3]),
            _call("print", [], [x[3]]),
        ],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_n0)
    return in_cfg, out_cfg


def test_do_not_propagate_behind_global_limits():
    """
    +-----------------+
    |       0.        |
    | x#0 = y#0 * 0x4 |
    | x#1 = x#0 + 0x2 |
    | y#1 = x#1 * 0x5 |
    | x#2 = x#1 + y#1 |
    |   print(x#2)    |
    +-----------------+

    Without propagation (limit 0):
    +-----------------+
    |       0.        |
    | x#0 = y#0 * 0x4 |
    | x#1 = x#0 + 0x2 |
    | y#1 = x#1 * 0x5 |
    | x#2 = x#1 + y#1 |
    |   print(x#2)    |
    +-----------------+
    With propagation limit 4:
    +--------------------------+
    |            0.            |
    |     x#0 = y#0 * 0x4      |
    | x#1 = (y#0 * 0x4) + 0x2  |
    |     y#1 = x#1 * 0x5      |
    | x#2 = x#1 + (x#1 * 0x5)  |
    | print(x#1 + (x#1 * 0x5)) |
    +--------------------------+
    With propagation limit 20:
    +----------------------------------------------------------+
    |                            0.                            |
    |                     x#0 = y#0 * 0x4                      |
    |                 x#1 = (y#0 * 0x4) + 0x2                  |
    |             y#1 = ((y#0 * 0x4) + 0x2) * 0x5              |
    | x#2 = ((y#0 * 0x4) + 0x2) + (((y#0 * 0x4) + 0x2) * 0x5)  |
    | print(((y#0 * 0x4) + 0x2) + (((y#0 * 0x4) + 0x2) * 0x5)) |
    +----------------------------------------------------------+

    """
    cfg = graph_single_block_global_limit_0()
    output_cfg = graph_single_block_global_limit_0()
    _run_expression_propagation(cfg, _generate_options(instr=0))
    assert _graphs_equal(cfg, output_cfg)
    _run_expression_propagation(cfg, _generate_options(instr=4))
    output_cfg = graph_single_block_global_limit_4()
    assert _graphs_equal(cfg, output_cfg)
    _run_expression_propagation(cfg, _generate_options(instr=20))
    output_cfg = graph_single_block_global_limit_20()
    assert _graphs_equal(cfg, output_cfg)


def graph_single_block_global_limit_0():
    x = vars("x", 6)
    y = vars("y", 6)
    c = const(10)
    n0 = BasicBlock(
        0,
        [
            _assign(x[0], _mul(y[0], c[4])),
            _assign(x[1], _add(x[0], c[2])),
            _assign(y[1], _mul(x[1], c[5])),
            _assign(x[2], _add(x[1], y[1])),
            _call("print", [], [x[2]]),
        ],
    )
    cfg = ControlFlowGraph()
    cfg.add_node(n0)
    return cfg


def graph_single_block_global_limit_4():
    x = vars("x", 6)
    y = vars("y", 6)
    c = const(10)
    n0 = BasicBlock(
        0,
        [
            _assign(x[0], _mul(y[0], c[4])),
            _assign(x[1], _add(_mul(y[0], c[4]), c[2])),
            _assign(y[1], _mul(x[1], c[5])),
            _assign(x[2], _add(x[1], _mul(x[1], c[5]))),
            _call("print", [], [_add(x[1], _mul(x[1], c[5]))]),
        ],
    )
    cfg = ControlFlowGraph()
    cfg.add_node(n0)
    return cfg


def graph_single_block_global_limit_20():
    x = vars("x", 6)
    y = vars("y", 6)
    c = const(10)
    n0 = BasicBlock(
        0,
        [
            _assign(x[0], _mul(y[0], c[4])),
            _assign(x[1], _add(_mul(y[0], c[4]), c[2])),
            _assign(y[1], _mul(_add(_mul(y[0], c[4]), c[2]), c[5])),
            _assign(x[2], _add(_add(_mul(y[0], c[4]), c[2]), _mul(_add(_mul(y[0], c[4]), c[2]), c[5]))),
            _call("print", [], [_add(_add(_mul(y[0], c[4]), c[2]), _mul(_add(_mul(y[0], c[4]), c[2]), c[5]))]),
        ],
    )
    cfg = ControlFlowGraph()
    cfg.add_node(n0)
    return cfg


def test_specific_propagation_limits():
    """
    Call propagation limit:
    +---------------------+
    |         0.          |
    | a = (x * 0x2) + 0x1 |
    |        b = a        |
    |       foo(a)        |
    +---------------------+
    With global limit 5 and call limit 1:
    +---------------------+
    |         0.          |
    | a = (x * 0x2) + 0x1 |
    | b = (x * 0x2) + 0x1 |
    |       foo(a)        |
    +---------------------+

    Branch propagation limit:
    +---------------------+
    |         0.          |
    | a = (x * 0x2) + 0x1 |
    |        b = a        |
    |    if(a <= 0x0)     |
    +---------------------+
    With global limit 5 and branch limit 1:
    +---------------------+
    |         0.          |
    | a = (x * 0x2) + 0x1 |
    | b = (x * 0x2) + 0x1 |
    |    if(a <= 0x0)     |
    +---------------------+

    Assignment propagation limit:
    +---------------------+
    |         0.          |
    | a = (x * 0x2) + 0x1 |
    |        b = a        |
    |    if(a <= 0x3)     |
    +---------------------+
    Assignment limit 1, branch limit 5:
    +------------------------------+
    |              0.              |
    |     a = (x * 0x2) + 0x1      |
    |            b = a             |
    | if(((x * 0x2) + 0x1) <= 0x3) |
    +------------------------------+


    """
    c = const(4)
    a = Variable("a")
    b = Variable("b")
    x = Variable("x")
    # test call limit
    instructions = [_assign(a, _add(_mul(x, c[2]), c[1])), _assign(b, a), _call("foo", [], [a])]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg, _generate_options(instr=5, call=1))
    assert [i for i in cfg.instructions] == [
        _assign(a, _add(_mul(x, c[2]), c[1])),
        _assign(b, _add(_mul(x, c[2]), c[1])),
        _call("foo", [], [a]),
    ]
    # test branch limit
    instructions = [_assign(a, _add(_mul(x, c[2]), c[1])), _assign(b, a), _if(op.less_or_equal, a, c[0])]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg, _generate_options(instr=5, branch=1))
    assert [i for i in cfg.instructions] == [
        _assign(a, _add(_mul(x, c[2]), c[1])),
        _assign(b, _add(_mul(x, c[2]), c[1])),
        _if(op.less_or_equal, a, c[0]),
    ]
    # test assignment limit
    instructions = [_assign(a, _add(_mul(x, c[2]), c[1])), _assign(b, a), _if(op.less_or_equal, a, c[3])]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg, _generate_options(assignment=1, branch=5))
    assert [i for i in cfg.instructions] == [
        _assign(a, _add(_mul(x, c[2]), c[1])),
        _assign(b, a),
        _if(op.less_or_equal, _add(_mul(x, c[2]), c[1]), c[3]),
    ]


def test_calls_not_propagated():
    """
    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    |    x#1 = x#0    |
    | z#0 = x#1 + 0x5 |
    |   return z#0    |
    +-----------------+

    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    |    x#1 = x#0    |
    | z#0 = x#0 + 0x5 |
    |   return z#0    |
    +-----------------+

    """
    x = vars("x", 6)
    z = vars("z", 6, aliased=True)
    c = const(10)
    instructions = [_call("rand", [x[0]], []), _assign(x[1], x[0]), _assign(z[0], _add(x[1], c[5])), _ret(z[0])]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg)
    assert [i for i in cfg.instructions] == [_call("rand", [x[0]], []), _assign(x[1], x[0]), _assign(z[0], _add(x[0], c[5])), _ret(z[0])]


def test_globals_not_propagated_1():
    """
     Check that definitions of Globals are not propagated.
    +------------------------+
     |           0.           |
     |    global_x#0 = 0x5    |
     | y#0 = global_x#0 + 0x5 |
     +------------------------+

     +------------------------+
     |           0.           |
     |    global_x#0 = 0x5    |
     | y#0 = global_x#0 + 0x5 |
     +------------------------+
    """
    global_var = GlobalVariable("global_x", ssa_label=0)
    y = Variable("y", ssa_label=0)
    instructions = [_assign(global_var, Constant(5)), _assign(y, _add(global_var, Constant(5)))]
    original = _assign(y, _add(global_var, Constant(5)))
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg)
    assert list(cfg.instructions)[1] == original


def test_globals_not_propagated_2():
    """
    Check that variables that use Globals do not get propagated.
    +------------------------+
    |           0.           |
    | y#0 = global_x#0 + 0x5 |
    |       z#0 = y#0        |
    +------------------------+

    +------------------------+
    |           0.           |
    | y#0 = global_x#0 + 0x5 |
    |       z#0 = y#0        |
    +------------------------+
    """
    global_var = GlobalVariable("global_x", ssa_label=0)
    y = Variable("y", ssa_label=0)
    z = Variable("z", ssa_label=0)
    instructions = [_assign(y, _add(global_var, Constant(5))), _assign(z, y)]
    original = _assign(z, y)
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg)
    assert list(cfg.instructions)[1] == original


def test_address_assignments_not_propagated():
    """
    +--------------+
    |      0.      |
    | x#0 = &(z#0) |
    |  x#1 = x#0   |
    |  scanf(x#1)  |
    |  z#1 = z#0   |
    |  return z#1  |
    +--------------+
    +--------------+
    |      0.      |
    | x#0 = &(z#0) |
    |  x#1 = x#0   |
    |  scanf(x#0)  |
    |  z#1 = z#0   |
    |  return z#1  |
    +--------------+

    """
    x = vars("x", 6)
    z = vars("z", 6, aliased=True)
    c = const(10)
    instructions = [_assign(x[0], _addr(z[0])), _assign(x[1], x[0]), _call("scanf", [], [x[1]]), _assign(z[1], z[0]), _ret(z[1])]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg)
    assert [i for i in cfg.instructions] == [
        _assign(x[0], _addr(z[0])),
        _assign(x[1], x[0]),
        _call("scanf", [], [x[0]]),
        _assign(z[1], z[0]),
        _ret(z[1]),
    ]


def test_do_not_propagate_operations_into_phi_functions():
    """
    +------------------+
    |        0.        |
    |    x#0 = y#0     |
    |    w#0 = 0x0     |
    |    z#0 = 0x6     |
    |    v#0 = y#1     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    |  if(y#2 <= 0x1)  | <+
    +------------------+  |
      |                   |
      |                   |
      v                   |
    +------------------+  |
    |        2.        |  |
    | x#2 = ϕ(x#0,x#1) |  |
    | w#2 = ϕ(w#0,w#1) |  |
    | z#2 = ϕ(z#0,z#1) |  |
    | v#2 = ϕ(v#0,v#1) |  |
    |    x#1 = y#1     |  |
    | w#1 = x#1 + 0x5  |  |
    |    z#1 = w#1     |  |
    | v#1 = x#1 + 0x4  | -+
    +------------------+
    +------------------+
    |        0.        |
    |    x#0 = y#0     |
    |    w#0 = 0x0     |
    |    z#0 = 0x6     |
    |    v#0 = y#1     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    |  if(y#2 <= 0x1)  | <+
    +------------------+  |
      |                   |
      |                   |
      v                   |
    +------------------+  |
    |        2.        |  |
    | x#2 = ϕ(y#0,y#1) |  |
    | w#2 = ϕ(0x0,w#1) |  |
    | z#2 = ϕ(z#0,z#1) |  |
    | v#2 = ϕ(v#0,v#1) |  |
    |    x#1 = y#1     |  |
    | w#1 = y#1 + 0x5  |  |
    | z#1 = y#1 + 0x5  |  |
    | v#1 = y#1 + 0x4  | -+
    +------------------+
    """
    input_cfg, output_cfg = graphs_with_propagation_into_phi_functions()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_propagation_into_phi_functions():
    x = vars("x", 6)
    y = vars("y", 6)
    w = vars("w", 6)
    z = vars("z", 6, aliased=True)
    v = vars("v", 6, aliased=True)
    c = const(10)
    in_n0 = BasicBlock(
        0,
        [
            _assign(x[0], y[0]),
            _assign(w[0], c[0]),
            _assign(z[0], c[6]),
            _assign(v[0], y[1]),
        ],
    )
    in_n1 = BasicBlock(1, [_if(op.less_or_equal, y[2], c[1])])
    in_n2 = BasicBlock(
        2,
        [
            _phi(x[2], x[0], x[1]),
            _phi(w[2], w[0], w[1]),
            _phi(z[2], z[0], z[1]),
            _phi(v[2], v[0], v[1]),
            _assign(x[1], y[1]),
            _assign(w[1], _add(x[1], c[5])),
            _assign(z[1], w[1]),
            _assign(v[1], _add(x[1], c[4])),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_edges_from([UnconditionalEdge(in_n0, in_n1), UnconditionalEdge(in_n1, in_n2), UnconditionalEdge(in_n2, in_n1)])
    out_n0 = BasicBlock(
        0,
        [
            _assign(x[0], y[0]),
            _assign(w[0], c[0]),
            _assign(z[0], c[6]),
            _assign(v[0], y[1]),
        ],
    )
    out_n1 = BasicBlock(1, [_if(op.less_or_equal, y[2], c[1])])
    out_n2 = BasicBlock(
        2,
        [
            _phi(x[2], y[0], y[1]),
            _phi(w[2], c[0], w[1]),
            _phi(z[2], z[0], z[1]),
            _phi(v[2], v[0], v[1]),
            _assign(x[1], y[1]),
            _assign(w[1], _add(y[1], c[5])),
            _assign(z[1], _add(y[1], c[5])),
            _assign(v[1], _add(y[1], c[4])),
        ],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_edges_from([UnconditionalEdge(out_n0, out_n1), UnconditionalEdge(out_n1, out_n2), UnconditionalEdge(out_n2, out_n1)])
    return in_cfg, out_cfg


def test_do_not_propagate_into_address():
    """
    +----------------------+
    |          0.          |
    |      x#0 = x#2       |
    |      z#0 = x#0       |
    |     y#0 = &(z#0)     |
    |      x#1 = 0x0       |
    |      z#1 = x#1       |
    | y#1 = (&(z#1)) + x#0 |
    | y#2 = (&(0x2)) + z#1 |
    +----------------------+

    +----------------------+
    |          0.          |
    |      x#0 = x#2       |
    |      z#0 = x#2       |
    |     y#0 = &(z#0)     |
    |      x#1 = 0x0       |
    |      z#1 = 0x0       |
    | y#1 = (&(z#1)) + x#2 |
    | y#2 = (&(0x2)) + z#1 |
    +----------------------+
    """
    input_cfg, output_cfg = graphs_no_ep_in_address()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def test_limit_calculation():
    """
    Test whether the complexity of an instruction after propagation is calculated correctly.

    +-----------------+
    |       0.        |
    | x#0 = y#0 * 0x4 |
    | x#1 = x#0 + 0x2 |
    | y#1 = x#1 * 0x5 |
    | x#2 = y#1 * y#1 |
    |   print(x#2)    |
    +-----------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_node(
        BasicBlock(
            0,
            instructions=[
                Assignment(Variable("x", ssa_label=0), BinaryOperation(OperationType.multiply, [Variable("y", ssa_label=0), Constant(4)])),
                Assignment(Variable("x", ssa_label=1), BinaryOperation(OperationType.plus, [Variable("x", ssa_label=0), Constant(2)])),
                Assignment(Variable("y", ssa_label=1), BinaryOperation(OperationType.multiply, [Variable("x", ssa_label=1), Constant(5)])),
                Assignment(
                    Variable("x", ssa_label=2),
                    BinaryOperation(OperationType.multiply, [Variable("y", ssa_label=1), Variable("y", ssa_label=1)]),
                ),
                Assignment(ListOperation([]), Call(ImportedFunctionSymbol("print", 0x42), [Variable("x", ssa_label=2)])),
            ],
        )
    )
    _run_expression_propagation(cfg, _generate_options(instr=3))
    assert list(cfg.instructions)[-1] == Assignment(
        ListOperation([]),
        Call(
            ImportedFunctionSymbol("print", 0x42),
            [BinaryOperation(OperationType.multiply, [Variable("y", ssa_label=1), Variable("y", ssa_label=1)])],
        ),
    )


def graphs_no_ep_in_address():
    x = vars("x", 6)
    y = vars("y", 6)
    z = vars("z", 6, aliased=True)
    c = const(10)
    in_n0 = BasicBlock(
        0,
        [
            _assign(x[0], x[2]),
            _assign(z[0], x[0]),
            _assign(y[0], _addr(z[0])),
            _assign(x[1], c[0]),
            _assign(z[1], x[1]),
            _assign(y[1], _add(_addr(z[1]), x[0])),
            _assign(y[2], _add(_addr(c[2]), z[1])),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_n0 = BasicBlock(
        0,
        [
            _assign(x[0], x[2]),
            _assign(z[0], x[2]),
            _assign(y[0], _addr(z[0])),
            _assign(x[1], c[0]),
            _assign(z[1], c[0]),
            _assign(y[1], _add(_addr(z[1]), x[2])),
            _assign(y[2], _add(_addr(c[2]), z[1])),
        ],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_n0)
    return in_cfg, out_cfg


def test_do_not_propagate_unknown_expressions():
    ecx = vars("ecx", 6)
    edi = vars("edi", 5, Pointer(Integer(32, True), 32))
    vertex_0 = BasicBlock(
        0,
        [
            Assignment(
                ecx[1],
                sub_expr := BinaryOperation(
                    OperationType.bitwise_and, [ecx[0], Constant(0xFFFFFFFC, Integer(32, True))], Integer(32, True)
                ),
            ),
            Assignment(ecx[2], BinaryOperation(OperationType.right_shift_us, [ecx[1], Constant(2, Integer(32, True))], Integer(32, False))),
            Assignment(edi[1], UnknownExpression("mov     edi, edx")),
        ],
    )
    vertex_2 = BasicBlock(
        2,
        [
            Assignment(ecx[5], BinaryOperation(OperationType.plus, [ecx[4], Constant(2, Integer.int32_t())])),
            Assignment(edi[3], UnknownExpression("mov     edi, edx")),
            Assignment(edi[4], BinaryOperation(OperationType.plus, [edi[3], Constant(2, Integer.int32_t())])),
        ],
    )
    vertex_2_old = vertex_2.copy()
    vertex_1 = BasicBlock(
        1,
        [
            Phi(ecx[4], [ecx[3], ecx[5]], {vertex_0: ecx[3], vertex_2: ecx[5]}),
            Phi(edi[2], [edi[1], edi[4]], {vertex_0: edi[1], vertex_2: edi[4]}),
            Branch(Condition(OperationType.not_equal, [ecx[4], Constant(0, Integer(32, True))], CustomType("bool", 1))),
        ],
    )
    vertex_1_old = vertex_1.copy()
    vertex_3 = BasicBlock(3, [Return([Constant(0, Integer.int32_t())])])
    vertex_3_old = vertex_3.copy()
    cfg = ControlFlowGraph()
    cfg.add_nodes_from([vertex_0, vertex_1, vertex_2])
    cfg.add_edges_from(
        [
            UnconditionalEdge(vertex_0, vertex_1),
            TrueCase(vertex_1, vertex_2),
            FalseCase(vertex_1, vertex_3),
            UnconditionalEdge(vertex_2, vertex_1),
        ]
    )
    _run_expression_propagation(cfg)
    assert vertex_0.instructions == [
        Assignment(
            ecx[1], BinaryOperation(OperationType.bitwise_and, [ecx[0], Constant(0xFFFFFFFC, Integer(32, True))], Integer(32, True))
        ),
        Assignment(ecx[2], BinaryOperation(OperationType.right_shift_us, [sub_expr, Constant(2, Integer(32, True))], Integer(32, False))),
        Assignment(edi[1], UnknownExpression("mov     edi, edx")),
    ]
    assert all(
        vertex.instructions == old_vertex.instructions
        for vertex, old_vertex in [(vertex_1, vertex_1_old), (vertex_2, vertex_2_old), (vertex_3, vertex_3_old)]
    )


def test_correct_propagation_relation():
    """
    Do not propagate relations
    +-------------------------------------+
    |                 0.                  |
    |         var_14#1 = var_14#0         |
    |       var_28#0 = &(var_14#1)        |
    | __isoc99_scanf(0x804b01f, var_28#0) |
    |        var_14#2 -> var_14#1         |
    |          eax#1 = var_14#2           |
    |      printf(0x804b024, eax#1)       |
    |         var_14#3 = var_14#2         |
    |      var_14#4 = var_14#3 + 0x2      |
    |       var_28#1 = &(var_14#4)        |
    | __isoc99_scanf(0x804b01f, var_28#1) |
    |        var_14#5 -> var_14#4         |
    +-------------------------------------+
    """
    var_14 = vars("var_14", 6, Integer(32, True), True)
    var_28 = vars("var_28", 2, Pointer(Integer(32, True), 32), False)
    eax = Variable("eax", Integer(32, True), 1, False, None)

    instructions = [
        _assign(var_14[1], var_14[0]),
        _assign(var_28[0], UnaryOperation(OperationType.address, [var_14[1]], Pointer(Integer(32, True), 32), None, False)),
        _assign(
            ListOperation([]),
            Call(
                Constant("__isoc99_scanf", UnknownType()),
                [Constant(134524959, Integer(32, True)), var_28[0]],
                Pointer(CustomType("void", 0), 32),
                2,
            ),
        ),
        Relation(var_14[2], var_14[1]),
        _assign(eax, var_14[2]),
        _assign(
            ListOperation([]),
            Call(
                Constant("printf", UnknownType()),
                [Constant(134524964, Pointer(Integer(8, True), 32)), eax],
                Pointer(CustomType("void", 0), 32),
                3,
            ),
        ),
        _assign(var_14[3], var_14[2]),
        _assign(var_14[4], _add(var_14[3], Constant(2))),
        _assign(var_28[1], UnaryOperation(OperationType.address, [var_14[4]], Pointer(Integer(32, True), 32), None, False)),
        _assign(
            ListOperation([]),
            Call(
                Constant("__isoc99_scanf", UnknownType()),
                [Constant(134524959, Integer(32, True)), var_28[1]],
                Pointer(CustomType("void", 0), 32),
                5,
            ),
        ),
        Relation(var_14[5], var_14[4]),
    ]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [i.copy() for i in instructions]))
    _run_expression_propagation(cfg)
    assert list(cfg.instructions) == instructions


def _generate_options(instr: int = 10, branch: int = 10, call: int = 10, assignment: int = 10) -> Options:
    options = Options()
    options.set("expression-propagation.maximum_instruction_complexity", instr)
    options.set("expression-propagation.maximum_branch_complexity", branch)
    options.set("expression-propagation.maximum_call_complexity", call)
    options.set("expression-propagation.maximum_assignment_complexity", assignment)
    return options


def _run_expression_propagation(cfg: ControlFlowGraph, options: Options = _generate_options()) -> None:
    task = DecompilerTask("test", cfg, options=options)
    ExpressionPropagation().run(task)


def _graphs_equal(g1: ControlFlowGraph, g2: ControlFlowGraph) -> bool:
    if type(g1) != type(g2):
        return False
    for x, y in zip(g1.nodes, g2.nodes):
        if x.instructions != y.instructions:
            from pprint import pprint

            pprint(x.instructions)
            pprint(y.instructions)
            return False

    return all(x.instructions == y.instructions for x, y in zip(g1.nodes, g2.nodes))


def vars(name: str, num: int, type: Type = Integer.int32_t(), aliased: bool = False) -> List[Variable]:
    return [Variable(name, type, i, aliased) for i in range(num)]


def const(num: int) -> List[Constant]:
    return [Constant(i) for i in range(num)]


def _add(*operands: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.plus, list(operands))


def _assign(x: Expression, y: Expression) -> Assignment:
    return Assignment(x, y)


def _deref(x: Expression) -> UnaryOperation:
    return UnaryOperation(OperationType.dereference, [x])


def _addr(x: Expression) -> UnaryOperation:
    return UnaryOperation(OperationType.address, [x])


def _phi(x: Expression, *y: Expression) -> Phi:
    return Phi(x, list(y))


def _mul(*operands: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.multiply, list(operands))


def _call(func_name: str, ret_val: List[Expression] = None, operands: List[Expression] = None) -> Assignment:
    if not ret_val:
        ret_val = list()
    if not operands:
        operands = list()
    return Assignment(ListOperation(ret_val), Call(ImportedFunctionSymbol(func_name, 0x42), operands))


def _if(operation: op, *operands) -> Branch:
    return Branch(Condition(operation, list(operands)))


def _ret(*operands: Expression) -> Return:
    return Return(list(operands))


def _cast(type: Type, x: Expression, contraction=False) -> UnaryOperation:
    return UnaryOperation(OperationType.cast, [x], vartype=type, contraction=contraction)