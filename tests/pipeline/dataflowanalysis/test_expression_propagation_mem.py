from typing import List, Tuple

from decompiler.pipeline.dataflowanalysis import ExpressionPropagationMemory
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import (
    Constant,
    Expression,
    GlobalVariable,
    ImportedFunctionSymbol,
    UnknownExpression,
    Variable,
)
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Relation, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation
from decompiler.structures.pseudo.operations import OperationType
from decompiler.structures.pseudo.operations import OperationType as op
from decompiler.structures.pseudo.operations import UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer, Type, UnknownType
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

int32 = Integer.int32_t()
int64 = Integer.int64_t()


def test_postponed_aliased_propagation_handles_aliases_correctly():
    """
         +--------------------------------+
        |               0.               |
        |      var_18#1 = var_18#0       |
        |             func()             |
        |      var_18#2 = var_18#1       |
        |     var_28#1 = &(var_18#2)     |
        |        scanf(var_28#1)         |
        |      var_18#3 -> var_18#2      |
        |        eax#1 = var_18#3        |
        |        var_14#4 = eax#1        |<--------var_14 is now an alias of var_18
        |             func()             |
        |      var_18#4 = var_18#3       |
        |     var_10#1 = &(var_18#4)     |
        |       *(var_10#1) = 0x7        |<--------var_18 is changed via deref, so does var_14, since they are aliases
        |      var_18#5 -> var_18#4      |
        |      var_14#5 = var_14#4       |<--------do not propagate old value of var_14 here, cause of change above
        |       eax_2#3 = var_18#5       |
        | return (&(var_14#5)) + eax_2#3 |
        +--------------------------------+

        +---------------------------------+
        |               0.                |
        |       var_18#1 = var_18#0       |
        |             func()              |
        |       var_18#2 = var_18#0       |
        |     var_28#1 = &(var_18#2)      |
        |       scanf(&(var_18#2))        |
        |      var_18#3 -> var_18#2       |
        |        eax#1 = var_18#3         |
        |       var_14#4 = var_18#3       |
        |             func()              |
        |       var_18#4 = var_18#3       |
        |     var_10#1 = &(var_18#4)      |
        |        *(var_10#1) = 0x7        |
        |      var_18#5 -> var_18#4       |
        |       var_14#5 = var_14#4       |<--------this instruction should not be changed after epm
        |       eax_2#3 = var_18#5        |
        | return (&(var_14#5)) + var_18#5 |
    +---------------------------------+
    """
    input_cfg, output_cfg = graphs_with_aliases()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_aliases():
    var_18 = vars("var_18", 6, aliased=True)
    var_14 = vars("var_14", 6, aliased=True)
    var_28 = vars("var_28", 2, type=Pointer(int32))
    var_10 = vars("var_10", 2, type=Pointer(int32))
    eax = vars("eax", 2)
    eax_2 = vars("eax_2", 4)
    c = const(8)

    in_n0 = BasicBlock(
        0,
        [
            _assign(var_18[1], var_18[0]),
            _call("func", [], []),
            _assign(var_18[2], var_18[1]),
            _assign(var_28[1], _addr(var_18[2])),
            _call("scanf", [], [var_28[1]]),
            Relation(var_18[3], var_18[2]),
            _assign(eax[1], var_18[3]),
            _assign(var_14[4], eax[1]),
            _call("func", [], []),
            _assign(var_18[4], var_18[3]),
            _assign(var_10[1], _addr(var_18[4])),
            _assign(_deref(var_10[1]), c[7]),
            Relation(var_18[5], var_18[4]),
            _assign(var_14[5], var_14[4]),
            _assign(eax_2[3], var_18[5]),
            _ret(_add(_addr(var_14[5]), eax_2[3])),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0,
            [
                _assign(var_18[1], var_18[0]),
                _call("func", [], []),
                _assign(var_18[2], var_18[0]),
                _assign(var_28[1], _addr(var_18[2])),
                _call("scanf", [], [_addr(var_18[2])]),
                Relation(var_18[3], var_18[2]),
                _assign(eax[1], var_18[3]),
                _assign(var_14[4], var_18[3]),
                _call("func", [], []),
                _assign(var_18[4], var_18[3]),
                _assign(var_10[1], _addr(var_18[4])),
                _assign(_deref(var_10[1]), c[7]),
                Relation(var_18[5], var_18[4]),
                _assign(var_14[5], var_14[4]),
                _assign(eax_2[3], var_18[5]),
                _ret(_add(_addr(var_14[5]), var_18[5])),
            ],
        )
    )
    return in_cfg, out_cfg


def test_address_propagation_does_not_break_relations_between_aliased_versions():
    """
    +------------------+
    |        0.        |
    |    x#0 = 0x0     |
    |    y#0 = 0x0     | <--- DO NOT propagate
    | ptr_x#1 = &(x#0) | <--- can propagate
    | ptr_y#1 = &(y#0) | <--- can propagate
    |  func(ptr_x#1)   |
    |    y#1 = y#0     | <--- propagation will cause connection loss between lhs and rhs variable
    |    x#1 -> x#0    |
    |  func(ptr_y#1)   |
    |    y#2 -> y#1    |
    |    x#2 = x#1     |
    |    x#3 = x#2     | <--- can propagate (aliased) definition x#2=x#1 here, as x#2 is not used anywhere else
    |    y#3 = y#2     |
    | return x#3 + y#3 |
    +------------------+

    After:
    +------------------+
    |        0.        |
    |    x#0 = 0x0     |
    |    y#0 = 0x0     |
    | ptr_x#1 = &(x#0) |
    | ptr_y#1 = &(y#0) |
    |   func(&(x#0))   |
    |    y#1 = y#0     |
    |    x#1 -> x#0    |
    |   func(&(y#0))   |
    |    y#2 -> y#1    |
    |    x#2 = x#1     |
    |    x#3 = x#1     |
    |    y#3 = y#2     |
    | return x#1 + y#2 |
    +------------------+
    """
    input_cfg, output_cfg = graphs_with_address_propagation_does_not_break_relations_between_aliased_versions()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_address_propagation_does_not_break_relations_between_aliased_versions():
    x = vars("x", 5, aliased=True)
    y = vars("y", 5, aliased=True)
    ptr_x = vars("ptr_x", 2, type=Pointer(int32))
    ptr_y = vars("ptr_y", 2, type=Pointer(int32))
    c = const(5)

    in_n0 = BasicBlock(
        0,
        [
            _assign(x[0], c[0]),
            _assign(y[0], c[0]),
            _assign(ptr_x[1], _addr(x[0])),
            _assign(ptr_y[1], _addr(y[0])),
            _call("func", [], [ptr_x[1]]),
            _assign(y[1], y[0]),
            Relation(x[1], x[0]),
            _call("func", [], [ptr_y[1]]),
            Relation(y[2], y[1]),
            _assign(x[2], x[1]),
            _assign(x[3], x[2]),
            _assign(y[3], y[2]),
            _ret(_add(x[3], y[3])),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0,
            [
                _assign(x[0], c[0]),
                _assign(y[0], c[0]),
                _assign(ptr_x[1], _addr(x[0])),
                _assign(ptr_y[1], _addr(y[0])),
                _call("func", [], [_addr(x[0])]),
                _assign(y[1], y[0]),
                Relation(x[1], x[0]),
                _call("func", [], [_addr(y[0])]),
                Relation(y[2], y[1]),
                _assign(x[2], x[1]),
                _assign(x[3], x[1]),
                _assign(y[3], y[2]),
                _ret(_add(x[1], y[2])),
            ],
        )
    )
    return in_cfg, out_cfg


def test_assignments_with_dereference_subexpressions_on_rhs_are_propagated_when_no_modification_between_def_and_use():
    """
    +-------------------------------------+
    |                 0.                  |
    | x#0 = (long) *(ptr#0 + (x#1 * 0x4)) |<--- propagate
    |      func_no_modification(x#1)      |
    |             return x#0              |<---- here
    +-------------------------------------+


    +--------------------------------------+
    |                  0.                  |
    | x#0 = (long) *(ptr#0 + (x#1 * 0x4))  |
    |      func_no_modification(x#1)       |
    | return (long) *(ptr#0 + (x#1 * 0x4)) |
    +--------------------------------------+

    """
    input_cfg, output_cfg = graphs_with_cast_dereference_assignments_no_modification()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_cast_dereference_assignments_no_modification():
    x = vars("x", 2)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0,
        [_assign(x[0], _cast(int64, _deref(_add(ptr[0], _mul(x[1], Constant(4)))))), _call("func_no_modification", [], [x[1]]), _ret(x[0])],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0,
            [
                _assign(x[0], _cast(int64, _deref(_add(ptr[0], _mul(x[1], Constant(4)))))),
                _call("func_no_modification", [], [x[1]]),
                _ret(_cast(int64, _deref(_add(ptr[0], _mul(x[1], Constant(4)))))),
            ],
        )
    )
    return in_cfg, out_cfg


def test_no_assignments_with_dereference_subexpressions_on_rhs_are_propagated():
    """
    +-------------------------------------+
    |                 0.                  |
    | x#0 = (long) *(ptr#0 + (x#1 * 0x4)) |<---- DO NOT propagate
    |    func_modifying_pointer(ptr#0)    |
    |             return x#0              |<--- here
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


def test_propagating_dereference_if_no_pointer_value_modification_between_def_and_use():
    """
    +---------------------------------+
    |               0.                |
    |  x#0 = *(ptr#0 + (x#1 * 0x4))   |<--- propagate
    | func_non_modifying_pointer(x#2) |
    |           return x#0            |<--- here
    +---------------------------------+

    +---------------------------------+
    |               0.                |
    |  x#0 = *(ptr#0 + (x#1 * 0x4))   |
    | func_non_modifying_pointer(x#2) |
    |  return *(ptr#0 + (x#1 * 0x4))  |<--- because pointer value is not modified in between
    +---------------------------------+

    """
    input_cfg, output_cfg = graphs_without_instructions_modifying_via_pointer()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_without_instructions_modifying_via_pointer():
    x = vars("x", 3)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0, [_assign(x[0], _deref(_add(ptr[0], _mul(x[1], Constant(4))))), _call("func_non_modifying_pointer", [], [x[2]]), _ret(x[0])]
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0,
            [
                _assign(x[0], _deref(_add(ptr[0], _mul(x[1], Constant(4))))),
                _call("func_non_modifying_pointer", [], [x[2]]),
                _ret(_deref(_add(ptr[0], _mul(x[1], Constant(4))))),
            ],
        )
    )
    return in_cfg, out_cfg


def test_not_propagating_when_modification_via_pointer_dereference_between_def_and_use():
    """
    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 + (x#1 * 0x4))  |<--- do not propagate into return
    | *(ptr#0 + (x#1 * 0x4)) = 0x14 |<--- cause this line changes the value
    |          return x#0           |
    +-------------------------------+

    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 + (x#1 * 0x4))  |
    | *(ptr#0 + (x#1 * 0x4)) = 0x14 |
    |          return x#0           |
    +-------------------------------+
    """
    input_cfg, output_cfg = graphs_with_pointer_value_modification_via_dereference()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_pointer_value_modification_via_dereference():
    x = vars("x", 2)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0,
        [
            _assign(x[0], _deref(_add(ptr[0], _mul(x[1], Constant(4))))),
            _assign(_deref(_add(ptr[0], _mul(x[1], Constant(4)))), Constant(20)),
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
                _assign(x[0], _deref(_add(ptr[0], _mul(x[1], Constant(4))))),
                _assign(_deref(_add(ptr[0], _mul(x[1], Constant(4)))), Constant(20)),
                _ret(x[0]),
            ],
        )
    )
    return in_cfg, out_cfg


def test_not_propagating_globals():
    """
    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 +0x4)           |
    | y#0 = x#0 + 0x4               |
    |          return y#0           |
    +-------------------------------+

    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 +0x4)           |
    | y#0 = x#0 + 0x4               |
    |          return y#0           |
    +-------------------------------+
    """
    input_cfg, output_cfg = graphs_with_globals_dereference()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_globals_dereference():
    y = Variable("y", ssa_label=0)
    x = Variable("x", ssa_label=0)
    ptr = GlobalVariable("ptr", vartype=Pointer(int32), initial_value=Constant(0x42))

    in_n0 = BasicBlock(0, [_assign(x, _deref(_add(ptr, Constant(4)))), _assign(y, _add(x, Constant(4))), _ret(x)])
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(BasicBlock(0, [_assign(x, _deref(_add(ptr, Constant(4)))), _assign(y, _add(x, Constant(4))), _ret(x)]))
    return in_cfg, out_cfg


def test_not_propagating_when_modification_via_pointer_pass_in_function_is_possible():
    """
    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 + (x#1 * 0x4))  |<--- do not propagate into return
    | func_modifying_pointer(ptr#0) |<--- cause value pointed may be changed by the function
    |          return x#0           |
    +-------------------------------+

    +-------------------------------+
    |              0.               |
    | x#0 = *(ptr#0 + (x#1 * 0x4))  |
    | func_modifying_pointer(ptr#0) |
    |          return x#0           |
    +-------------------------------+
    """
    input_cfg, output_cfg = graphs_with_pointer_value_modification_via_function_call()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_pointer_value_modification_via_function_call():
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


def test_not_propagating_when_modification_via_pointer_pass_in_function_is_possible_pointer_not_first_in_requirements():
    """
    +-------------------------------+
    |              0.               |
    | x#0 = *((x#1 * 0x4) + ptr#0)  |<--- do not propagate (ptr not the first requirement)
    | func_modifying_pointer(ptr#0) |
    |          return x#0           |<--- here
    +-------------------------------+

    +-------------------------------+
    |              0.               |
    | x#0 = *((x#1 * 0x4) + ptr#0)  |
    | func_modifying_pointer(ptr#0) |
    |          return x#0           |
    +-------------------------------+

    """
    input_cfg, output_cfg = graphs_with_pointer_value_modification_via_function_call_pointer_not_first_in_requirements()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_pointer_value_modification_via_function_call_pointer_not_first_in_requirements():
    x = vars("x", 2)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0, [_assign(x[0], _deref(_add(_mul(x[1], Constant(4)), ptr[0]))), _call("func_modifying_pointer", [], [ptr[0]]), _ret(x[0])]
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0, [_assign(x[0], _deref(_add(_mul(x[1], Constant(4)), ptr[0]))), _call("func_modifying_pointer", [], [ptr[0]]), _ret(x[0])]
        )
    )
    return in_cfg, out_cfg


def test_propagate_dereference_of_constant():
    """
    +---------------------+
    |         0.          |
    | x#0 = *(0xffffffff) |<--- propagate as no ptr used
    |      func(x#1)      |
    |     return x#0      |
    +---------------------+

    +----------------------+
    |          0.          |
    | x#0 = *(0xffffffff)  |
    |      func(x#1)       |
    | return *(0xffffffff) |
    +----------------------+

    """
    input_cfg, output_cfg = graphs_with_dereference_of_constant()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def test_address_of_constant_not_propagated():
    x = vars("x", 1, int64)[0]
    y = vars("y", 1)[0]
    input_cfg, output_cfg = ControlFlowGraph(), ControlFlowGraph()
    input_cfg.add_node(BasicBlock(0, [Assignment(x, Constant(10)), Return([_cast(int32, UnaryOperation(OperationType.address, [x]))])]))
    output_cfg.add_node(BasicBlock(0, [Assignment(x, Constant(10)), Return([_cast(int32, UnaryOperation(OperationType.address, [x]))])]))
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_with_dereference_of_constant():
    x = vars("x", 2)

    in_n0 = BasicBlock(0, [_assign(x[0], _deref(Constant(0xFFFFFFFF))), _call("func", [], [x[1]]), _ret(x[0])])
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(0, [_assign(x[0], _deref(Constant(0xFFFFFFFF))), _call("func", [], [x[1]]), _ret(_deref(Constant(0xFFFFFFFF)))])
    )
    return in_cfg, out_cfg


def test_propagating_when_dangerous_use_in_the_same_block_as_definition_but_is_not_between_definition_and_target():
    """
    +---------------+
    |      0.       |
    | scanf(&(z#0)) |
    |   z#1 = z#0   |
    |   x#0 = z#1   |
    | if(x#0 > 0xa) |<--- we want to propagate x0=z1 (x0=z0) here
    +---------------+
      |
      |
      v
    +---------------+
    |      1.       |
    | if(x#0 > 0x8) |<--- and here!
    +---------------+

    +---------------+
    |      0.       |
    | scanf(&(z#0)) |
    |   z#1 = z#0   |
    |   x#0 = z#0   |
    | if(z#0 > 0xa) |<--- propagated
    +---------------+
      |
      |
      v
    +---------------+
    |      1.       |
    | if(z#0 > 0x8) |<---- propagated
    +---------------+

    """
    in_cfg, out_cfg = graphs_with_dangerous_use_in_definition_block_but_not_between_definition_and_target()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def graphs_with_dangerous_use_in_definition_block_but_not_between_definition_and_target() -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    x = vars("x", 3)
    y = vars("y", 3)
    z = vars("z", 3, aliased=True)
    c = const(11)
    in_n0 = BasicBlock(0, [_call("scanf", [], [_addr(z[0])]), _assign(z[1], z[0]), _assign(x[0], z[1]), _if(op.greater, x[0], c[10])])
    in_n1 = BasicBlock(1, [_if(op.greater, x[0], c[8])])
    in_cfg = ControlFlowGraph()
    in_cfg.add_edges_from([UnconditionalEdge(in_n0, in_n1)])
    out_n0 = BasicBlock(0, [_call("scanf", [], [_addr(z[0])]), _assign(z[1], z[0]), _assign(x[0], z[0]), _if(op.greater, z[0], c[10])])
    out_n1 = BasicBlock(1, [_if(op.greater, z[0], c[8])])
    out_cfg = ControlFlowGraph()
    out_cfg.add_edges_from([UnconditionalEdge(out_n0, out_n1)])
    return in_cfg, out_cfg


def test_propagating_when_dangerous_use_in_the_same_block_as_target_but_is_not_between_definition_and_target():
    """
    +---------------+
    |      0.       |
    |   z#0 = 0x5   |
    | if(x#2 > z#0) |<--- we want to propagate z0=5 here
    +---------------+
      |
      |
      v
    +---------------+
    |      1.       |
    | if(x#1 > z#0) |<--- and here !
    | scanf(&(z#0)) |
    +---------------+


    +---------------+
    |      0.       |
    |   z#0 = 0x5   |
    | if(x#2 > 0x5) |<--- propagated
    +---------------+
      |
      |
      v
    +---------------+
    |      1.       |
    | if(x#1 > 0x5) |<--- propagated
    | scanf(&(z#0)) |
    +---------------+


    """
    in_cfg, out_cfg = graphs_with_dangerous_use_in_target_block_but_not_between_definition_and_target()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def graphs_with_dangerous_use_in_target_block_but_not_between_definition_and_target():
    in_cfg = ControlFlowGraph()
    x = vars("x", 3)
    y = vars("y", 3)
    z = vars("z", 3, aliased=True)
    c = const(11)
    in_n0 = BasicBlock(0, [_assign(z[0], c[5]), _if(op.greater, x[2], z[0])])
    in_n1 = BasicBlock(1, [_if(op.greater, x[1], z[0]), _call("scanf", [], [_addr(z[0])])])
    in_cfg = ControlFlowGraph()
    in_cfg.add_edges_from([UnconditionalEdge(in_n0, in_n1)])
    out_n0 = BasicBlock(0, [_assign(z[0], c[5]), _if(op.greater, x[2], c[5])])
    out_n1 = BasicBlock(1, [_if(op.greater, x[1], c[5]), _call("scanf", [], [_addr(z[0])])])
    out_cfg = ControlFlowGraph()
    out_cfg.add_edges_from([UnconditionalEdge(out_n0, out_n1)])
    return in_cfg, out_cfg


def test_dangerous_dereference_in_same_block_as_target():
    """Show that definitions are not propagated if their address is being used 32 bits
    +----------------+     +------------------------+
    |                |     |           0.           |
    |       2.       |     |       x#0 = 0x1        |
    | ptr#1 = &(y#0) |     |       y#0 = 0x2        |
    |                |     |      z#0 = rand()      |
    |                | <-- |     if(z#0 < 0xa)      |
    +----------------+     +------------------------+
      |                      |
      |                      |
      |                      v
      |                    +------------------------+
      |                    |           1.           |
      |                    |     ptr#0 = &(x#0)     |
      |                    +------------------------+
      |                      |
      |                      |
      |                      v
      |                    +------------------------+
      |                    |           3.           |
      |                    | ptr#2 = ϕ(ptr#0,ptr#1) |
      |                    |     *(ptr#2) = 0x3     |
      |                    |       print(x#0)       |
      |                    |       print(y#0)       |
      |                    |      z#1 = ptr#2       |
      |                    |      z#2 = *(z#1)      |
      +------------------> |       return z#2       |
                           +------------------------+

    +----------------+     +------------------------+
    |                |     |           0.           |
    |       2.       |     |       x#0 = 0x1        |
    | ptr#1 = &(y#0) |     |       y#0 = 0x2        |
    |                |     |      z#0 = rand()      |
    |                | <-- |     if(z#0 < 0xa)      |
    +----------------+     +------------------------+
      |                      |
      |                      |
      |                      v
      |                    +------------------------+
      |                    |           1.           |
      |                    |     ptr#0 = &(x#0)     |
      |                    +------------------------+
      |                      |
      |                      |
      |                      v
      |                    +------------------------+
      |                    |           3.           |
      |                    | ptr#2 = ϕ(ptr#0,ptr#1) |
      |                    |     *(ptr#2) = 0x3     |
      |                    |       print(x#0)       |<--- do not propagate x#0 = 0x1 cause dangerous use *(ptr#2) = 0x3 lies in between
      |                    |       print(y#0)       |<--- do not propagate y#0 = 0x2 cause dangerous use *(ptr#2) = 0x3 lies in between
      |                    |      z#1 = ptr#2       |
      |                    |     z#2 = *(ptr#2)     |
      +------------------> |    return *(ptr#2)     |
                           +------------------------+

    """
    in_cfg, out_cfg = _graphs_with_dangerous_dereference_in_the_same_block_as_target()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def _graphs_with_dangerous_dereference_in_the_same_block_as_target() -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    in_cfg = ControlFlowGraph()
    x = vars("x", 1, aliased=True)
    y = vars("y", 1, aliased=True)
    z = vars("z", 3, aliased=False)
    ptr = vars("ptr", 3, aliased=False)
    c = const(11)
    in_n0 = BasicBlock(0, [_assign(x[0], c[1]), _assign(y[0], c[2]), _call("rand", [z[0]], []), _if(op.less, z[0], c[10])])
    in_n1 = BasicBlock(1, [_assign(ptr[0], _addr(x[0]))])
    in_n2 = BasicBlock(2, [_assign(ptr[1], _addr(y[0]))])
    in_n3 = BasicBlock(
        3,
        [
            _phi(ptr[2], ptr[0], ptr[1]),
            _assign(_deref(ptr[2]), c[3]),
            _call("print", [], [x[0]]),
            _call("print", [], [y[0]]),
            _assign(z[1], ptr[2]),
            _assign(z[2], _deref(z[1])),
            _ret(z[2]),
        ],
    )
    in_cfg.add_edges_from(
        [UnconditionalEdge(in_n0, in_n1), UnconditionalEdge(in_n0, in_n2), UnconditionalEdge(in_n1, in_n3), UnconditionalEdge(in_n2, in_n3)]
    )

    out_cfg = ControlFlowGraph()
    out_n0 = BasicBlock(0, [_assign(x[0], c[1]), _assign(y[0], c[2]), _call("rand", [z[0]], []), _if(op.less, z[0], c[10])])
    out_n1 = BasicBlock(1, [_assign(ptr[0], _addr(x[0]))])
    out_n2 = BasicBlock(2, [_assign(ptr[1], _addr(y[0]))])
    out_n3 = BasicBlock(
        3,
        [
            _phi(ptr[2], ptr[0], ptr[1]),
            _assign(_deref(ptr[2]), c[3]),
            _call("print", [], [x[0]]),
            _call("print", [], [y[0]]),
            _assign(z[1], ptr[2]),
            _assign(z[2], _deref(ptr[2])),
            _ret(_deref(ptr[2])),
        ],
    )
    out_cfg.add_edges_from(
        [
            UnconditionalEdge(out_n0, out_n1),
            UnconditionalEdge(out_n0, out_n2),
            UnconditionalEdge(out_n1, out_n3),
            UnconditionalEdge(out_n2, out_n3),
        ]
    )
    return in_cfg, out_cfg


def test_dangerous_dereference_in_the_same_block_as_target_and_definition_64bit():
    """
    +------------------+
    |        0.        |
    |   x#0 = rand()   |
    | y#0 = x#0 + 0x5  |
    |  ptr#0 = &(y#0)  |
    | x#1 = (long) y#0 |<--- y#0 = x#0 + 0x5 can be propagated here cause no dangerous uses in between
    |  *(ptr#0) = 0xa  |
    |    y#1 = y#0     |<--- y#0 = x#0 + 0x5 CAN NOT be propagated here cause dangerous use *(ptr#0) = 0xa in between
    |    return y#0    |
    +------------------+

    +------------------------+
    |           0.           |
    |      x#0 = rand()      |
    |    y#0 = x#0 + 0x5     |
    |     ptr#0 = &(y#0)     |
    | x#1 = (long) x#0 + 0x5 |<--- propagated
    |     *(ptr#0) = 0xa     |
    |       y#1 = y#0        |<--- NOT propagated
    |       return y#0       |<--- propagated :)
    +------------------------+
    """
    in_cfg, out_cfg = _graphs_dangerous_dereference_in_the_same_block_as_target_and_definition_64bit()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def _graphs_dangerous_dereference_in_the_same_block_as_target_and_definition_64bit() -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    in_cfg = ControlFlowGraph()
    x = vars("x", 2, int64, aliased=False)
    y = vars("y", 2, int32, aliased=True)
    ptr = vars("ptr", 1, int64, aliased=False)
    c = const(11)
    in_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(ptr[0], _addr(y[0])),
            _assign(x[1], _cast(int64, y[0])),
            _assign(_deref(ptr[0]), c[10]),
            _assign(y[1], y[0]),
            _ret(y[0]),
        ],
    )
    in_cfg.add_node(in_node)
    out_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(ptr[0], _addr(y[0])),
            _assign(x[1], _cast(int64, _add(x[0], c[5]))),
            _assign(_deref(ptr[0]), c[10]),
            _assign(y[1], y[0]),
            _ret(y[0]),
        ],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_node)
    return in_cfg, out_cfg


def test_dangerous_dereference_in_the_same_block_as_target_and_definition_32bit():
    """
    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    | y#0 = x#0 + 0x5 |
    | ptr#0 = &(y#0)  |
    |    x#1 = y#0    |<--- y#0 = x#0 + 0x5 can be propagated here cause no dangerous uses in between
    | *(ptr#0) = 0xa  |
    |    y#1 = y#0    |<--- y#0 = x#0 + 0x5 CAN NOT be propagated here cause dangerous use *(ptr#0) = 0xa in between
    |   return y#0    |
    +-----------------+

    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    | y#0 = x#0 + 0x5 |
    | ptr#0 = &(y#0)  |
    | x#1 = x#0 + 0x5 |<--- propagated
    | *(ptr#0) = 0xa  |
    |    y#1 = y#0    |<--- NOT propagated
    |   return y#0    |<--- propagated :)
    +-----------------+
    """
    in_cfg, out_cfg = _graphs_dangerous_dereference_in_the_same_block_as_target_and_definition_32bit()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def _graphs_dangerous_dereference_in_the_same_block_as_target_and_definition_32bit() -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    in_cfg = ControlFlowGraph()
    x = vars("x", 2, aliased=False)
    y = vars("y", 2, aliased=True)
    ptr = vars("ptr", 1, aliased=False)
    c = const(11)
    in_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(ptr[0], _addr(y[0])),
            _assign(x[1], y[0]),
            _assign(_deref(ptr[0]), c[10]),
            _assign(y[1], y[0]),
            _ret(y[0]),
        ],
    )
    in_cfg.add_node(in_node)
    out_cfg = ControlFlowGraph()
    out_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(ptr[0], _addr(y[0])),
            _assign(x[1], _add(x[0], c[5])),
            _assign(_deref(ptr[0]), c[10]),
            _assign(y[1], y[0]),
            _ret(y[0]),
        ],
    )
    out_cfg.add_node(out_node)
    return in_cfg, out_cfg


def test_dangerous_pointer_use_in_single_block_graph():
    """
    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    | y#0 = x#0 + 0x5 |
    | ptr#0 = &(y#0)  |
    |    x#1 = y#0    |
    |  scanf(ptr#0)   |
    |    y#1 = y#0    |
    |   return y#1    |
    +-----------------+

    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    | y#0 = x#0 + 0x5 |
    | ptr#0 = &(y#0)  |
    | x#1 = x#0 + 0x5 |
    |  scanf(&(y#0))  |
    |    y#1 = y#0    |
    |   return y#0    |
    +-----------------+

    """
    in_cfg, out_cfg = _graphs_with_dangerous_pointer_use()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def _graphs_with_dangerous_pointer_use() -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    in_cfg = ControlFlowGraph()
    x = vars("x", 2, aliased=False)
    y = vars("y", 2, aliased=True)
    ptr = vars("ptr", 1, aliased=False)
    c = const(11)
    in_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(ptr[0], _addr(y[0])),
            _assign(x[1], y[0]),
            _call("scanf", [], [ptr[0]]),
            _assign(y[1], y[0]),
            _ret(y[1]),
        ],
    )
    in_cfg.add_node(in_node)
    out_cfg = ControlFlowGraph()
    out_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(ptr[0], _addr(y[0])),
            _assign(x[1], _add(x[0], c[5])),
            _call("scanf", [], [_addr(y[0])]),
            _assign(y[1], y[0]),
            _ret(y[0]),
        ],
    )
    out_cfg.add_node(out_node)
    return in_cfg, out_cfg


def test_dangerous_reference_use_in_single_block_graph():
    """
    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    | y#0 = x#0 + 0x5 |
    |    x#1 = y#0    |
    |  scanf(&(y#0))  |
    |    y#1 = y#0    |
    |   return y#1    |
    +-----------------+

    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    | y#0 = x#0 + 0x5 |
    | x#1 = x#0 + 0x5 |
    |  scanf(&(y#0))  |
    |    y#1 = y#0    |
    |   return y#0    |
    +-----------------+

    """
    in_cfg, out_cfg = _graphs_with_dangerous_reference_use()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def test_dangerous_relation_in_between():
    """
    Don't propagate y#0 into rand(x#0) because of possible change in between (relation)
    +-----------------+
    |       0.        |
    |    x#0 = y#0    |
    |   memset(y#0)   |
    |   y#1 -> y#0    |
    | z#0 = rand(x#0) |
    |   return z#0    |
    +-----------------+

    +-----------------+
    |       0.        |
    |    x#0 = y#0    |
    |   memset(y#0)   |
    |   y#1 -> y#0    |
    | z#0 = rand(x#0) |
    |   return z#0    |
    +-----------------+
    """
    in_cfg, out_cfg = _graph_with_dangerous_relation_between()
    _run_expression_propagation(in_cfg)
    assert _graphs_equal(in_cfg, out_cfg)


def _graph_with_dangerous_relation_between():
    in_cfg = ControlFlowGraph()
    x = vars("x", 2, aliased=False)
    y = vars("y", 2, aliased=True)
    z = vars("z", 1, aliased=False)
    c = const(11)
    in_node = BasicBlock(
        0,
        [
            _assign(x[0], y[0]),
            _call("memset", [], [y[0]]),
            Relation(y[1], y[0]),
            _call("rand", [z[0]], [x[0]]),
            _ret(z[0]),
        ],
    )
    in_cfg.add_node(in_node)
    out_cfg = ControlFlowGraph()
    out_node = BasicBlock(
        0,
        [
            _assign(x[0], y[0]),
            _call("memset", [], [y[0]]),
            Relation(y[1], y[0]),
            _call("rand", [z[0]], [x[0]]),
            _ret(z[0]),
        ],
    )
    out_cfg.add_node(out_node)
    return in_cfg, out_cfg


def _graphs_with_dangerous_reference_use() -> Tuple[ControlFlowGraph, ControlFlowGraph]:
    in_cfg = ControlFlowGraph()
    x = vars("x", 2, aliased=False)
    y = vars("y", 2, aliased=True)
    c = const(11)
    in_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(x[1], y[0]),
            _call("scanf", [], [_addr(y[0])]),
            _assign(y[1], y[0]),
            _ret(y[1]),
        ],
    )
    in_cfg.add_node(in_node)
    out_cfg = ControlFlowGraph()
    out_node = BasicBlock(
        0,
        [
            _call("rand", [x[0]], []),
            _assign(y[0], _add(x[0], c[5])),
            _assign(x[1], _add(x[0], c[5])),
            _call("scanf", [], [_addr(y[0])]),
            _assign(y[1], y[0]),
            _ret(y[0]),
        ],
    )
    out_cfg.add_node(out_node)
    return in_cfg, out_cfg


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


def test_assignments_containing_aliased_propagated():
    """
    +-----------------+
    |       0.        |
    |    x#0 = z#0    |
    |    x#1 = x#0    |
    |   print(z#0)    |
    |    z#1 = z#0    |
    | x#2 = z#1 + 0x5 |
    |   print(x#2)    |
    |    z#3 = 0x4    |
    |    x#3 = z#3    |
    |    x#4 = x#3    |
    |   print(x#4)    |
    +-----------------+

    +------------------+
    |        0.        |
    |    x#0 = z#0     |
    |    x#1 = z#0     |
    |    print(z#0)    |
    |    z#1 = z#0     |
    | x#2 = z#0 + 0x5  |
    | print(z#0 + 0x5) |
    |    z#3 = 0x4     |
    |    x#3 = 0x4     |
    |    x#4 = 0x4     |
    |    print(0x4)    |
    +------------------+
    """
    input_cfg, output_cfg = graphs_aliased_propagation()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_aliased_propagation():
    x = vars("x", 6)
    z = vars("z", 6, aliased=True)
    c = const(10)
    in_n0 = BasicBlock(
        0,
        [
            _assign(x[0], z[0]),
            _assign(x[1], x[0]),
            _call("print", [], [z[0]]),
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
            _assign(x[1], z[0]),
            _call("print", [], [z[0]]),
            _assign(z[1], z[0]),
            _assign(x[2], _add(z[0], c[5])),
            _call("print", [], [_add(z[0], c[5])]),
            _assign(z[3], c[4]),
            _assign(x[3], c[4]),
            _assign(x[4], c[4]),
            _call("print", [], [c[4]]),
        ],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_n0)
    return in_cfg, out_cfg


def test_calls_not_propagated():
    """
    +-----------------+
    |       0.        |
    |  x#0 = rand()   |
    |    x#1 = x#0    |
    | z#0 = x#1 + 0x5 |
    |   return z#0    |
    +-----------------+

    +------------------+
    |        0.        |
    |   x#0 = rand()   |
    |    x#1 = x#0     |
    | z#0 = x#0 + 0x5  |
    | return x#0 + 0x5 |
    +------------------+

    """
    x = vars("x", 6)
    z = vars("z", 6, aliased=True)
    c = const(10)
    instructions = [_call("rand", [x[0]], []), _assign(x[1], x[0]), _assign(z[0], _add(x[1], c[5])), _ret(z[0])]
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    _run_expression_propagation(cfg)
    assert [i for i in cfg.instructions] == [
        _call("rand", [x[0]], []),
        _assign(x[1], x[0]),
        _assign(z[0], _add(x[0], c[5])),
        _ret(_add(x[0], c[5])),
    ]


def test_address_assignments_propagated():
    """
    +--------------+
    |      0.      |
    | x#0 = &(z#0) |
    |  x#1 = x#0   |
    |  scanf(x#1)  |
    |  z#1 = z#0   |
    |  return z#1  |
    +--------------+
    +-----------------+
    |      0.         |
    |  x#0 = &(z#0)   |
    |  x#1 = &(z#0)   |
    |  scanf(&(z#0))  |
    |  z#1 = z#0      |
    |  return z#0     |
    +-----------------+

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
        _assign(x[1], _addr(z[0])),
        _call("scanf", [], [_addr(z[0])]),
        _assign(z[1], z[0]),
        _ret(z[0]),
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
    | z#2 = ϕ(0x6,w#1) |  |
    | v#2 = ϕ(y#1,v#1) |  |
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
    in_n0 = BasicBlock(0, [_assign(x[0], y[0]), _assign(w[0], c[0]), _assign(z[0], c[6]), _assign(v[0], y[1])])
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
    out_n0 = BasicBlock(0, [_assign(x[0], y[0]), _assign(w[0], c[0]), _assign(z[0], c[6]), _assign(v[0], y[1])])
    out_n1 = BasicBlock(1, [_if(op.less_or_equal, y[2], c[1])])
    out_n2 = BasicBlock(
        2,
        [
            _phi(x[2], y[0], y[1]),
            _phi(w[2], c[0], w[1]),
            _phi(z[2], c[6], w[1]),
            _phi(v[2], y[1], v[1]),
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
    | y#2 = (&(0x2)) + 0x0 |
    +----------------------+
    """
    input_cfg, output_cfg = graphs_no_ep_in_address()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


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
    x = vars("x", 2, aliased=True)
    y = vars("y", 1)
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [_assign(x[1], x[0]), _if(op.greater, y[0], x[1])]))
    _run_expression_propagation(cfg, _generate_options(branch=1))
    node = [n for n in cfg][0]
    assert node.instructions == [_assign(x[1], x[0]), _if(op.greater, y[0], x[0])]


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
            _assign(y[2], _add(_addr(c[2]), c[0])),
        ],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_n0)
    return in_cfg, out_cfg


def test_do_not_propagate_unknown_expressions():
    ecx = vars("ecx", 6, aliased=True)
    edi = vars("edi", 5, Pointer(Integer(32, True), 32), aliased=True)
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

    +------------------------------------------+
    |                    0.                    |
    |           var_14#1 = var_14#0            |
    |          var_28#0 = &(var_14#1)          |
    | "__isoc99_scanf"(0x804b01f, &(var_14#1)) |
    |           var_14#2 -> var_14#1           |
    |             eax#1 = var_14#2             |
    |      "printf"(0x804b024, var_14#2)       |
    |           var_14#3 = var_14#2            |
    |        var_14#4 = var_14#2 + 0x2         |
    |          var_28#1 = &(var_14#4)          |
    | "__isoc99_scanf"(0x804b01f, &(var_14#4)) |
    |           var_14#5 -> var_14#4           |
    +------------------------------------------+
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
    assert list(cfg.instructions) == [
        instructions[0],
        # _assign(var_28[0], UnaryOperation(OperationType.address, [var_14[0]], Pointer(Integer(32, True), 32), None, False)),
        instructions[1],
        _assign(
            ListOperation([]),
            Call(
                Constant("__isoc99_scanf", UnknownType()),
                [
                    Constant(134524959, Integer(32, True)),
                    UnaryOperation(OperationType.address, [var_14[1]], Pointer(Integer(32, True), 32), None, False),
                ],
                Pointer(CustomType("void", 0), 32),
                2,
            ),
        ),
        # Relation(var_14[2], var_14[0]),
        instructions[3],
        instructions[4],
        _assign(
            ListOperation([]),
            Call(
                Constant("printf", UnknownType()),
                [Constant(134524964, Pointer(Integer(8, True), 32)), var_14[2]],
                Pointer(CustomType("void", 0), 32),
                3,
            ),
        ),
        instructions[6],
        _assign(var_14[4], _add(var_14[2], Constant(2))),
        instructions[8],
        _assign(
            ListOperation([]),
            Call(
                Constant("__isoc99_scanf", UnknownType()),
                [
                    Constant(134524959, Integer(32, True)),
                    UnaryOperation(OperationType.address, [var_14[4]], Pointer(Integer(32, True), 32), None, False),
                ],
                Pointer(CustomType("void", 0), 32),
                5,
            ),
        ),
        instructions[10],
    ]


def test_address_into_dereference():
    """
    Test with cast in destination (x#0 stays the same type)
    +---------------------+
    |         0.          |
    | (long) x#0 = &(x#1) |
    |    *(x#0) = x#0     |
    +---------------------+

    +---------------------+
    |         0.          |
    | (long) x#0 = &(x#1) |
    |    *(x#0) = x#0     |
    +---------------------+
    """
    input_cfg, output_cfg = graphs_addr_into_deref()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def test_address_into_dereference_with_multiple_defs():
    """
    Extended test of above where we have two definitions (as a ListOp).
    +---------------------+
    |         0.          |
    | (long) x#1 = &(x#0) |
    |  *(x#1),y#0 = x#1   |
    +---------------------+

    +---------------------+
    |         0.          |
    | (long) x#1 = &(x#0) |
    |  *(x#1),y#0 = x#1   |
    +---------------------+
    """
    input_cfg, output_cfg = graphs_addr_into_deref_multiple_defs()
    _run_expression_propagation(input_cfg)
    assert _graphs_equal(input_cfg, output_cfg)


def graphs_addr_into_deref():
    x = vars("x", 2)
    in_n0 = BasicBlock(
        0,
        [_assign(_cast(int64, x[0]), _addr(x[1])), _assign(_deref(x[0]), x[0])],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_n0 = BasicBlock(
        0,
        [_assign(_cast(int64, x[0]), _addr(x[1])), _assign(_deref(x[0]), x[0])],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_n0)
    return in_cfg, out_cfg


def graphs_addr_into_deref_multiple_defs():
    x = vars("x", 2)
    y = vars("y", 1)
    in_n0 = BasicBlock(
        0,
        [_assign(_cast(int64, x[1]), _addr(x[0])), _assign(ListOperation([_deref(x[1]), y[0]]), x[1])],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_n0 = BasicBlock(
        0,
        [_assign(_cast(int64, x[1]), _addr(x[0])), _assign(ListOperation([_deref(x[1]), y[0]]), x[1])],
    )
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(out_n0)
    return in_cfg, out_cfg


def graphs_with_no_propagation_of_contraction_address_assignment():
    x = vars("x", 3)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0,
        [
            _assign(UnaryOperation(OperationType.cast, [x[1]], contraction=True), _addr(x[0])),
            _assign(x[2], UnaryOperation(OperationType.cast, [x[1]], contraction=True)),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    out_cfg = ControlFlowGraph()
    out_cfg.add_node(
        BasicBlock(
            0,
            [
                _assign(UnaryOperation(OperationType.cast, [x[1]], contraction=True), _addr(x[0])),
                _assign(x[2], UnaryOperation(OperationType.cast, [_addr(x[0])], contraction=True)),
            ],
        )
    )
    return in_cfg, out_cfg


def _generate_options(instr: int = 10, branch: int = 10, call: int = 10, assign: int = 10) -> Options:
    options = Options()
    options.set("expression-propagation-memory.maximum_instruction_complexity", instr)
    options.set("expression-propagation-memory.maximum_branch_complexity", branch)
    options.set("expression-propagation-memory.maximum_call_complexity", call)
    options.set("expression-propagation-memory.maximum_assignment_complexity", assign)
    return options


def _run_expression_propagation(cfg: ControlFlowGraph, options=_generate_options()) -> None:
    ExpressionPropagationMemory().run(DecompilerTask(name="test", function_identifier="", cfg=cfg, options=options))


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


def _mul(*operands: Expression) -> BinaryOperation:
    return BinaryOperation(OperationType.multiply, list(operands))


def _assign(x: Expression, y: Expression) -> Assignment:
    return Assignment(x, y)


def _deref(x: Expression) -> UnaryOperation:
    return UnaryOperation(OperationType.dereference, [x])


def _addr(x: Expression) -> UnaryOperation:
    return UnaryOperation(OperationType.address, [x])


def _phi(x: Expression, *y: Expression) -> Phi:
    return Phi(x, list(y))


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


def _cast(type: Type, x: Expression) -> UnaryOperation:
    return UnaryOperation(OperationType.cast, [x], vartype=type)
