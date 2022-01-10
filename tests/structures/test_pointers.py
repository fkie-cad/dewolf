from typing import List

from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, UnconditionalEdge
from decompiler.structures.pointers import Pointers
from decompiler.structures.pseudo.expressions import Constant, Expression, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation
from decompiler.structures.pseudo.operations import OperationType
from decompiler.structures.pseudo.operations import OperationType as op
from decompiler.structures.pseudo.operations import UnaryOperation
from decompiler.structures.pseudo.typing import Integer, Pointer, Type

int32 = Integer.int32_t()
int64 = Integer.int64_t()


def test_if_else():
    x = vars("x", 3, aliased=True)
    y = vars("y", 3, aliased=True)
    z = vars("z", 1)
    ptr = vars("ptr", 3, aliased=True)
    c = const(10)

    n0 = BasicBlock(0, [_assign(x[0], c[1]), _assign(y[0], c[2]), _if(op.less, z[0], c[0])])
    n1 = BasicBlock(1, [_assign(ptr[0], _addr(x[0]))])
    n2 = BasicBlock(2, [_assign(ptr[1], _addr(y[0]))])
    n3 = BasicBlock(
        3,
        [
            _phi(ptr[2], ptr[0], ptr[1]),
            _assign(_deref(ptr[2]), c[3]),
            _assign(x[1], x[0]),
            _assign(y[1], y[0]),
            _call("print", [x[1]]),
            _call("print", [y[1]]),
        ],
    )

    cfg = ControlFlowGraph()
    cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n0, n2), UnconditionalEdge(n1, n3), UnconditionalEdge(n2, n3)])

    pointers = Pointers().from_cfg(cfg)
    assert pointers.points_to == {ptr[0]: {"x"}, ptr[1]: {"y"}, ptr[2]: {"x", "y"}}
    assert pointers.is_pointed_by == {"x": {ptr[0], ptr[2]}, "y": {ptr[1], ptr[2]}}


def test_with_pointers_without_aliased():
    x = vars("x", 2)
    ptr = vars("ptr", 1, type=Pointer(int32))

    in_n0 = BasicBlock(
        0,
        [
            _call("malloc", [ptr[0]], [Constant(10)]),
            _assign(x[0], _deref(_add(ptr[0], _mul(x[1], Constant(4))))),
            _call("func_modifying_pointer", [], [ptr[0]]),
            _ret(x[0]),
        ],
    )
    in_cfg = ControlFlowGraph()
    in_cfg.add_node(in_n0)
    pointers = Pointers().from_cfg(in_cfg)
    assert pointers.points_to == {ptr[0]: set()}
    assert pointers.is_pointed_by == {}


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
