from functools import partial

import decompiler.structures.pseudo.operations as operations
from decompiler.pipeline.preprocessing import RegisterPairHandling
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, RegisterPair, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer, UnknownType

cast = partial(operations.UnaryOperation, operations.OperationType.cast)
division = partial(operations.BinaryOperation, operations.OperationType.divide)
modulo = partial(operations.BinaryOperation, operations.OperationType.modulo)
right_shift = partial(operations.BinaryOperation, operations.OperationType.right_shift)
logical_and = partial(operations.BinaryOperation, operations.OperationType.bitwise_and)
constant = partial(operations.Constant)

int16 = Integer.int16_t()
int32 = Integer.int32_t()
int64 = Integer.int64_t()
error_type = UnknownType()

v0 = Variable("v0", int32, 2)
v1 = Variable("v1", int32, 3)
v2 = Variable("v2", int32, 5)
v3 = Variable("v3", int32, 7)
v4 = Variable("v4", int32, 7)
v5 = Variable("v5", int32, 7)
v6 = Variable("v6", int32, 2)
v7 = Variable("v7", int32, 3)
v8 = Variable("v8", int32, 5)
var_wrong_type = Variable("v", 0, 0)
var_wrong_type2 = Variable("v2", 0, 0)

register_pair1 = RegisterPair(v2, v1, int64)
replacement_var1 = Variable("loc_0", int64, 0)
register_pair2 = RegisterPair(v7, v8, int64)
replacement_var2 = Variable("loc_1", int64, 0)
register_pair_with_wrong_type = RegisterPair(var_wrong_type, var_wrong_type2, int64)

higher_register_mask_16 = Constant(0x10, Integer.uint16_t())
lower_register_mask_16 = Constant(0xFFFF, int16)
higher_register_mask_32 = Constant(0x20, Integer.uint32_t())
lower_register_mask_32 = Constant(0xFFFFFFFF, int32)


class MockTask:
    def __init__(self, cfg: ControlFlowGraph):
        self.graph = cfg


def test_one_register_pair_is_handled_correctly():
    cfg = ControlFlowGraph()
    n1 = BasicBlock(
        0,
        [
            Assignment(register_pair1, cast([v0], int64)),
            Assignment(v4, division([register_pair1, v3], int32)),
            Assignment(v5, modulo([register_pair1, v3], int32)),
        ],
    )
    cfg.add_node(n1)
    task = MockTask(cfg)
    RegisterPairHandling().run(task)
    assert n1.instructions == [
        Assignment(replacement_var1, cast([v0], int64)),
        Assignment(v1, logical_and([replacement_var1, lower_register_mask_32.copy()])),
        Assignment(v2, right_shift([replacement_var1, higher_register_mask_32.copy()])),
        Assignment(v4, division([replacement_var1, v3], int32)),
        Assignment(v5, modulo([replacement_var1, v3], int32)),
    ]


def test_multiple_register_pairs_are_handled_correctly():
    cfg = ControlFlowGraph()
    eax, ebx, a, b = (lambda x, name=name: Variable(name, Integer.int32_t(), ssa_label=x) for name in ["eax", "ebx", "a", "b"])
    v0, v1 = (lambda name=name: Variable(name, Integer.int64_t(), ssa_label=0) for name in ["loc_0", "loc_1"])
    cfg.add_node(
        n1 := BasicBlock(
            0,
            [
                Assignment(RegisterPair(ebx(0), eax(0), Integer.int64_t()), UnaryOperation(OperationType.cast, [a(0)])),
                Assignment(a(1), eax(0)),
                Assignment(b(0), ebx(0)),
                Assignment(
                    RegisterPair(ebx(1), eax(1), Integer.int64_t()),
                    Call(FunctionSymbol("foo", 0), [RegisterPair(ebx(0), eax(0), Integer.int64_t()), a(1)]),
                ),
                Return([ebx(1)]),
            ],
        )
    )
    task = MockTask(cfg)
    RegisterPairHandling().run(task)
    assert n1.instructions == [
        Assignment(v0(), UnaryOperation(OperationType.cast, [a(0)])),
        Assignment(eax(0), BinaryOperation(OperationType.bitwise_and, [v0(), lower_register_mask_32.copy()])),
        Assignment(ebx(0), BinaryOperation(OperationType.right_shift, [v0(), higher_register_mask_32.copy()])),
        Assignment(a(1), eax(0)),
        Assignment(b(0), ebx(0)),
        Assignment(v1(), Call(FunctionSymbol("foo", 0), [v0(), a(1)])),
        Assignment(eax(1), BinaryOperation(OperationType.bitwise_and, [v1(), lower_register_mask_32.copy()])),
        Assignment(ebx(1), BinaryOperation(OperationType.right_shift, [v1(), higher_register_mask_32.copy()])),
        Return([ebx(1)]),
    ] or n1.instructions == [
        Assignment(v1(), UnaryOperation(OperationType.cast, [a(0)])),
        Assignment(eax(0), BinaryOperation(OperationType.bitwise_and, [v1(), lower_register_mask_32.copy()])),
        Assignment(ebx(0), BinaryOperation(OperationType.right_shift, [v1(), higher_register_mask_32.copy()])),
        Assignment(a(1), eax(0)),
        Assignment(b(0), ebx(0)),
        Assignment(v0(), Call(FunctionSymbol("foo", 0), [v1(), a(1)])),
        Assignment(eax(1), BinaryOperation(OperationType.bitwise_and, [v0(), lower_register_mask_32.copy()])),
        Assignment(ebx(1), BinaryOperation(OperationType.right_shift, [v0(), higher_register_mask_32.copy()])),
        Return([ebx(1)]),
    ]


def test_non_32_bit_register_pairs_are_handled_correctly():
    cfg = ControlFlowGraph()
    ax = Variable("ax", int16, 0)
    dx = Variable("dx", int16, 0)
    pair = RegisterPair(dx, ax, int32)
    replacement_var = Variable("loc_0", int32, 0)
    n1 = BasicBlock(0, instructions=[Assignment(pair, constant(4)), Assignment(v1, ax), Assignment(v2, dx), Assignment(v3, pair)])
    cfg.add_node(n1)
    task = MockTask(cfg)
    RegisterPairHandling().run(task)
    assert n1.instructions == [
        Assignment(replacement_var, constant(4)),
        Assignment(ax, logical_and([replacement_var, lower_register_mask_16.copy()])),
        Assignment(dx, right_shift([replacement_var, higher_register_mask_16.copy()])),
        Assignment(v1, ax),
        Assignment(v2, dx),
        Assignment(v3, replacement_var),
    ]


def test_undefined_register_pair_is_replaced():
    cfg = ControlFlowGraph()
    eax, ebx = Variable("eax", Integer.uint32_t()), Variable("ebx", Integer.uint32_t())
    cfg.add_node(
        block := BasicBlock(
            0,
            instructions=[
                Assignment(
                    operations.ListOperation([]),
                    operations.Call(FunctionSymbol("kill", 0), [RegisterPair(ebx, eax, Integer.uint64_t())]),
                )
            ],
        )
    )
    RegisterPairHandling().run(MockTask(cfg))
    assert block.instructions == [
        Assignment(
            replacement_var := Variable("loc_0", Integer.uint64_t(), 0),
            operations.BinaryOperation(
                operations.OperationType.plus,
                [eax, operations.BinaryOperation(operations.OperationType.left_shift, [ebx, Constant(eax.type.size, Integer.int32_t())])],
            ),
        ),
        Assignment(operations.ListOperation([]), operations.Call(FunctionSymbol("kill", 0), [replacement_var])),
    ]


def test_definition_is_placed_before_usage():
    """
    +----------------------------+
    |             0.             |
    | if(ebx#0 == (eax#0 + 0x1)) |
    +----------------------------+
      |
      |
      v
    +----------------------------+
    |             1.             |
    | bar((ebx#0:eax#0))         |
    +----------------------------+
      |
      |
      v
    +----------------------------+
    |             2.             |
    | ecx#0 = qtx((ebx#0:eax#0)) |
    | return ecx#0               |
    +----------------------------+
    """
    cfg = ControlFlowGraph()
    eax, ebx, ecx = (lambda name=name: Variable(name, Integer.int32_t(), ssa_label=0) for name in ["eax", "ebx", "ecx"])
    bar, qtx = [lambda name=name: FunctionSymbol(name, 0) for name in ["bar", "qtx"]]
    pair = lambda: RegisterPair(ebx(), eax(), Integer.int64_t())
    v = lambda: Variable("loc_0", Integer.int64_t(), ssa_label=0)
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[
                    Branch(
                        Condition(OperationType.equal, [ebx(), BinaryOperation(OperationType.plus, [eax(), Constant(1, Integer.char())])])
                    )
                ],
            ),
            n1 := BasicBlock(1, instructions=[Assignment(ListOperation([]), Call(bar(), [pair()]))]),
            n2 := BasicBlock(2, instructions=[Assignment(ecx(), Call(qtx(), [pair()])), Return([ecx()])]),
        ]
    )
    cfg.add_edges_from([TrueCase(n0, n1), UnconditionalEdge(n1, n2)])
    RegisterPairHandling().run(MockTask(cfg))
    assert n0.instructions == [
        Branch(Condition(OperationType.equal, [ebx(), BinaryOperation(OperationType.plus, [eax(), Constant(1, Integer.char())])]))
    ]
    assert n1.instructions == [
        Assignment(
            v(),
            BinaryOperation(
                OperationType.plus,
                [eax(), BinaryOperation(OperationType.left_shift, [ebx(), Constant(eax().type.size, Integer.int32_t())])],
            ),
        ),
        Assignment(ListOperation([]), Call(bar(), [v()])),
    ]
    assert n2.instructions == [Assignment(ecx(), Call(qtx(), [v()])), Return([ecx()])]


def test_definition_is_inserted_correctly():
    """
    Test whether the correct dominator is chosen as insert location for definitions.
         +----------------------------+
         |             0.             |
         | eax#0 = 0x1                |
         | ebx#0 = foo(eax#0)         |
         | if(eax#0 > ebx#0)          | -+    <-- insert definition here
         +----------------------------+  |
           |                             |
           |                             |
           v                             |
         +----------------------------+  |
         |             1.             |  |
      +- | if(ebx#0 == (eax#0 + 0x1)) |  |
      |  +----------------------------+  |
      |    |                             |
      |    |                             |
      |    v                             |
      |  +----------------------------+  |
      |  |             2.             |  |
      |  | bar((ebx#0:eax#0))         |  |
      |  +----------------------------+  |
      |    |                             |
      |    |                             |
      |    v                             |
      |  +----------------------------+  |
      |  |             3.             |  |
      |  | ecx#0 = qtx((ebx#0:eax#0)) |  |
      +> | return ecx#0               | <+
         +----------------------------+
    """
    cfg = ControlFlowGraph()
    eax, ebx, ecx = [Variable(name, Integer.uint32_t(), 0) for name in ["eax", "ebx", "ecx"]]
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[
                    Assignment(eax.copy(), Constant(1, Integer.char())),
                    Assignment(ebx.copy(), Call(FunctionSymbol("foo", 0), [eax.copy()])),
                    Branch(Condition(OperationType.greater, [eax.copy(), ebx.copy()])),
                ],
            ),
            n1 := BasicBlock(
                1,
                instructions=[
                    Branch(
                        Condition(
                            OperationType.equal,
                            [ebx.copy(), BinaryOperation(OperationType.plus, [eax.copy(), Constant(1, Integer.int32_t())])],
                        )
                    )
                ],
            ),
            n2 := BasicBlock(
                2,
                instructions=[
                    Assignment(
                        ListOperation([]),
                        Call(FunctionSymbol("bar", 0), [RegisterPair(ebx.copy(), eax.copy(), Integer.int64_t())]),
                    )
                ],
            ),
            n3 := BasicBlock(
                3,
                instructions=[
                    Assignment(
                        ecx.copy(),
                        Call(FunctionSymbol("qtx", 0), [RegisterPair(ebx.copy(), eax.copy(), Integer.int64_t())]),
                    ),
                    Return([ecx.copy()]),
                ],
            ),
        ]
    )
    cfg.add_edges_from(
        [
            FalseCase(n0, n1),
            TrueCase(n0, n3),
            FalseCase(n1, n2),
            TrueCase(n1, n3),
            UnconditionalEdge(n2, n3),
        ]
    )
    RegisterPairHandling().run(MockTask(cfg))
    assert n0.instructions == [
        Assignment(eax.copy(), Constant(1, Integer.char())),
        Assignment(ebx.copy(), Call(FunctionSymbol("foo", 0), [eax.copy()])),
        Assignment(
            Variable("loc_0", Integer.int64_t(), 0),
            BinaryOperation(OperationType.plus, [eax.copy(), BinaryOperation(OperationType.left_shift, [ebx.copy(), Constant(32, Integer.int32_t())])]),
        ),
        Branch(Condition(OperationType.greater, [eax.copy(), ebx.copy()])),
    ]
