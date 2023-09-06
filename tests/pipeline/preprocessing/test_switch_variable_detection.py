from functools import partial

from decompiler.pipeline.preprocessing import SwitchVariableDetection
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, SwitchCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, IndirectBranch, Phi, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer

arg, eax, ebx = (lambda x, name=name: Variable(name, Integer.int32_t(), ssa_label=x) for name in ["arg", "eax", "ebx"])
const = lambda value: Constant(value, Integer.int32_t())


def function_symbol(name: str, value: int = 0x42) -> FunctionSymbol:
    return FunctionSymbol(name, value)


def imp_function_symbol(name: str, value: int = 0x42) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


class MockTask:
    def __init__(self, cfg: ControlFlowGraph):
        self.graph = cfg


class TestSwitchVariableDetection:
    """
    Test non-linear switch cases, with an expression based on an operation,
    with default case and varying optimization level.

    int test9(int week)
    {
        switch(week+1)
        {
            case 1:
                printf("Monday");
                break;
            case 12:
                printf("Tuesday");
                break;
            case 34:
                printf("Wednesday");
                break;
            case 40:
                printf("Thursday");
                break;
            case 500:
                printf("Friday");
                break;
            case 6:
                printf("Saturday");
                break;
            case 9:
                printf("Sunday");
                break;
            default:
                printf("Invalid input! Please enter week number between 1-7.");
        }

        return 0;
    }"""

    def test9_normal(self):
        """Test the relevant part of the example above with no explicitly stated optimization level (gcc)."""
        cfg = ControlFlowGraph()
        cfg.add_nodes_from(
            [
                start := BasicBlock(
                    0,
                    instructions=[
                        Assignment(eax(1), arg(0)),
                        Assignment(eax(2), BinaryOperation(OperationType.plus, [eax(1), const(1)])),
                        Branch(Condition(OperationType.greater, [eax(2), const(0x28)])),
                    ],
                ),
                second_branch := BasicBlock(1, instructions=[Branch(Condition(OperationType.less_or_equal, [eax(2), const(0)]))]),
                third_branch := BasicBlock(2, instructions=[Branch(Condition(OperationType.greater, [eax(2), Constant(0x28)]))]),
                switch_block := BasicBlock(
                    3,
                    instructions=[
                        Assignment(
                            eax(3),
                            UnaryOperation(
                                OperationType.dereference,
                                [
                                    BinaryOperation(
                                        OperationType.plus,
                                        [BinaryOperation(OperationType.left_shift, [eax(2), const(2)]), const(0x804A308)],
                                    ),
                                ],
                            ),
                        ),
                        switch := IndirectBranch(eax(3)),
                    ],
                ),
            ]
        )
        cfg.add_edges_from(
            [
                FalseCase(start, second_branch),
                FalseCase(second_branch, third_branch),
                FalseCase(third_branch, switch_block),
            ]
        )
        svd = SwitchVariableDetection()
        svd.run(MockTask(cfg))
        assert svd.find_switch_expression(switch) == eax(2)

    def test9_o3(self):
        """The same example as above in a more optimized version. Does not include a dedicated address calculation."""
        cfg = ControlFlowGraph()
        cfg.add_nodes_from(
            [
                start := BasicBlock(
                    0,
                    instructions=[
                        Assignment(eax(1), arg(0)),
                        Assignment(eax(2), BinaryOperation(OperationType.plus, [eax(1), const(1)])),
                        Branch(Condition(OperationType.greater, [eax(2), const(0x28)])),
                    ],
                ),
                second_branch := BasicBlock(1, instructions=[Branch(Condition(OperationType.less_or_equal, [eax(2), const(0)]))]),
                third_branch := BasicBlock(2, instructions=[Branch(Condition(OperationType.greater, [eax(2), Constant(0x28)]))]),
                switch_block := BasicBlock(
                    3,
                    instructions=[
                        switch := IndirectBranch(
                            UnaryOperation(
                                OperationType.dereference,
                                [
                                    BinaryOperation(
                                        OperationType.plus,
                                        [BinaryOperation(OperationType.left_shift, [eax(2), const(2)]), const(0x804A308)],
                                    ),
                                ],
                            )
                        ),
                    ],
                ),
            ]
        )
        cfg.add_edges_from(
            [
                FalseCase(start, second_branch),
                FalseCase(second_branch, third_branch),
                FalseCase(third_branch, switch_block),
            ]
        )
        svd = SwitchVariableDetection()
        svd.run(MockTask(cfg))
        assert svd.find_switch_expression(switch) == eax(2)

    def test_switch_variable_in_condition_assignment(self):
        """
        Check whether we track the switch expression correctly even if it was used in a dedicated condition statement."

        This test is based on the output of gcc 9.2.1 on ubuntu switch sample test_switch test8.
        +----------+     +------------------------------+
        |          |     |              0.              |
        |    2.    |     |                              |
        | foo(0x0) |     |     cond:0#0 = x u< 0x8      |
        |          | <-- |     if(cond:0#0 != 0x0)      |
        +----------+     +------------------------------+
          |                |
          |                |
          |                v
          |              +------------------------------+     +----------+
          |              |              1.              |     |          |
          |              |           y#0 = x            |     |    4.    |
          |              | y#1 = 0xfffff + (y#0 << 0x2) |     | bar(0x2) |
          |              |           jmp y#1            | --> |          |
          |              +------------------------------+     +----------+
          |                |                                    |
          |                |                                    |
          |                v                                    |
          |              +------------------------------+       |
          |              |              3.              |       |
          |              |           bar(0x1)           |       |
          |              +------------------------------+       |
          |                |                                    |
          |                |                                    |
          |                v                                    |
          |              +------------------------------+       |
          |              |             -1.              |       |
          +------------> |           return x           | <-----+
                         +------------------------------+
        """
        cfg = ControlFlowGraph()
        y0 = Variable("y", ssa_label=0)
        y1 = Variable("y", ssa_label=1)
        x = Variable("x")
        cfg.add_nodes_from(
            [
                start := BasicBlock(
                    0,
                    instructions=[
                        Assignment(Variable("cond:0", ssa_label=0), Condition(OperationType.less_us, [x, Constant(8)])),
                        Branch(Condition(OperationType.not_equal, [Variable("cond:0", ssa_label=0), Constant(0)])),
                    ],
                ),
                switch_block := BasicBlock(
                    1,
                    instructions=[
                        Assignment(y0, x),
                        Assignment(
                            y1,
                            BinaryOperation(
                                OperationType.plus,
                                [Constant(0xFFFFF), BinaryOperation(OperationType.left_shift, [y0, Constant(2)])],
                            ),
                        ),
                        switch := IndirectBranch(y1),
                    ],
                ),
                default := BasicBlock(2, instructions=[Assignment(ListOperation([]), Call(function_symbol("foo"), [Constant(0)]))]),
                end := BasicBlock(-1, instructions=[Return([x])]),
                case_1 := BasicBlock(
                    3,
                    instructions=[
                        Assignment(ListOperation([]), Call(function_symbol("bar"), [Constant(1)])),
                    ],
                ),
                case_2 := BasicBlock(
                    4,
                    instructions=[
                        Assignment(ListOperation([]), Call(function_symbol("bar"), [Constant(2)])),
                    ],
                ),
            ]
        )
        cfg.add_edges_from(
            [
                TrueCase(start, switch_block),
                FalseCase(start, default),
                SwitchCase(switch_block, case_1, [Constant(1)]),
                SwitchCase(switch_block, case_2, [Constant(2)]),
                UnconditionalEdge(default, end),
                UnconditionalEdge(case_1, end),
                UnconditionalEdge(case_2, end),
            ]
        )
        svd = SwitchVariableDetection()
        svd.run(MockTask(cfg))
        assert svd.find_switch_expression(switch) == y0


a0 = Variable("a", Integer.int32_t(), 0)
a1 = Variable("a", Integer.int32_t(), 1)
a2 = Variable("a", Integer.int32_t(), 2)
a3 = Variable("a", Integer.int32_t(), 3)
a4 = Variable("a", Integer.int32_t(), 4)

add = partial(BinaryOperation, OperationType.plus)
gt = partial(Condition, OperationType.greater)
shl = partial(BinaryOperation, OperationType.left_shift)
dereference = partial(UnaryOperation, OperationType.dereference)
call_assignment = partial(Assignment, ListOperation([]))

JT_OFFSET = 0xFFFFFF42


def test_dummy_heuristic_on_standard_jump_table_block():
    """
    Tests that the switch variable is discovered correctly in normal case, when the block with jump table offset calculation
    has only instructions relevant to the offset calculation
    """
    v0 = BasicBlock(0, instructions=[Assignment(a1, a0), Assignment(a2, Variable("x")), Branch(gt([a2, Constant(7)]))])
    v1 = BasicBlock(
        1,
        instructions=[
            Assignment(a3, shl([a2, Constant(2)])),
            Assignment(a4, dereference([add([add([a3, Constant(JT_OFFSET)]), Constant(JT_OFFSET)])])),
            IndirectBranch(a4),
        ],
    )
    v2 = BasicBlock(2, instructions=[call_assignment(Call(function_symbol("func1"), []))])
    v3 = BasicBlock(3, instructions=[call_assignment(Call(function_symbol("func2"), []))])
    v4 = BasicBlock(4, instructions=[call_assignment(Call(function_symbol("func3"), []))])
    v5 = BasicBlock(5, instructions=[call_assignment(Call(function_symbol("error"), []))])
    v6 = BasicBlock(6, instructions=[Return([Constant(0)])])
    cfg = ControlFlowGraph()
    cfg.add_edge(UnconditionalEdge(v0, v1))
    cfg.add_edge(UnconditionalEdge(v0, v5))
    cfg.add_edge(SwitchCase(v1, v2, []))
    cfg.add_edge(SwitchCase(v1, v3, []))
    cfg.add_edge(SwitchCase(v1, v4, []))
    cfg.add_edge(SwitchCase(v1, v5, []))
    cfg.add_edge(UnconditionalEdge(v5, v6))

    task = MockTask(cfg)
    SwitchVariableDetection().run(task)

    assert v1.instructions == [
        Assignment(a3, shl([a2, Constant(2)])),
        Assignment(a4, dereference([add([add([a3, Constant(JT_OFFSET)]), Constant(JT_OFFSET)])])),
        IndirectBranch(a2),
    ]

    assert v2.instructions == [call_assignment(Call(function_symbol("func1"), []))]
    assert v3.instructions == [call_assignment(Call(function_symbol("func2"), []))]
    assert v4.instructions == [call_assignment(Call(function_symbol("func3"), []))]
    assert v5.instructions == [call_assignment(Call(function_symbol("error"), []))]
    assert v6.instructions == [Return([Constant(0)])]


def test_constant_pointer():
    """
    +--------------+     +--------------------------++--------------+
    |      1.      |     |            0.            ||      7.      |
    |  return 0x4  | <-- | if((*(0x423658)) u> 0x4) || rbx#4 = 0xb  | ----------------------+
    +--------------+     +--------------------------++--------------+                       |
                           |                           ^                                    |
                           |                           |                                    |
                           v                           |                                    |
    +--------------+     +------------------------------------------+     +--------------+  |
    |      5.      |     |                    2.                    |     |      6.      |  |
    | rbx#2 = 0x14 |     |   rax#1 = (unsigned long) *(0x423658)    |     | rbx#3 = 0x17 |  |
    |              | <-- |     jmp *((rax#1 << 0x3) + 0x416268)     | --> |              |  |
    +--------------+     +------------------------------------------+     +--------------+  |
      |                    |                           |                    |               |
      |                    |                           |                    |               |
      |                    v                           v                    |               |
      |                  +--------------------------++--------------+       |               |
      |                  |            3.            ||      4.      |       |               |
      |                  |       rbx#0 = 0x2c       || rbx#1 = 0x28 |       |               |
      |                  +--------------------------++--------------+       |               |
      |                    |                           |                    |               |
      |                    |                           |                    |               |
      |                    v                           v                    |               |
      |                  +------------------------------------------+       |               |
      +----------------> |                    8.                    | <-----+               |
                         | rbx#5 = ϕ(rbx#0,rbx#1,rbx#2,rbx#3,rbx#4) |                       |
                         |               return rbx#5               |                       |
                         |                                          | <---------------------+
                         +------------------------------------------+
    """
    cfg = ControlFlowGraph()
    cont_pointer = UnaryOperation(
        OperationType.dereference,
        [Constant(4339288, Pointer(Integer(32, False), 64))],
        Integer(32, False),
        None,
        False,
    )
    rax = Variable("rax", Integer(64, False), 1, False, None)
    rbx = [Variable("rbx", Integer(64, False), i, False, None) for i in range(6)]
    switch_expression = UnaryOperation(
        OperationType.dereference,
        [
            BinaryOperation(
                OperationType.plus,
                [
                    BinaryOperation(
                        OperationType.left_shift,
                        [rax, Constant(3, Integer(8, True))],
                        Integer(64, False),
                    ),
                    Constant(4285032, Integer(64, True)),
                ],
                Integer(64, True),
            )
        ],
        Integer(64, True),
        None,
        False,
    )
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [Branch(Condition(OperationType.greater_us, [cont_pointer, Constant(4, Integer(32, True))], CustomType("bool", 1)))],
            ),
            BasicBlock(1, [Return([Constant(4, Integer(64, True))])]),
            BasicBlock(
                2,
                [
                    Assignment(rax, UnaryOperation(OperationType.cast, [cont_pointer], Integer(64, False), None, False)),
                    IndirectBranch(switch_expression),
                ],
            ),
            BasicBlock(3, [Assignment(rbx[0], Constant(44, Integer(64, True)))]),
            BasicBlock(4, [Assignment(rbx[1], Constant(40, Integer(64, True)))]),
            BasicBlock(
                5,
                [Assignment(rbx[2], Constant(20, Integer(64, True)))],
            ),
            BasicBlock(
                6,
                [Assignment(rbx[3], Constant(23, Integer(64, True)))],
            ),
            BasicBlock(
                7,
                [Assignment(rbx[4], Constant(11, Integer(64, True)))],
            ),
            BasicBlock(
                8,
                [
                    Phi(
                        rbx[5],
                        rbx[0:5],
                        {},
                    ),
                    Return([rbx[5]]),
                ],
            ),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            SwitchCase(vertices[2], vertices[3], [Constant(3)]),
            SwitchCase(vertices[2], vertices[4], [Constant(4)]),
            SwitchCase(vertices[2], vertices[5], [Constant(0)]),
            SwitchCase(vertices[2], vertices[6], [Constant(1)]),
            SwitchCase(vertices[2], vertices[7], [Constant(2)]),
            UnconditionalEdge(vertices[3], vertices[8]),
            UnconditionalEdge(vertices[4], vertices[8]),
            UnconditionalEdge(vertices[5], vertices[8]),
            UnconditionalEdge(vertices[6], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[8]),
        ]
    )
    task = MockTask(cfg)
    SwitchVariableDetection().run(task)
    assert vertices[2].instructions[-1] == IndirectBranch(rax)


def test_first_simple_assignment():
    """
    +--------------+     +--------------------------++--------------+
    |      1.      |     |            0.            ||      7.      |
    |  return 0x4  |     |         x = arg0         || rbx#4 = 0xb  |
    |              | <-- | if((*(0x423658)) u> 0x4) ||              | ----------------------+
    +--------------+     +--------------------------++--------------+                       |
                           |                           ^                                    |
                           |                           |                                    |
                           v                           |                                    |
    +--------------+     +------------------------------------------+     +--------------+  |
    |              |     |                    2.                    |     |              |  |
    |      5.      |     |                rax#1 = x                 |     |      6.      |  |
    | rbx#2 = 0x14 |     | rax#2 = (*(0xffffff42)) + (rax#1 << 0x3) |     | rbx#3 = 0x17 |  |
    |              |     |     rax#3 = rax#2 + (*(0xffffff42))      |     |              |  |
    |              | <-- |                jmp rax#3                 | --> |              |  |
    +--------------+     +------------------------------------------+     +--------------+  |
      |                    |                           |                    |               |
      |                    |                           |                    |               |
      |                    v                           v                    |               |
      |                  +--------------------------++--------------+       |               |
      |                  |            3.            ||      4.      |       |               |
      |                  |       rbx#0 = 0x2c       || rbx#1 = 0x28 |       |               |
      |                  +--------------------------++--------------+       |               |
      |                    |                           |                    |               |
      |                    |                           |                    |               |
      |                    v                           v                    |               |
      |                  +------------------------------------------+       |               |
      +----------------> |                    8.                    | <-----+               |
                         | rbx#5 = ϕ(rbx#0,rbx#1,rbx#2,rbx#3,rbx#4) |                       |
                         |               return rbx#5               |                       |
                         |                                          | <---------------------+
                         +------------------------------------------+
    """
    cfg = ControlFlowGraph()
    cont_pointer = UnaryOperation(
        OperationType.dereference,
        [Constant(4339288, Pointer(Integer(32, False), 64))],
        Integer(32, False),
        None,
        False,
    )
    rax1 = Variable("rax", Integer(64, False), 1, False, None)
    rax2 = Variable("rax", Integer(64, False), 2, False, None)
    rax3 = Variable("rax", Integer(64, False), 3, False, None)
    rbx = [Variable("rbx", Integer(64, False), i, False, None) for i in range(6)]
    def3 = Assignment(
        rax3,
        BinaryOperation(
            OperationType.plus,
            [
                rax2,
                UnaryOperation(OperationType.dereference, [Constant(JT_OFFSET)], Integer(64, True)),
            ],
            Integer(64, True),
        ),
    )
    def2 = Assignment(
        rax2,
        BinaryOperation(
            OperationType.plus,
            [
                UnaryOperation(OperationType.dereference, [Constant(JT_OFFSET)], Integer(64, True)),
                BinaryOperation(
                    OperationType.left_shift,
                    [rax1, Constant(3, Integer(8, True))],
                    Integer(64, False),
                ),
            ],
            Integer(64, True),
        ),
    )
    def1 = Assignment(rax1, Variable("x"))
    def0 = Assignment(Variable("x"), Variable("arg0"))

    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    def0,
                    Branch(Condition(OperationType.greater_us, [cont_pointer, Constant(4, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(1, [Return([Constant(4, Integer(64, True))])]),
            BasicBlock(
                2,
                [
                    def1,
                    def2,
                    def3,
                    switch := IndirectBranch(rax3),
                ],
            ),
            BasicBlock(3, [Assignment(rbx[0], Constant(44, Integer(64, True)))]),
            BasicBlock(4, [Assignment(rbx[1], Constant(40, Integer(64, True)))]),
            BasicBlock(
                5,
                [Assignment(rbx[2], Constant(20, Integer(64, True)))],
            ),
            BasicBlock(
                6,
                [Assignment(rbx[3], Constant(23, Integer(64, True)))],
            ),
            BasicBlock(
                7,
                [Assignment(rbx[4], Constant(11, Integer(64, True)))],
            ),
            BasicBlock(
                8,
                [
                    Phi(
                        rbx[5],
                        rbx[0:5],
                        {},
                    ),
                    Return([rbx[5]]),
                ],
            ),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(vertices[0], vertices[1]),
            FalseCase(vertices[0], vertices[2]),
            SwitchCase(vertices[2], vertices[3], [Constant(3)]),
            SwitchCase(vertices[2], vertices[4], [Constant(4)]),
            SwitchCase(vertices[2], vertices[5], [Constant(0)]),
            SwitchCase(vertices[2], vertices[6], [Constant(1)]),
            SwitchCase(vertices[2], vertices[7], [Constant(2)]),
            UnconditionalEdge(vertices[3], vertices[8]),
            UnconditionalEdge(vertices[4], vertices[8]),
            UnconditionalEdge(vertices[5], vertices[8]),
            UnconditionalEdge(vertices[6], vertices[8]),
            UnconditionalEdge(vertices[7], vertices[8]),
        ]
    )
    task = MockTask(cfg)
    svd = SwitchVariableDetection()
    svd.run(task)
    assert vertices[2].instructions[-1] == IndirectBranch(rax1)
    assert svd.find_switch_expression(switch) == rax1
