from decompiler.pipeline.dataflowanalysis import IdentityElimination
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Relation, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Call, Condition, ListOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import CustomType, Integer, Pointer, UnknownType
from decompiler.task import DecompilerTask


def imp_function_symbol(name: str, value=0x42) -> ImportedFunctionSymbol:
    return ImportedFunctionSymbol(name, value)


def function_symbol(name: str, value=0x42) -> FunctionSymbol:
    return FunctionSymbol(name, value)


def test_aliased_problems_1():
    """
    Need the check that the defined variable is not an aliased variable.
    +------------+
    |     0.     |
    | x#0 = y#3  |
    |  foo(x#0)  |
    | return x#0 |
    +------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("x", ssa_label=0, is_aliased=True), Variable("y", ssa_label=3)),
                Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("x", ssa_label=0, is_aliased=True)])),
                Return([Variable("x", ssa_label=0, is_aliased=True)]),
            ],
        )
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[Variable("y", ssa_label=3)]))
    assert node.instructions == [
        Assignment(Variable("x", ssa_label=0, is_aliased=True), Variable("y", ssa_label=3)),
        Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("x", ssa_label=0, is_aliased=True)])),
        Return([Variable("x", ssa_label=0, is_aliased=True)]),
    ]


def test_aliased_problems_2():
    """
    Need also aliased-variables in Phi-function values.
        +------------------+
        |        0.        |
        |  scanf(&(y#0))   |
        |    x#0 = y#0     |
        +------------------+
          |
          |
          v
        +------------------+
        |        1.        |
        | x#1 = ϕ(x#0,x#2) |
        |  y#1 = bar(x#1)  | ---+
        |    x#2 = y#1     |    |
        |  if(x#2 > 0x14)  | <--+
        +------------------+
          |
          |
          v
        +------------------+
        |        2.        |
        |    return x#2    |
        +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    x0.is_aliased = True
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(x0.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Assignment(y1.copy(), Call(function_symbol("bar"), [x1])),
                    Assignment(x2.copy(), y1.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(start, loop_body), TrueCase(loop_body, end), FalseCase(loop_body, loop_body)])
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
        Assignment(x0.copy(), y0.copy()),
    ]
    assert loop_body.instructions == [
        Phi(x1.copy(), [x0.copy(), y1.copy()]),
        Assignment(y1.copy(), Call(function_symbol("bar"), [x1])),
        Branch(Condition(OperationType.greater, [y1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([y1.copy()])]


def test_aliased_problems_3():
    """
    Need the check that the Phi-function does not depenend on only one aliased-variable.
    +------------------+
    |        0.        |
    |  scanf(&(y#0))   |
    |    x#0 = y#0     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | x#1 = ϕ(x#0,x#0) |
    |  y#1 = bar(x#1)  | ---+
    |    y#2 = y#1     |    |
    |  if(y#1 > 0x14)  | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    |    return y#2    |
    +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    x0.is_aliased = True
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(x0.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x0.copy()]),
                    Assignment(y1.copy(), Call(function_symbol("bar"), [x1])),
                    Assignment(y2.copy(), y1.copy()),
                    Branch(Condition(OperationType.greater, [y1.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([y2.copy()])]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(start, loop_body), TrueCase(loop_body, end), FalseCase(loop_body, loop_body)])
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
        Assignment(x0.copy(), y0.copy()),
    ]
    assert loop_body.instructions == [
        Phi(x1.copy(), [x0.copy(), x0.copy()]),
        Assignment(y1.copy(), Call(function_symbol("bar"), [x1])),
        Branch(Condition(OperationType.greater, [y1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([y1.copy()])]


def test_aliased_problems_4():
    """
    Check that a Phi-function that depends on an aliased and non-aliased variable,
    where the aliased-variables x#0 and y#0 can not be identified.
        +------------------+
        |        0.        |
        |  scanf(&(y#0))   |
        |    x#0 = y#0     |
        +------------------+
          |
          |
          v
        +------------------+
        |        1.        |
        | x#1 = ϕ(x#0,x#2) |
        |  y#1 = bar(x#1)  | ---+
        |    x#2 = y#1     |    |
        |  if(x#2 > 0x14)  | <--+
        +------------------+
          |
          |
          v
        +------------------+
        |        2.        |
        |    return x#2    |
        +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    x0.is_aliased = True
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    y0.is_aliased = True
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(x0.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Assignment(y1.copy(), Call(function_symbol("bar"), [x1])),
                    Assignment(x2.copy(), y1.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
        Assignment(x0.copy(), y0.copy()),
    ]
    assert loop_body.instructions == [
        Phi(x1.copy(), [x0.copy(), y1.copy()]),
        Assignment(y1.copy(), Call(FunctionSymbol("bar", 0x42), [x1])),
        Branch(Condition(OperationType.greater, [y1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([y1.copy()])]


def test_aliased_problems_5():
    """
    Check that a Phi-function that depends on an aliased and non-aliased variable, where we would identify all variables in the Phi-function
    if they are all aliased or non-aliased.
        +------------------+
        |        0.        |
        |  scanf(&(y#0))   |
        |    x#0 = y#0     |
        +------------------+
          |
          |
          v
        +------------------+
        |        1.        |
        | x#1 = ϕ(x#0,x#2) |
        |    y#1 = x#1     | ---+
        |    x#2 = y#1     |    |
        |  if(x#2 > 0x14)  | <--+
        +------------------+
          |
          |
          v
        +------------------+
        |        2.        |
        |    return x#2    |
        +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    x0.is_aliased = True
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    y0.is_aliased = True
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(x0.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Assignment(y1.copy(), x1.copy()),
                    Assignment(x2.copy(), y1.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(start, loop_body), TrueCase(loop_body, end), FalseCase(loop_body, loop_body)])
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
        Assignment(x0.copy(), y0.copy()),
    ]
    assert loop_body.instructions == [
        Phi(x1.copy(), [x0.copy(), x1.copy()]),
        Branch(Condition(OperationType.greater, [x1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([x1.copy()])]


def test_aliased_problems_6():
    """
    Check that a Phi-function that depends on an aliased and non-aliased variable, where both arguments are identities
    are renamed correctly.
        +------------------+
        |        0.        |
        |  scanf(&(y#0))   |
        |    y#1 = y#0     |
        +------------------+
          |
          |
          v
        +------------------+
        |        1.        |
        | x#1 = ϕ(y#1,x#2) |
        |  x#3 = bar(x#1)  | ---+
        |    x#2 = x#3     |    |
        |  if(x#2 > 0x14)  | <--+
        +------------------+
          |
          |
          v
        +------------------+
        |        2.        |
        |    return x#2    |
        +------------------+
    """
    x0, x1, x2, x3 = [Variable("x", Integer.int32_t(), i) for i in range(4)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i, is_aliased=True) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(y1.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [y1.copy(), x2.copy()]),
                    Assignment(x3.copy(), Call(FunctionSymbol("bar", 0x42), [x1])),
                    Assignment(x2.copy(), x3.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(start, loop_body), TrueCase(loop_body, end), FalseCase(loop_body, loop_body)])
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])]))
    ]
    assert loop_body.instructions == [
        Phi(x1.copy(), [y0.copy(), x3.copy()]),
        Assignment(x3.copy(), Call(FunctionSymbol("bar", 0x42), [x1])),
        Branch(Condition(OperationType.greater, [x3.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([x3.copy()])]


def test_aliased_problems_7():
    """
    Check that a Phi-function that depends on an aliased and non-aliased variable, where we would identify all variables in the Phi-function
    if they are all aliased or non-aliased.
        +------------------+
        |        0.        |
        |  scanf(&(y#0))   |
        |    y#1 = y#0     |
        +------------------+
          |
          |
          v
        +------------------+
        |        1.        |
        | x#1 = ϕ(y#1,x#2) |
        |    x#3 = x#1     | ---+
        |    x#2 = x#3     |    |
        |  if(x#2 > 0x14)  | <--+
        +------------------+
          |
          |
          v
        +------------------+
        |        2.        |
        |    return x#2    |
        +------------------+
    """
    x0, x1, x2, x3 = [Variable("x", Integer.int32_t(), i) for i in range(4)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i, is_aliased=True) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(y1.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [y1.copy(), x2.copy()]),
                    Assignment(x3.copy(), x1.copy()),
                    Assignment(x2.copy(), x3.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(start, loop_body), TrueCase(loop_body, end), FalseCase(loop_body, loop_body)])
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])]))
    ]
    assert loop_body.instructions == [
        Phi(x1.copy(), [y0.copy(), x1.copy()]),
        Branch(Condition(OperationType.greater, [x1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([x1.copy()])]


def test_aliased_problems_8():
    """
    Check that a Phi-function that depends on an aliased and constant is not merged.
        +------------------+
        |        0.        |
        |  scanf(&(y#0))   |
        |    y#1 = y#0     |
        +------------------+
          |
          |
          v
        +------------------+
        |        1.        |
        | y#2 = ϕ(0x1,y#2) |
        |    x#3 = x#1     | ---+
        |    x#2 = x#3     |    |
        |  if(x#2 > 0x14)  | <--+
        +------------------+
          |
          |
          v
        +------------------+
        |        2.        |
        |    return x#2    |
        +------------------+
    """
    x0, x1, x2, x3 = [Variable("x", Integer.int32_t(), i) for i in range(4)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i, is_aliased=True) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(y1.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(y2.copy(), [Constant(1), y2.copy()]),
                    Assignment(x3.copy(), x1.copy()),
                    Assignment(x2.copy(), x3.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])]))
    ]
    assert loop_body.instructions == [
        Phi(y2.copy(), [Constant(1), y2.copy()]),
        Branch(Condition(OperationType.greater, [x1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([x1.copy()])]


def test_aliased_problems_9():
    """
    Check that a Phi-function that depends on same aliased variables, can be identified.
        +------------------+
        |        0.        |
        |  scanf(&(y#0))   |
        |    y#1 = y#0     |
        +------------------+
          |
          |
          v
        +------------------+
        |        1.        |
        | y#2 = ϕ(y#1,y#2) |
        |    x#3 = x#1     | ---+
        |    x#2 = x#3     |    |
        |  if(x#2 > 0x14)  | <--+
        +------------------+
          |
          |
          v
        +------------------+
        |        2.        |
        |    return x#2    |
        +------------------+
    """
    x0, x1, x2, x3 = [Variable("x", Integer.int32_t(), i) for i in range(4)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i, is_aliased=True) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(y1.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(y2.copy(), [y1.copy(), y2.copy()]),
                    Assignment(x3.copy(), x1.copy()),
                    Assignment(x2.copy(), x3.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])]))
    ]
    assert loop_body.instructions == [
        Branch(Condition(OperationType.greater, [x1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([x1.copy()])]


def test_aliased_problems_10():
    """
    Check that a Phi-function that depends on aliased variables but with different names, so it can not be identified.
    +------------------+
    |        0.        |
    |  scanf(&(y#0))   |
    |    y#1 = y#0     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | y#2 = ϕ(y#1,x#0) |
    |  scanf(&(x#0))   | ---+
    |    x#2 = x#1     |    |
    |  if(x#2 > 0x14)  | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    |    return x#2    |
    +------------------+
    """
    x0, x1, x2, x3 = [Variable("x", Integer.int32_t(), i) for i in range(4)]
    x0.is_aliased = True
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i, is_aliased=True) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])])),
                    Assignment(y1.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(y2.copy(), [y1.copy(), x0.copy()]),
                    Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [x0.copy()])])),
                    Assignment(x2.copy(), x1.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [y0.copy()])]))
    ]
    assert loop_body.instructions == [
        Phi(y2.copy(), [y0.copy(), x0.copy()]),
        Assignment(ListOperation([]), Call(imp_function_symbol("scanf"), [UnaryOperation(OperationType.address, [x0.copy()])])),
        Branch(Condition(OperationType.greater, [x1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([x1.copy()])]


def test_aliased_problems_11():
    """
     Check that a Phi-function that is a leaf in the dependency graph is marked as leaf.
    +------------------+
     |        0.        |
     | x#0 = 0xa        |
     +------------------+
       |
       |
       v
     +------------------+
     |        1.        |
     | x#1 = ϕ(x#0,x#2) |
     | x#2 = ϕ(x#0,y#2) |
     | z#0 = 0x5        | ---+
     | y#2 = z#0        |    |
     | if(x#1 > y#1)    | <--+
     +------------------+
       |
       |
       v
     +------------------+
     |        2.        |
     | return y#1 - x#1 |
     +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i, is_aliased=True) for i in range(3)]
    y1, y2 = [Variable("y", Integer.int32_t(), i + 1) for i in range(2)]
    z0 = Variable("z", Integer.int32_t(), 0)
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[Assignment(x0.copy(), Constant(10, Integer.int32_t()))],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Phi(x2.copy(), [x0.copy(), y2.copy()]),
                    Assignment(z0.copy(), Constant(5, Integer.int32_t())),
                    Assignment(y2.copy(), z0.copy()),
                    Branch(Condition(OperationType.greater, [x1.copy(), y1.copy()])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([BinaryOperation(OperationType.minus, [y1.copy(), x1.copy()])])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [Assignment(x0.copy(), Constant(10, Integer.int32_t()))]
    assert loop_body.instructions == [
        Phi(x1.copy(), [x0.copy(), x2.copy()]),
        Phi(x2.copy(), [x0.copy(), z0.copy()]),
        Assignment(z0.copy(), Constant(5, Integer.int32_t())),
        Branch(Condition(OperationType.greater, [x1.copy(), y1.copy()])),
    ]
    assert end.instructions == [Return([BinaryOperation(OperationType.minus, [y1.copy(), x1.copy()])])]


def test_paper_example_figure_2a():
    """
                            +------------------+
                            |        0.        |
                            | x#0 = bar()      |
                            | z#0 = 0xa        |
                            | y#0 = x#0        |
                            +------------------+
                              |
                              |
                              v
    +-----------------+     +------------------+
    |       3.        |     |        1.        |
    | y#1 = y#0 + z#1 |     | x#1 = ϕ(x#0,x#2) |
    | return          |     | z#1 = ϕ(z#0,z#2) |
    |                 | <-- | if(x#1 < z#1)    | <+
    +-----------------+     +------------------+  |
                              |                   |
                              |                   |
                              v                   |
                            +------------------+  |
                            |        2.        |  |
                            | z#2 = qux()      |  |
                            | x#2 = y#0        | -+
                            +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    y0, y1 = [Variable("y", Integer.int32_t(), i) for i in range(2)]
    bar, qux = [Call(FunctionSymbol(name, 0x42), []) for name in ["bar", "qux"]]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(x0.copy(), bar.copy()),
                    Assignment(z0.copy(), Constant(10, Integer.int32_t())),
                    Assignment(y0.copy(), x0.copy()),
                ],
            ),
            loop_condition := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Phi(z1.copy(), [z0.copy(), z2.copy()]),
                    Branch(Condition(OperationType.less, [x1.copy(), z1.copy()])),
                ],
            ),
            loop_body := BasicBlock(2, instructions=[Assignment(z2.copy(), qux.copy()), Assignment(x2.copy(), y0.copy())]),
            end := BasicBlock(
                3, instructions=[Assignment(y1.copy(), BinaryOperation(OperationType.plus, [y0.copy(), z1.copy()])), Return([y1.copy()])]
            ),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_condition),
            TrueCase(loop_condition, loop_body),
            FalseCase(loop_condition, end),
            UnconditionalEdge(loop_body, loop_condition),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [Assignment(x0.copy(), bar.copy()), Assignment(z0.copy(), Constant(10, Integer.int32_t()))]
    assert loop_condition.instructions == [
        Phi(z1.copy(), [z0.copy(), z2.copy()]),
        Branch(Condition(OperationType.less, [x0.copy(), z1.copy()])),
    ]
    assert loop_body.instructions == [Assignment(z2.copy(), qux.copy())]
    assert end.instructions == [Assignment(y1.copy(), BinaryOperation(OperationType.plus, [x0.copy(), z1.copy()])), Return([y1.copy()])]


def test_eva_counterexample():
    """
    +------------------+
    |        0.        |
    | x#0 = 0xa        |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | x#1 = ϕ(x#0,x#2) |
    | y#1 = ϕ(x#0,y#2) |
    | z#0 = 0x5        |
    | x#2 = z#0        | ---+
    | y#2 = z#0        |    |
    | if(x#1 > y#1)    | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    | return y#1 - x#1 |
    +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    y1, y2 = [Variable("y", Integer.int32_t(), i + 1) for i in range(2)]
    z0 = Variable("z", Integer.int32_t(), 0)
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[Assignment(x0.copy(), Constant(10, Integer.int32_t()))],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Phi(y1.copy(), [x0.copy(), y2.copy()]),
                    Assignment(z0.copy(), Constant(5, Integer.int32_t())),
                    Assignment(x2.copy(), z0.copy()),
                    Assignment(y2.copy(), z0.copy()),
                    Branch(Condition(OperationType.greater, [x1.copy(), y1.copy()])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([BinaryOperation(OperationType.minus, [y1.copy(), x1.copy()])])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert loop_body.instructions == [
        Phi(x1.copy(), [x0.copy(), z0.copy()]),
        Phi(y1.copy(), [x0.copy(), z0.copy()]),
        Assignment(z0.copy(), Constant(5, Integer.int32_t())),
        Branch(Condition(OperationType.greater, [x1.copy(), y1.copy()])),
    ]


def test_counterexample_2():
    """
    +------------------+
    |        0.        |
    |    y#0 = 0x0     |
    |    x#0 = y#0     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | x#1 = ϕ(x#0,x#2) |
    |  y#1 = bar(x#1)  | ---+
    |    x#2 = y#1     |    |
    |  if(x#2 > 0x14)  | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    |    return x#2    |
    +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(y0.copy(), Constant(0, Integer.int32_t())),
                    Assignment(x0.copy(), y0.copy()),
                ],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Assignment(y1.copy(), Call(FunctionSymbol("bar", 0x42), [x1])),
                    Assignment(x2.copy(), y1.copy()),
                    Branch(Condition(OperationType.greater, [x2.copy(), Constant(20)])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [Assignment(y0.copy(), Constant(0, Integer.int32_t()))]
    assert loop_body.instructions == [
        Phi(x1.copy(), [y0.copy(), y1.copy()]),
        Assignment(y1.copy(), Call(FunctionSymbol("bar", 0x42), [x1])),
        Branch(Condition(OperationType.greater, [y1.copy(), Constant(20)])),
    ]
    assert end.instructions == [Return([y1.copy()])]


def test_counterexample_3():
    """
    +------------------+
    |        0.        |
    |    x#0 = z#0     |
    |    y#0 = z#0     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | x#2 = ϕ(x#0,y#2) |
    | y#2 = ϕ(y#0,x#2) |
    | u#1 = ϕ(0x0,u#2) | ---+
    | u#2 = u#1 + 0x1  |    |
    |  if(u#2 > 0xa)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    |    return x#2    |
    +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[Assignment(x0.copy(), z0.copy()), Assignment(y0.copy(), z0.copy())],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x2.copy(), [x0.copy(), y2.copy()]),
                    Phi(y2.copy(), [y0.copy(), x2.copy()]),
                    Phi(u1.copy(), [Constant(0, Integer.int32_t()), u2.copy()]),
                    Assignment(u2.copy(), BinaryOperation(OperationType.plus, [u1.copy(), Constant(1, Integer.int32_t())])),
                    Branch(Condition(OperationType.greater, [u2.copy(), Constant(10, Integer.int32_t())])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == []
    assert loop_body.instructions == [
        Phi(u1.copy(), [Constant(0, Integer.int32_t()), u2.copy()]),
        Assignment(u2.copy(), BinaryOperation(OperationType.plus, [u1.copy(), Constant(1, Integer.int32_t())])),
        Branch(Condition(OperationType.greater, [u2.copy(), Constant(10, Integer.int32_t())])),
    ]
    assert end.instructions == [Return([z0.copy()])]


def test_counterexample_4():
    """
    +------------------+
    |        0.        |
    |    x#0 = z#0     |
    |    y#0 = z#0     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | x#2 = ϕ(x#0,y#2) |
    | y#2 = ϕ(y#0,y#1) |
    | u#1 = ϕ(0x0,u#2) |
    | u#2 = u#1 + 0x1  | ---+
    |   y#1 = bar()    |    |
    |  if(u#2 > 0xa)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    |    return x#2    |
    +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[Assignment(x0.copy(), z0.copy()), Assignment(y0.copy(), z0.copy())],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x2.copy(), [x0.copy(), y2.copy()]),
                    Phi(y2.copy(), [y0.copy(), y1.copy()]),
                    Phi(u1.copy(), [Constant(0, Integer.int32_t()), u2.copy()]),
                    Assignment(u2.copy(), BinaryOperation(OperationType.plus, [u1.copy(), Constant(1, Integer.int32_t())])),
                    Assignment(y1.copy(), Call(FunctionSymbol("bar", 0x42), [])),
                    Branch(Condition(OperationType.greater, [u2.copy(), Constant(10, Integer.int32_t())])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([x2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[z0.copy()]))
    assert start.instructions == []
    assert loop_body.instructions == [
        Phi(x2.copy(), [z0.copy(), y2.copy()]),
        Phi(y2.copy(), [z0.copy(), y1.copy()]),
        Phi(u1.copy(), [Constant(0, Integer.int32_t()), u2.copy()]),
        Assignment(u2.copy(), BinaryOperation(OperationType.plus, [u1.copy(), Constant(1, Integer.int32_t())])),
        Assignment(y1.copy(), Call(FunctionSymbol("bar", 0x42), [])),
        Branch(Condition(OperationType.greater, [u2.copy(), Constant(10, Integer.int32_t())])),
    ]
    assert end.instructions == [Return([x2.copy()])]


def test_counterexample_5():
    """
    +-----------+     +----------------------+
    |    2.     |     |          0.          |
    | y#1 = 0xa | <-- |                      |
    +-----------+     +----------------------+
      |                 |
      |                 |
      |                 v
      |               +----------------------+
      |               |          1.          |
      |               |      x#0 = z#0       |
      |               |      y#0 = z#0       |
      |               +----------------------+
      |                 |
      |                 |
      |                 v
      |               +----------------------+
      |               |          3.          |
      |               | x#2 = ϕ(x#0,y#1,y#2) | ---+
      |               | y#2 = ϕ(y#0,y#1,y#1) |    |
      +-------------> |    if(x#2 > y#2)     | <--+
                      +----------------------+
                        |
                        |
                        v
                      +----------------------+
                      |          4.          |
                      +----------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(0, instructions=[]),
            start_1 := BasicBlock(
                1,
                instructions=[Assignment(x0.copy(), z0.copy()), Assignment(y0.copy(), z0.copy())],
            ),
            start_2 := BasicBlock(2, instructions=[Assignment(y1.copy(), Constant(10, Integer.int32_t()))]),
            loop_body := BasicBlock(
                3,
                instructions=[
                    Phi(x2.copy(), [x0.copy(), y1.copy(), y2.copy()]),
                    Phi(y2.copy(), [y0.copy(), y1.copy(), y1.copy()]),
                    Branch(Condition(OperationType.greater, [x2.copy(), y2.copy()])),
                ],
            ),
            end := BasicBlock(4, instructions=[]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(head, start_1),
            FalseCase(head, start_2),
            UnconditionalEdge(start_1, loop_body),
            UnconditionalEdge(start_2, loop_body),
            FalseCase(loop_body, loop_body),
            TrueCase(loop_body, end),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[z0.copy()]))
    assert head.instructions == []
    assert start_1.instructions == []
    assert start_2.instructions == [Assignment(y1.copy(), Constant(10, Integer.int32_t()))]
    assert loop_body.instructions == [
        Phi(x2.copy(), [z0.copy(), y1.copy(), y2.copy()]),
        Phi(y2.copy(), [z0.copy(), y1.copy(), y1.copy()]),
        Branch(Condition(OperationType.greater, [x2.copy(), y2.copy()])),
    ]
    assert end.instructions == []


def test_counterexample_6():
    """
                            +------------------+
                            |        0.        |
                            | y#1 = y#0 * 0x4  |
                            |    x#0 = y#1     |
                            |   u#0 = bar()    |
                            |    z#0 = u#0     |
                            +------------------+
                              |
                              |
                              v
    +-----------------+     +------------------+
    |       3.        |     |        1.        |
    | z#1 = x#1 + u#1 |     | u#1 = ϕ(u#0,u#2) |
    |   return z#1    |     | x#1 = ϕ(x#0,x#2) |
    |                 | <-- |  if(u#1 != x#1)  | <+
    +-----------------+     +------------------+  |
                              |                   |
                              |                   |
                              v                   |
                            +------------------+  |
                            |        2.        |  |
                            |    u#2 = z#0     |  |
                            |    x#2 = u#0     | -+
                            +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[
                    Assignment(y1.copy(), BinaryOperation(OperationType.multiply, [y0.copy(), Constant(4, Integer.int32_t())])),
                    Assignment(x0.copy(), y1.copy()),
                    Assignment(u0.copy(), Call(FunctionSymbol("bar", 0x42), [])),
                    Assignment(z0.copy(), u0.copy()),
                ],
            ),
            loop_start := BasicBlock(
                1,
                instructions=[
                    Phi(u1.copy(), [u0.copy(), u2.copy()]),
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Branch(Condition(OperationType.not_equal, [u1.copy(), x1.copy()])),
                ],
            ),
            loop_body := BasicBlock(
                2,
                instructions=[
                    Assignment(u2.copy(), z0.copy()),
                    Assignment(x2.copy(), u0.copy()),
                ],
            ),
            end := BasicBlock(
                3, instructions=[Assignment(z1.copy(), BinaryOperation(OperationType.plus, [x1.copy(), u1.copy()])), Return([z1.copy()])]
            ),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_start),
            TrueCase(loop_start, loop_body),
            UnconditionalEdge(loop_body, loop_start),
            FalseCase(loop_start, end),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert start.instructions == [
        Assignment(y1.copy(), BinaryOperation(OperationType.multiply, [y0.copy(), Constant(4, Integer.int32_t())])),
        Assignment(u0.copy(), Call(FunctionSymbol("bar", 0x42), [])),
    ]
    assert loop_start.instructions == [
        Phi(x1.copy(), [y1.copy(), u0.copy()]),
        Branch(Condition(OperationType.not_equal, [u0.copy(), x1.copy()])),
    ]
    assert loop_body.instructions == []
    assert end.instructions == [Assignment(z1.copy(), BinaryOperation(OperationType.plus, [x1.copy(), u0.copy()])), Return([z1.copy()])]


def test_counterexample_7():
    """
         +----------------------+
         |          0.          |
         |      y#0 = u#0       |
         |      z#0 = u#0       |
         +----------------------+
           |
           |
           v
         +----------------------+
         |          1.          |
    +--- | y#1 = ϕ(y#0,z#1,y#2) |
    |    | z#1 = ϕ(z#0,y#1,y#2) |
    +--> |    if(y#1 > z#1)     | <+
         +----------------------+  |
           |                       |
           |                       |
           v                       |
         +----------------------+  |
         |          2.          |  |
         |      y#2 = z#1       |  |
         |    if(y#2 > y#1)     | -+
         +----------------------+
           |
           |
           v
         +----------------------+
         |          3.          |
         +----------------------+
    """
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(0, instructions=[Assignment(y0.copy(), u0.copy()), Assignment(z0.copy(), u0.copy())]),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(y1.copy(), [y0.copy(), z1.copy(), y2.copy()]),
                    Phi(z1.copy(), [z0.copy(), y1.copy(), y2.copy()]),
                    Branch(Condition(OperationType.greater, [y1.copy(), z1.copy()])),
                ],
            ),
            loop_body2 := BasicBlock(
                2, instructions=[Assignment(y2.copy(), z1.copy()), Branch(Condition(OperationType.greater, [y2.copy(), y1.copy()]))]
            ),
            end := BasicBlock(3, instructions=[]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(head, loop_body),
            FalseCase(loop_body, loop_body),
            TrueCase(loop_body, loop_body2),
            TrueCase(loop_body2, loop_body),
            FalseCase(loop_body2, end),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert head.instructions == end.instructions == []
    assert loop_body.instructions == loop_body2.instructions == [Branch(Condition(OperationType.greater, [u0.copy(), u0.copy()]))]


def test_counterexample_8():
    """
         +----------------------+
         |          0.          |
         |      y#0 = u#0       |
         |      z#0 = u#0       |
         +----------------------+
           |
           |
           v
         +----------------------+
         |          1.          |
    +--- | y#1 = ϕ(y#0,z#1,y#2) |
    |    | z#1 = ϕ(z#0,y#1,y#2) |
    +--> |    if(y#1 > z#1)     | <+
         +----------------------+  |
           |                       |
           |                       |
           v                       |
         +----------------------+  |
         |          2.          |  |
         |      y#2 = 0x3       |  |
         |    if(y#2 > y#1)     | -+
         +----------------------+
           |
           |
           v
         +----------------------+
         |          3.          |
         +----------------------+
    """
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(0, instructions=[Assignment(y0.copy(), u0.copy()), Assignment(z0.copy(), u0.copy())]),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(y1.copy(), [y0.copy(), z1.copy(), y2.copy()]),
                    Phi(z1.copy(), [z0.copy(), y1.copy(), y2.copy()]),
                    Branch(Condition(OperationType.greater, [y1.copy(), z1.copy()])),
                ],
            ),
            loop_body2 := BasicBlock(
                2,
                instructions=[
                    Assignment(y2.copy(), Constant(0x3, Integer.int32_t())),
                    Branch(Condition(OperationType.greater, [y2.copy(), y1.copy()])),
                ],
            ),
            end := BasicBlock(3, instructions=[]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(head, loop_body),
            FalseCase(loop_body, loop_body),
            TrueCase(loop_body, loop_body2),
            TrueCase(loop_body2, loop_body),
            FalseCase(loop_body2, end),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[u0.copy()]))
    assert head.instructions == end.instructions == []
    assert loop_body.instructions == [
        Phi(y1.copy(), [u0.copy(), z1.copy(), y2.copy()]),
        Phi(z1.copy(), [u0.copy(), y1.copy(), y2.copy()]),
        Branch(Condition(OperationType.greater, [y1.copy(), z1.copy()])),
    ]
    assert loop_body2.instructions == [
        Assignment(y2.copy(), Constant(3, Integer.int32_t())),
        Branch(Condition(OperationType.greater, [y2.copy(), y1.copy()])),
    ]


def test_counterexample_9():
    """
    +------------------+
    |        0.        |
    |    y#0 = u#0     |
    |    z#0 = u#0     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | y#1 = ϕ(y#0,y#2) |
    | z#1 = ϕ(z#0,y#2) | ---+
    |    y#2 = 0x2     |    |
    |  if(y#1 > z#1)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        3.        |
    +------------------+
    """
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(0, instructions=[Assignment(y0.copy(), u0.copy()), Assignment(z0.copy(), u0.copy())]),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(y1.copy(), [y0.copy(), y2.copy()]),
                    Phi(z1.copy(), [z0.copy(), y2.copy()]),
                    Assignment(y2.copy(), Constant(2, Integer.int32_t())),
                    Branch(Condition(OperationType.greater, [y1.copy(), z1.copy()])),
                ],
            ),
            end := BasicBlock(3, instructions=[]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(head, loop_body), FalseCase(loop_body, loop_body), TrueCase(loop_body, end)])
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[Variable("u", Integer.int32_t())]))
    assert head.instructions == end.instructions == []
    assert loop_body.instructions == [
        Phi(y1.copy(), [u0.copy(), y2.copy()]),
        Phi(z1.copy(), [u0.copy(), y2.copy()]),
        Assignment(y2.copy(), Constant(2, Integer.int32_t())),
        Branch(Condition(OperationType.greater, [y1.copy(), z1.copy()])),
    ]


def test_counterexample_10():
    """
         +----------------------+
         |          0.          |
         |      y#2 = u#0       |
         |      z#0 = u#0       |
         +----------------------+
           |
           |
           v
         +----------------------+
         |          1.          |
    +--- | y#3 = ϕ(z#1,y#2,y#5) |
    |    | z#1 = ϕ(z#0,y#3,y#5) |
    +--> |    if(y#3 > z#1)     | <+
         +----------------------+  |
           |                       |
           |                       |
           v                       |
         +----------------------+  |
         |          2.          |  |
         |      y#4 = 0x3       |  |
         |      y#5 = y#4       |  |
         |    if(y#4 > y#3)     | -+
         +----------------------+
           |
           |
           v
         +----------------------+
         |          3.          |
         +----------------------+
    """
    y2, y3, y4, y5 = [Variable("y", Integer.int32_t(), i) for i in range(2, 6)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(0, instructions=[Assignment(y2.copy(), u0.copy()), Assignment(z0.copy(), u0.copy())]),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(y3.copy(), [z1.copy(), y2.copy(), y5.copy()]),
                    Phi(z1.copy(), [z0.copy(), y3.copy(), y5.copy()]),
                    Branch(Condition(OperationType.greater, [y3.copy(), z1.copy()])),
                ],
            ),
            loop_body2 := BasicBlock(
                2,
                instructions=[
                    Assignment(y4.copy(), Constant(0x3, Integer.int32_t())),
                    Assignment(y5.copy(), y4.copy()),
                    Branch(Condition(OperationType.greater, [y4.copy(), y3.copy()])),
                ],
            ),
            end := BasicBlock(3, instructions=[]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(head, loop_body),
            FalseCase(loop_body, loop_body),
            TrueCase(loop_body, loop_body2),
            TrueCase(loop_body2, loop_body),
            FalseCase(loop_body2, end),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[Variable("u", Integer.int32_t())]))
    assert head.instructions == end.instructions == []
    assert loop_body.instructions == [
        Phi(y3.copy(), [z1.copy(), u0.copy(), y4.copy()]),
        Phi(z1.copy(), [u0.copy(), y3.copy(), y4.copy()]),
        Branch(Condition(OperationType.greater, [y3.copy(), z1.copy()])),
    ]
    assert loop_body2.instructions == [
        Assignment(y4.copy(), Constant(0x3, Integer.int32_t())),
        Branch(Condition(OperationType.greater, [y4.copy(), y3.copy()])),
    ]


def test_counterexample_11():
    """
    +------------------+
    |        0.        |
    |    x#0 = u#0     |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | x#1 = ϕ(x#0,x#2) |
    | z#1 = ϕ(u#0,z#2) |
    | z#2 = u#0 + 0x1  | ---+
    |    x#2 = x#0     |    |
    |  if(z#1 > 0xa)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    | y#1 = ϕ(z#1,y#2) | ---+
    |    y#2 = z#1     |    |
    |  if(y#1 > 0xa)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        3.        |
    |    return y#1    |
    +------------------+
    """
    x0, x1, x2 = [Variable("x", Integer.int32_t(), i) for i in range(3)]
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[Assignment(x0.copy(), u0.copy())],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(x1.copy(), [x0.copy(), x2.copy()]),
                    Phi(z1.copy(), [u0.copy(), z2.copy()]),
                    Assignment(z2.copy(), BinaryOperation(OperationType.plus, [u0.copy(), Constant(1, Integer.int32_t())])),
                    Assignment(x2.copy(), x0.copy()),
                    Branch(Condition(OperationType.greater, [z1.copy(), Constant(10, Integer.int32_t())])),
                ],
            ),
            loop_body_2 := BasicBlock(
                2,
                instructions=[
                    Phi(y1.copy(), [z1.copy(), y2.copy()]),
                    Assignment(y2.copy(), z1.copy()),
                    Branch(Condition(OperationType.greater, [y1.copy(), Constant(10, Integer.int32_t())])),
                ],
            ),
            end := BasicBlock(3, instructions=[Return([y1.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, loop_body_2),
            FalseCase(loop_body, loop_body),
            TrueCase(loop_body_2, end),
            FalseCase(loop_body_2, loop_body_2),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[u0.copy()]))
    assert start.instructions == []
    assert loop_body.instructions == [
        Phi(z1.copy(), [u0.copy(), z2.copy()]),
        Assignment(z2.copy(), BinaryOperation(OperationType.plus, [u0.copy(), Constant(1, Integer.int32_t())])),
        Branch(Condition(OperationType.greater, [z1.copy(), Constant(10, Integer.int32_t())])),
    ]
    assert loop_body_2.instructions == [
        Branch(Condition(OperationType.greater, [z1.copy(), Constant(10, Integer.int32_t())])),
    ]
    assert end.instructions == [Return([z1.copy()])]


def test_counterexample_12():
    """
    +------------------+
    |        0.        |
    | z#0 = u#0 + 0x1  |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | z#1 = ϕ(z#0,z#2) | ---+
    | z#2 = z#1 + 0x1  |    |
    |  if(z#1 > 0xa)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    | u#1 = ϕ(z#1,y#1) | ---+
    | y#1 = ϕ(z#1,u#1) |    |
    |  if(y#1 > 0xa)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        3.        |
    |    return u#1    |
    +------------------+
    """
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[Assignment(z0.copy(), BinaryOperation(OperationType.plus, [u0.copy(), Constant(1, Integer.int32_t())]))],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(z1.copy(), [z0.copy(), z2.copy()]),
                    Assignment(z2.copy(), BinaryOperation(OperationType.plus, [z1.copy(), Constant(1, Integer.int32_t())])),
                    Branch(Condition(OperationType.greater, [z1.copy(), Constant(10, Integer.int32_t())])),
                ],
            ),
            loop_body_2 := BasicBlock(
                2,
                instructions=[
                    Phi(u1.copy(), [z1.copy(), y1.copy()]),
                    Phi(y1.copy(), [z1.copy(), u1.copy()]),
                    Branch(Condition(OperationType.greater, [y1.copy(), Constant(10, Integer.int32_t())])),
                ],
            ),
            end := BasicBlock(3, instructions=[Return([u1.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, loop_body_2),
            FalseCase(loop_body, loop_body),
            TrueCase(loop_body_2, end),
            FalseCase(loop_body_2, loop_body_2),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[u0.copy()]))
    assert start.instructions == [Assignment(z0.copy(), BinaryOperation(OperationType.plus, [u0.copy(), Constant(1, Integer.int32_t())]))]
    assert loop_body.instructions == [
        Phi(z1.copy(), [z0.copy(), z2.copy()]),
        Assignment(z2.copy(), BinaryOperation(OperationType.plus, [z1.copy(), Constant(1, Integer.int32_t())])),
        Branch(Condition(OperationType.greater, [z1.copy(), Constant(10, Integer.int32_t())])),
    ]
    assert loop_body_2.instructions == [
        Branch(Condition(OperationType.greater, [z1.copy(), Constant(10, Integer.int32_t())])),
    ]
    assert end.instructions == [Return([z1.copy()])]


def test_counterexample_13():
    """
    +------------------+
    |        0.        |
    | y#0 = u#0 + 0x3  |
    +------------------+
      |
      |
      v
    +------------------+
    |        1.        |
    | z#1 = ϕ(u#0,z#2) |
    | y#1 = ϕ(y#0,z#2) |
    | y#2 = ϕ(u#0,y#1) | ---+
    |    z#2 = u#0     |    |
    |  if(z#1 > 0xa)   | <--+
    +------------------+
      |
      |
      v
    +------------------+
    |        2.        |
    |    return y#2    |
    +------------------+
    """
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    u0, u1, u2 = [Variable("u", Integer.int32_t(), i) for i in range(3)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(
                0,
                instructions=[Assignment(y0.copy(), BinaryOperation(OperationType.plus, [u0.copy(), Constant(3, Integer.int32_t())]))],
            ),
            loop_body := BasicBlock(
                1,
                instructions=[
                    Phi(z1.copy(), [u0.copy(), z2.copy()]),
                    Phi(y1.copy(), [y0.copy(), z2.copy()]),
                    Phi(y2.copy(), [u0.copy(), y1.copy()]),
                    Assignment(z2.copy(), u0.copy()),
                    Branch(Condition(OperationType.greater, [z1.copy(), Constant(10, Integer.int32_t())])),
                ],
            ),
            end := BasicBlock(2, instructions=[Return([y2.copy()])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, loop_body),
            TrueCase(loop_body, end),
            FalseCase(loop_body, loop_body),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[u0.copy()]))
    assert start.instructions == [Assignment(y0.copy(), BinaryOperation(OperationType.plus, [u0.copy(), Constant(3, Integer.int32_t())]))]
    assert loop_body.instructions == [
        Phi(y1.copy(), [y0.copy(), u0.copy()]),
        Phi(y2.copy(), [u0.copy(), y1.copy()]),
        Branch(Condition(OperationType.greater, [u0.copy(), Constant(10, Integer.int32_t())])),
    ]
    assert end.instructions == [Return([y2.copy()])]


def test_alilased_variables():
    """
    Test that aliased variables are not added to the idenity graph.

    +-------------+
    |     0.      |
    |  x#0 = y#3  |
    | z#14 = x#0  |
    |  foo(x#0)   |
    | return z#14 |
    +-------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("x", ssa_label=0), Variable("y", ssa_label=3, is_aliased=True)),
                Assignment(Variable("z", ssa_label=14), Variable("x", ssa_label=0)),
                Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("x", ssa_label=0)])),
                Return([Variable("z", ssa_label=14)]),
            ],
        )
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[Variable("y", ssa_label=3, is_aliased=True)]))
    assert node.instructions == [
        Assignment(Variable("x", ssa_label=0), Variable("y", ssa_label=3, is_aliased=True)),
        Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("x", ssa_label=0)])),
        Return([Variable("x", ssa_label=0)]),
    ]


def test_replace_in_idential_calls():
    """
    Test that we replace all variable occurrences, even in identical call instructions.

    +------------+
    |     0.     |
    | x#0 = a#7  |
    |  foo(x#0)  |
    |  foo(x#0)  |
    | return a#7 |
    +------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(Variable("x", ssa_label=0), Variable("a", ssa_label=7)),
                Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("x", ssa_label=0)])),
                Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("x", ssa_label=0)])),
                Return([Variable("a", ssa_label=7)]),
            ],
        )
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[Variable("a", ssa_label=7)]))
    assert node.instructions == [
        Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("a", ssa_label=7)])),
        Assignment(ListOperation([]), Call(function_symbol("foo"), [Variable("a", ssa_label=7)])),
        Return([Variable("a", ssa_label=7)]),
    ]


def test_replace_in_idential_branches():
    """
    Test that we replace all variable occurrences, even in identical branch instructions.

         +----------------+     +----------------+
         |       2.       |     |       0.       |
         |    foo(0x1)    |     |   x#0 = a#7    |
      +- | if(x#0 u< 0x2) | <-- | if(a#7 u> 0x8) |
      |  +----------------+     +----------------+
      |    |                      |
      |    |                      |
      |    |                      v
      |    |                    +----------------+
      |    |                    |       1.       |
      |    |                    |    foo(0x0)    |
      |    |                    | if(x#0 u< 0x2) | -+
      |    |                    +----------------+  |
      |    |                      |                 |
      |    |                      |                 |
      |    |                      v                 |
      |    |                    +----------------+  |
      |    |                    |       3.       |  |
      |    +------------------> |    bar(x#0)    |  |
      |                         +----------------+  |
      |                           |                 |
      |                           |                 |
      |                           v                 |
      |                         +----------------+  |
      |                         |       4.       |  |
      +-----------------------> |   return x#0   | <+
                                +----------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(
                0,
                instructions=[
                    Assignment(Variable("x", ssa_label=0), Variable("a", ssa_label=7)),
                    Branch(Condition(OperationType.greater_us, [Variable("a", ssa_label=7), Constant(8)])),
                ],
            ),
            case1 := BasicBlock(
                1,
                instructions=[
                    Assignment(ListOperation([]), Call(function_symbol("foo"), [Constant(0)])),
                    Branch(Condition(OperationType.less_us, [Variable("x", ssa_label=0), Constant(2)])),
                ],
            ),
            case2 := BasicBlock(
                2,
                instructions=[
                    Assignment(ListOperation([]), Call(function_symbol("foo"), [Constant(1)])),
                    Branch(Condition(OperationType.less_us, [Variable("x", ssa_label=0), Constant(2)])),
                ],
            ),
            case3 := BasicBlock(
                3,
                instructions=[
                    Assignment(ListOperation([]), Call(function_symbol("bar"), [Variable("x", ssa_label=0)])),
                ],
            ),
            end := BasicBlock(4, instructions=[Return([Variable("x", ssa_label=0)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(head, case1),
            FalseCase(head, case2),
            TrueCase(case1, end),
            TrueCase(case2, end),
            FalseCase(case1, case3),
            FalseCase(case2, case3),
            UnconditionalEdge(case3, end),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[Variable("a", ssa_label=7)]))
    assert head.instructions == [Branch(Condition(OperationType.greater_us, [Variable("a", ssa_label=7), Constant(8)]))]
    assert case1.instructions == [
        Assignment(ListOperation([]), Call(function_symbol("foo"), [Constant(0)])),
        Branch(Condition(OperationType.less_us, [Variable("a", ssa_label=7), Constant(2)])),
    ]
    assert case2.instructions == [
        Assignment(ListOperation([]), Call(function_symbol("foo"), [Constant(1)])),
        Branch(Condition(OperationType.less_us, [Variable("a", ssa_label=7), Constant(2)])),
    ]
    assert case3.instructions == [
        Assignment(ListOperation([]), Call(function_symbol("bar"), [Variable("a", ssa_label=7)])),
    ]
    assert end.instructions == [Return([Variable("a", ssa_label=7)])]


def test_non_defined_variables_no_sinks():
    """
        It helps to find loops if we do not consider variables, that are not defined as sinks. Of course, function parameters are sinks.
                                                           +--------------------------------------------------------------+
                                                       |                              0.                              |
                                                       |                   __x86.get_pc_thunk.bx()                    |
                                                       +--------------------------------------------------------------+
                                                         |
                                                         |
                                                         v
    +--------------------------------------------+     +--------------------------------------------------------------+
    |                                            |     |                              1.                              |
    |                                            |     |               var_28#1 = ϕ(var_28#0,var_28#2)                |
    |                     3.                     |     |               var_24#1 = ϕ(var_24#0,var_24#2)                |
    |              return var_10#2               |     |               var_20#1 = ϕ(var_20#0,var_20#2)                |
    |                                            |     |                  var_10#2 = ϕ(0x1,var_10#3)                  |
    |                                            | <-- |                    if(var_10#2 <= arg1#0)                    | <-----+
    +--------------------------------------------+     +--------------------------------------------------------------+       |
                                                         |                                                                    |
                                                         |                                                                    |
                                                         v                                                                    |
                                                       +--------------------------------------------------------------+       |
                                                       |                              2.                              |       |
                                                       +--------------------------------------------------------------+       |
                                                         |                                                                    |
                                                         |                                                                    |
                                                         v                                                                    |
    +--------------------------------------------+     +--------------------------------------------------------------+       |
    |                                            |     |                              4.                              |       |
    |                     6.                     |     |               var_28#2 = ϕ(var_28#1,var_10#2)                |       |
    | putchar(0xa, var_28#2, var_24#2, var_20#2) |     |              var_24#2 = ϕ(var_24#1,var_14_1#3)               |       |
    |         var_10#3 = var_10#2 + 0x1          |     |                var_20#2 = ϕ(var_20#1,eax_2#6)                |       |
    |                                            |     |                var_14_1#3 = ϕ(0x0,var_14_1#4)                |       |
    |                                            | <-- |                   if(var_14_1#3 <= arg2#0)                   | <+    |
    +--------------------------------------------+     +--------------------------------------------------------------+  |    |
      |                                                  |                                                               |    |
      |                                                  |                                                               |    |
      |                                                  v                                                               |    |
      |                                                +--------------------------------------------------------------+  |    |
      |                                                |                              5.                              |  |    |
      |                                                |               eax_2#6 = var_10#2 * var_14_1#3                |  |    |
      |                                                | printf(0x113c8, var_10#2, var_14_1#3, var_10#2 * var_14_1#3) |  |    |
      |                                                |                var_14_1#4 = var_14_1#3 + 0x1                 | -+    |
      |                                                +--------------------------------------------------------------+       |
      |                                                                                                                       |
      +-----------------------------------------------------------------------------------------------------------------------+
    """
    arg_1 = Variable("arg1", Integer(32, True), 0, False, None)
    arg_2 = Variable("arg2", Integer(32, True), 0, False, None)
    var_10 = [Variable("var_10", Integer(32, True), i, False, None) for i in range(4)]
    var_14_1 = [Variable("var_14_1", Integer(32, True), i, False, None) for i in range(5)]
    var_20 = [Variable("var_20", CustomType("void", 0), i, False, None) for i in range(4)]
    var_24 = [Variable("var_24", Integer(32, True), i, False, None) for i in range(3)]
    var_28 = [Variable("var_28", Integer(32, True), i, False, None) for i in range(3)]
    eax_2 = Variable("eax_2", CustomType("void", 0), 6, False, None)
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(
                        ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1)
                    )
                ],
            ),
            BasicBlock(
                1,
                [
                    Phi(var_28[1], [var_28[0], var_28[2]]),
                    Phi(var_24[1], [var_24[0], var_24[2]]),
                    Phi(var_20[1], [var_20[0], var_20[2]]),
                    Phi(var_10[2], [Constant(1, Integer(32, True)), var_10[3]]),
                    Branch(Condition(OperationType.less_or_equal, [var_10[2], arg_1], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(2, []),
            BasicBlock(3, [Return(ListOperation([var_10[2]]))]),
            BasicBlock(
                4,
                [
                    Phi(var_28[2], [var_28[1], var_10[2]]),
                    Phi(var_24[2], [var_24[1], var_14_1[3]]),
                    Phi(var_20[2], [var_20[1], eax_2]),
                    Phi(var_14_1[3], [Constant(0, Integer(32, True)), var_14_1[4]]),
                    Branch(Condition(OperationType.less_or_equal, [var_14_1[3], arg_2], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(
                5,
                [
                    Assignment(eax_2, BinaryOperation(OperationType.multiply, [var_10[2], var_14_1[3]], CustomType("void", 0))),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(70600, Pointer(Integer(8, True), 32)),
                                var_10[2],
                                var_14_1[3],
                                BinaryOperation(OperationType.multiply, [var_10[2], var_14_1[3]], CustomType("void", 0)),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            4,
                        ),
                    ),
                    Assignment(
                        var_14_1[4],
                        BinaryOperation(OperationType.plus, [var_14_1[3], Constant(1, Integer(32, True))], Integer(32, True)),
                    ),
                ],
            ),
            BasicBlock(
                6,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("putchar"),
                            [Constant(10, Integer(32, True)), var_28[2], var_24[2], var_20[2]],
                            Pointer(CustomType("void", 0), 32),
                            5,
                        ),
                    ),
                    Assignment(
                        var_10[3],
                        BinaryOperation(OperationType.plus, [var_10[2], Constant(1, Integer(32, True))], Integer(32, True)),
                    ),
                ],
            ),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[4]),
            TrueCase(vertices[4], vertices[5]),
            FalseCase(vertices[4], vertices[6]),
            UnconditionalEdge(vertices[5], vertices[4]),
            UnconditionalEdge(vertices[6], vertices[1]),
        ]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[Variable(f"arg{i}", Integer.int32_t()) for i in [1, 2]]))

    assert vertices[0].instructions == [
        Assignment(ListOperation([]), Call(imp_function_symbol("__x86.get_pc_thunk.bx"), [], Pointer(CustomType("void", 0), 32), 1))
    ]
    assert vertices[1].instructions == [
        Phi(var_10[2], [Constant(1, Integer(32, True)), var_10[3]]),
        Branch(Condition(OperationType.less_or_equal, [var_10[2], arg_1], CustomType("bool", 1))),
    ]
    assert vertices[2].instructions == []
    assert vertices[3].instructions == [Return(ListOperation([var_10[2]]))]
    assert vertices[4].instructions == [
        Phi(var_14_1[3], [Constant(0, Integer(32, True)), var_14_1[4]]),
        Branch(Condition(OperationType.less_or_equal, [var_14_1[3], arg_2], CustomType("bool", 1))),
    ]
    assert vertices[5].instructions == [
        Assignment(eax_2, BinaryOperation(OperationType.multiply, [var_10[2], var_14_1[3]], CustomType("void", 0))),
        Assignment(
            ListOperation([]),
            Call(
                imp_function_symbol("printf"),
                [
                    Constant(70600, Pointer(Integer(8, True), 32)),
                    var_10[2],
                    var_14_1[3],
                    BinaryOperation(OperationType.multiply, [var_10[2], var_14_1[3]], CustomType("void", 0)),
                ],
                Pointer(CustomType("void", 0), 32),
                4,
            ),
        ),
        Assignment(var_14_1[4], BinaryOperation(OperationType.plus, [var_14_1[3], Constant(1, Integer(32, True))], Integer(32, True))),
    ]
    assert vertices[6].instructions == [
        Assignment(
            ListOperation([]),
            Call(
                imp_function_symbol("putchar"),
                [Constant(10, Integer(32, True)), var_10[2], var_14_1[3], eax_2],
                Pointer(CustomType("void", 0), 32),
                5,
            ),
        ),
        Assignment(var_10[3], BinaryOperation(OperationType.plus, [var_10[2], Constant(1, Integer(32, True))], Integer(32, True))),
    ]


def test_conflict_in_component():
    """
    Do not merge variables that conflict each other, like var_10#2 and var_10#1.
                       +----------------------------------------+
                       |                   0.                   |
                       +----------------------------------------+
                         |
                         |
                         v
    +------------+     +----------------------------------------+
    |            |     |                   1.                   |
    |     3.     |     |       var_14#2 = ϕ(0x0,var_14#3)       |
    | return 0x0 |     |    var_10#1 = ϕ(var_10#0,var_10#2)     |
    |            | <-- |          if(var_14#2 <= 0x9)           | <+
    +------------+     +----------------------------------------+  |
                         |                                         |
                         |                                         |
                         v                                         |
                       +----------------------------------------+  |
                       |                   2.                   |  |
                       |     var_10#2 = var_10#1 + var_14#2     |  |
                       | printf(0x804a164, var_10#1 + var_14#2) |  |
                       |       var_14#3 = var_14#2 + 0x1        | -+
                       +----------------------------------------+
    """
    var_10 = [Variable("var_10", Integer(32, True), i, False, None) for i in range(4)]
    var_14 = [Variable("var_14", Integer(32, True), i, False, None) for i in range(4)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(0, []),
            BasicBlock(
                1,
                [
                    Phi(var_14[2], [Constant(0, Integer(32, True)), var_14[3]]),
                    Phi(var_10[1], [var_10[0], var_10[2]]),
                    Branch(Condition(OperationType.less_or_equal, [var_14[2], Constant(9, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(
                2,
                [
                    Assignment(var_10[2], BinaryOperation(OperationType.plus, [var_10[1], var_14[2]], Integer(32, True))),
                    Assignment(
                        ListOperation([]),
                        Call(
                            imp_function_symbol("printf"),
                            [
                                Constant(134521188, Pointer(Integer(8, True), 32)),
                                BinaryOperation(OperationType.plus, [var_10[1], var_14[2]], Integer(32, True)),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Assignment(
                        var_14[3],
                        BinaryOperation(OperationType.plus, [var_14[2], Constant(1, Integer(32, True))], Integer(32, True)),
                    ),
                ],
            ),
            BasicBlock(3, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(vertices[0], vertices[1]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            UnconditionalEdge(vertices[2], vertices[1]),
        ]
    )
    instructions = [inst.copy() for inst in cfg.instructions]
    IdentityElimination().run(DecompilerTask("test", cfg))
    assert instructions == list(cfg.instructions)


def test_do_not_identify_relations():
    """
      short version of test_switch test27
            +-------------------------------------+
            |                 0.                  |
            |         var_10#1 = var_10#0         |
            |       var_28#1 = &(var_10#1)        |
            | __isoc99_scanf(0x804c025, var_28#1) |
            |        var_10#2 -> var_10#1         |
            |         if(var_10#2 == 0x5)         | -+
            +-------------------------------------+  |
              |                                      |
              |                                      |
              v                                      |
            +-------------------------------------+  |
            |                 1.                  |  |
         +- |         if(var_10#2 > 0x5)          |  |
         |  +-------------------------------------+  |
         |    |                                      |
         |    |                                      |
         |    v                                      |
         |  +-------------------------------------+  |
         |  |                 3.                  |  |
         |  |         if(var_10#2 == 0x1)         | -+----+
         |  +-------------------------------------+  |    |
         |    |                                      |    |
         |    |                                      |    |
         |    v                                      |    |
         |  +-------------------------------------+  |    |
         |  |                 5.                  |  |    |
    +----+- |         if(var_10#2 == 0x3)         |  |    |
    |    |  +-------------------------------------+  |    |
    |    |    |                                      |    |
    |    |    |                                      |    |
    |    |    v                                      |    |
    |    |  +-------------------------------------+  |    |
    |    |  |                 7.                  |  |    |
    |    |  |  printf(0x804c025, arg_4#0 + 0x2)   |  |    |
    |    |  +-------------------------------------+  |    |
    |    |    |                                      |    |
    |    |    |                                      |    |
    |    |    v                                      v    v
    |    |  +------------------------------------------------------------------------------+
    |    |  |                                      2.                                      |
    |    |  |                 arg_4#6 = ϕ(arg_4#0,arg_4#0,arg_4#0,arg_4#0)                 |
    |    +> |              var_10#6 = ϕ(var_10#2,var_10#2,var_10#2,var_10#2)               |
    |       |                           var_28_4#6 = &(arg_4#6)                            |
    |       |                    __isoc99_scanf(0x804c025, var_28_4#6)                     |
    |       |                              arg_4#7 -> arg_4#6                              |
    +-----> |                             if(var_10#6 == 0x6)                              |
            +------------------------------------------------------------------------------+
              |                                           |
              |                                           |
              v                                           v
            +-------------------------------------+     +----------------------------------+
            |                 4.                  |     |                8.                |
            |  printf(0x804c025, arg_4#7 + 0x3)   |     | printf(0x804c025, arg_4#7 + 0x2) |
            +-------------------------------------+     +----------------------------------+
              |                                           |
              |                                           |
              v                                           |
            +-------------------------------------+       |
            |                 6.                  |       |
            |             return 0x0              | <-----+
            +-------------------------------------+
    """
    arg_4 = [Variable("arg_4", Integer(32, True), i, True, None) for i in range(8)]
    var_10 = [Variable("var_10", Integer(32, True), i, True, None) for i in range(7)]
    var_28 = Variable("var_28", Pointer(Integer(32, True), 32), 1, False, None)
    cfg = ControlFlowGraph()
    var_28_4 = Variable("var_28_4", Pointer(Integer(32, True), 32), 6, False, None)
    cfg.add_nodes_from(
        vertices := [
            BasicBlock(
                0,
                [
                    Assignment(var_10[1], var_10[0]),
                    Assignment(
                        var_28,
                        UnaryOperation(
                            OperationType.address,
                            [var_10[1]],
                            Pointer(Integer(32, True), 32),
                            None,
                            False,
                        ),
                    ),
                    Assignment(
                        ListOperation([]),
                        Call(
                            Constant("__isoc99_scanf", UnknownType()),
                            [Constant(134529061, Integer(32, True)), var_28],
                            Pointer(CustomType("void", 0), 32),
                            2,
                        ),
                    ),
                    Relation(var_10[2], var_10[1]),
                    Branch(
                        Condition(
                            OperationType.equal,
                            [var_10[2], Constant(5, Integer(32, True))],
                            CustomType("bool", 1),
                        )
                    ),
                ],
            ),
            BasicBlock(1, [Branch(Condition(OperationType.greater, [var_10[2], Constant(5, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(
                2,
                [
                    Phi(arg_4[6], [arg_4[0], arg_4[0], arg_4[0], arg_4[0]]),
                    Phi(var_10[6], [var_10[2], var_10[2], var_10[2], var_10[2]]),
                    Assignment(var_28_4, UnaryOperation(OperationType.address, [arg_4[6]], Pointer(Integer(32, True), 32), None, False)),
                    Assignment(
                        ListOperation([]),
                        Call(
                            Constant("__isoc99_scanf", UnknownType()),
                            [Constant(134529061, Integer(32, True)), var_28_4],
                            Pointer(CustomType("void", 0), 32),
                            7,
                        ),
                    ),
                    Relation(arg_4[7], arg_4[6]),
                    Branch(Condition(OperationType.equal, [var_10[6], Constant(6, Integer(32, True))], CustomType("bool", 1))),
                ],
            ),
            BasicBlock(
                3,
                [Branch(Condition(OperationType.equal, [var_10[2], Constant(1, Integer(32, True))], CustomType("bool", 1)))],
            ),
            BasicBlock(
                4,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            Constant("printf", UnknownType()),
                            [
                                Constant(134529061, Integer(32, True)),
                                BinaryOperation(OperationType.plus, [arg_4[7], Constant(3, Integer(32, True))], Integer(32, True)),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            8,
                        ),
                    )
                ],
            ),
            BasicBlock(5, [Branch(Condition(OperationType.equal, [var_10[2], Constant(3, Integer(32, True))], CustomType("bool", 1)))]),
            BasicBlock(6, [Return(ListOperation([Constant(0, Integer(32, True))]))]),
            BasicBlock(
                7,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            Constant("printf", UnknownType()),
                            [
                                Constant(134529061, Integer(32, True)),
                                BinaryOperation(
                                    OperationType.plus,
                                    [arg_4[0], Constant(2, Integer(32, True))],
                                    Integer(32, True),
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            5,
                        ),
                    )
                ],
            ),
            BasicBlock(
                8,
                [
                    Assignment(
                        ListOperation([]),
                        Call(
                            Constant("printf", UnknownType()),
                            [
                                Constant(134529061, Integer(32, True)),
                                BinaryOperation(
                                    OperationType.plus,
                                    [arg_4[7], Constant(2, Integer(32, True))],
                                    Integer(32, True),
                                ),
                            ],
                            Pointer(CustomType("void", 0), 32),
                            10,
                        ),
                    )
                ],
            ),
        ]
    )
    cfg.add_edges_from(
        [
            FalseCase(vertices[0], vertices[1]),
            TrueCase(vertices[0], vertices[2]),
            TrueCase(vertices[1], vertices[2]),
            FalseCase(vertices[1], vertices[3]),
            TrueCase(vertices[2], vertices[4]),
            FalseCase(vertices[2], vertices[8]),
            TrueCase(vertices[3], vertices[2]),
            FalseCase(vertices[3], vertices[5]),
            UnconditionalEdge(vertices[4], vertices[6]),
            TrueCase(vertices[5], vertices[7]),
            FalseCase(vertices[5], vertices[2]),
            UnconditionalEdge(vertices[7], vertices[2]),
            UnconditionalEdge(vertices[8], vertices[6]),
        ]
    )

    instructions = [inst.copy() for inst in cfg.instructions]
    IdentityElimination().run(DecompilerTask("test", cfg))
    print([str(i) for i in vertices[2].instructions])
    print(instructions[8])
    assert vertices[0].instructions == [
        Assignment(
            var_28,
            UnaryOperation(
                OperationType.address,
                [var_10[0]],
                Pointer(Integer(32, True), 32),
                None,
                False,
            ),
        ),
        instructions[2],
        Relation(var_10[2], var_10[0]),
        instructions[4],
    ]
    assert vertices[1].instructions == [instructions[5]]
    assert vertices[2].instructions == [
        Assignment(var_28_4, UnaryOperation(OperationType.address, [arg_4[0]], Pointer(Integer(32, True), 32), None, False)),
        instructions[9],
        Relation(arg_4[7], arg_4[0]),
        Branch(Condition(OperationType.equal, [var_10[2], Constant(6, Integer(32, True))], CustomType("bool", 1))),
    ]
    assert vertices[3].instructions == [instructions[12]]
    assert vertices[4].instructions == [instructions[13]]
    assert vertices[5].instructions == [instructions[14]]
    assert vertices[6].instructions == [instructions[15]]
    assert vertices[7].instructions == [instructions[16]]
    assert vertices[8].instructions == [instructions[17]]


def test_do_not_crash_if_no_identity():
    """
      +----------------------------------------------------------------------+
      v                                                                      |
    +------------------+     +------------------+     +-------------------+  |
    |        4.        |     |        2.        |     |        0.         |  |
    | z#2 = ϕ(z#0,y#2) |     |   y#2 = a_1#0    |     | if(a_0#0 < a_1#0) |  |
    |    return z#2    | <-- | if(a_1#0 < 0x14) | <-- |                   |  |
    +------------------+     +------------------+     +-------------------+  |
                               |                        |                    |
                               |                        |                    |
                               |                        v                    |
                               |                      +-------------------+  |
                               |                      |        1.         |  |
                               |                      |    y#1 = a_0#0    |  |
                               |                      |  if(a_0#0 > 0xa)  | -+
                               |                      +-------------------+
                               |                        |
                               |                        |
                               |                        v
                               |                      +-------------------+
                               |                      |        3.         |
                               |                      | z#1 = ϕ(z#0,y#1)  |
                               +--------------------> |    return z#1     |
                                                      +-------------------+
    """
    y0, y1, y2 = [Variable("y", Integer.int32_t(), i) for i in range(3)]
    z0, z1, z2 = [Variable("z", Integer.int32_t(), i) for i in range(3)]
    a_0, a_1 = [Variable(f"a_{i}", ssa_label=0) for i in range(2)]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            head := BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [a_0, a_1]))]),
            true := BasicBlock(1, [Assignment(y1, a_0), Branch(Condition(OperationType.greater, [a_0, Constant(10, Integer.int32_t())]))]),
            false := BasicBlock(2, [Assignment(y2, a_1), Branch(Condition(OperationType.less, [a_1, Constant(20, Integer.int32_t())]))]),
            r1 := BasicBlock(3, [Phi(z1.copy(), [z0.copy(), y1.copy()]), Return([z1])]),
            r2 := BasicBlock(4, [Phi(z2.copy(), [z0.copy(), y2.copy()]), Return([z2])]),
        ]
    )
    cfg.add_edges_from(
        [TrueCase(head, true), FalseCase(head, false), TrueCase(true, r1), FalseCase(true, r2), TrueCase(false, r2), FalseCase(false, r1)]
    )
    IdentityElimination().run(DecompilerTask("test", cfg, function_parameters=[a_0, a_1]))
