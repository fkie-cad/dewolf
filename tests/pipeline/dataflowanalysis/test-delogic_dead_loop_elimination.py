from decompiler.pipeline.dataflowanalysis import DeadLoopElimination, ExpressionPropagation
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Return
from decompiler.structures.pseudo.operations import Condition, OperationType
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

a = Variable("a", Integer.int32_t(), 0)
b = Variable("b", Integer.int32_t(), 1)
c = Variable("c", Integer.int32_t(), 2)
x = Variable("x", Integer.int32_t(), 3)
x1 = Variable("x", Integer.int32_t(), 1)
x2 = Variable("x", Integer.int32_t(), 2)
x3 = Variable("x", Integer.int32_t(), 3)


def _run_dead_loop_elimination(cfg: ControlFlowGraph):
    options = Options()
    options.set("dead-loop-elimination.timeout_satisfiable", 1000)
    options.set("logic-engine.engine", "delogic")
    DeadLoopElimination().run(DecompilerTask(name="test", function_identifier="", cfg=cfg, options=options))


def _run_expression_propagation(cfg: ControlFlowGraph):
    options = Options()
    options.set("expression-propagation.maximum_instruction_complexity", 10)
    options.set("expression-propagation.maximum_branch_complexity", 10)
    options.set("expression-propagation.maximum_call_complexity", 10)
    options.set("expression-propagation.maximum_assignment_complexity", 10)
    ExpressionPropagation().run(DecompilerTask(name="test", function_identifier="", cfg=cfg, options=options))


def test_no_propagation_no_change():
    """
    Simple case where no branch will be removed:
    No Constant in Phi.

    +----+     +---------------+
    | 2. |     | 0.            |
    |    |<----+ a = 0x0       |<---+
    +-+--+   f | x = phi(a, b) |    |
      |        | if(x == 0x0)  |    |
      |        +---------------+    |
      |          |t                 |
      |          |                  |
      |          V                  |
      |        +--------------+     |
      |        | 1.           |     |
      |        | b = 0x1      | f   |
      |        | if(b == 0x0) |-----+
      |        +--------------+
      |          |t
      |          |
      |          V
      |        +------------+
      |        | 3.         |
      +------> | return 0x1 |
               +------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0, instructions=[phi := Phi(x, [a, b]), branch := Branch(Condition(OperationType.equal, [phi.destination, Constant(0x0)]))]
            ),
            n1 := BasicBlock(
                1, instructions=[Assignment(b, Constant(0x1)), back_edge := Branch(Condition(OperationType.equal, [b, Constant(0x0)]))]
            ),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n2, n3),
            TrueCase(n1, n3),
            FalseCase(n1, n0),
        ]
    )
    origin_blocks = {n0: a, n1: b}
    phi.update_phi_function(origin_blocks)
    _run_dead_loop_elimination(cfg)
    assert set(cfg) == {n0, n1, n2, n3}
    assert n0.instructions == [phi, branch]
    assert isinstance(cfg.get_edge(n0, n1), TrueCase)
    assert isinstance(cfg.get_edge(n0, n2), FalseCase)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n3), TrueCase)
    assert isinstance(cfg.get_edge(n1, n0), FalseCase)


def test_backedge_no_change():
    """
    Simple case where no branch will be removed:
    Backedge prevents pruning.

    +----+     +------------------+
    | 2. |     | 0.               |
    |    |<----+ a = 0x0          |<--+
    +-+--+   f | x = phi(0x0, b)  |   |
      |        | if(x == 0x0)     |   |
      |        +------------------+   |
      |          |t                   |
      |          |                    |
      |          V                    |
      |        +--------------+       |
      |        | 1.           |       |
      |        | b = 0x1      | f     |
      |        | if(b == 0x0) |-------+
      |        +--------------+
      |          |t
      |          |
      |          V
      |        +------------+
      |        | 3.         |
      +------> | return 0x1 |
               +------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[
                    phi := Phi(x, [const := Constant(0x0), b]),
                    branch := Branch(Condition(OperationType.equal, [phi.destination, Constant(0x0)])),
                ],
            ),
            n1 := BasicBlock(
                1, instructions=[Assignment(b, Constant(0x1)), back_edge := Branch(Condition(OperationType.equal, [b, Constant(0x0)]))]
            ),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
        ]
    )
    origin_blocks = {n0: const, n1: b}
    phi.update_phi_function(origin_blocks)
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n2, n3),
            TrueCase(n1, n3),
            FalseCase(n1, n0),
        ]
    )
    _run_dead_loop_elimination(cfg)
    assert set(cfg) == {n0, n1, n2, n3}
    assert n0.instructions == [phi, branch]
    assert isinstance(cfg.get_edge(n0, n1), TrueCase)
    assert isinstance(cfg.get_edge(n0, n2), FalseCase)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n3), TrueCase)
    assert isinstance(cfg.get_edge(n1, n0), FalseCase)


def test_not_dominated_no_change():
    """
    Simple case where no branch will be removed:
    Variables in phi-function not dominated by current block.

                +-----------------+
                | 4.              |
                | b = 0x1         |
                +-+---------------+
                  |
                  |
                  v
    +----+     +--+---------------+
    | 2. |     | 0.               |
    |    +<----+ a = 0x0          +<--+
    +-+--+   f | x = phi(0x0, b)  |   |
      |        | if(x != 0x0)     |   |
      |        +------------------+   |
      |          |t                   |
      |          +                    |
      |          V                    |
      |        +--------------+       |
      |        | 1.           |       |
      |        | if(b == 0x0) | f     |
      |        |              +-------+
      |        +--------------+
      |          |t
      |          +
      |          V
      |        +------------+
      |        | 3.         |
      +------> | return 0x1 |
               +------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[
                    phi := Phi(x, [const := Constant(0x0), b]),
                    branch := Branch(Condition(OperationType.not_equal, [phi.destination, Constant(0x0)])),
                ],
            ),
            n1 := BasicBlock(1, instructions=[back_edge := Branch(Condition(OperationType.equal, [b, Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
            n4 := BasicBlock(4, instructions=[Assignment(b, Constant(0x1))]),
        ]
    )
    variable_of_block = {n0: const, n4: b}
    phi.update_phi_function(variable_of_block)
    cfg.add_edges_from(
        [
            UnconditionalEdge(n4, n0),
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n2, n3),
            TrueCase(n1, n3),
            FalseCase(n1, n0),
        ]
    )
    _run_dead_loop_elimination(cfg)
    assert set(cfg) == {n0, n1, n2, n3, n4}
    assert n0.instructions == [phi, branch]
    assert isinstance(cfg.get_edge(n4, n0), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n0, n1), TrueCase)
    assert isinstance(cfg.get_edge(n0, n2), FalseCase)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n3), TrueCase)
    assert isinstance(cfg.get_edge(n1, n0), FalseCase)


def test_false_branch_without_back_edge():
    """
    Simple case where block 1 will be removed:
    +----+     +------------------+
    |    |     |        0.        |
    | 2. |     | x#3 = ϕ(0x0,b#1) |
    |    | <-- |  if(x#3 != 0x0)  | <+
    +----+     +------------------+  |
      |          |                   |
      |          |                   |
      |          v                   |
      |        +------------------+  |
      |        |        1.        |  |
      |        |    b#1 = 0x1     |  |
      |        |  if(b#1 == 0x0)  | -+
      |        +------------------+
      |          |
      |          |
      |          v
      |        +------------------+
      |        |        3.        |
      +------> |    return 0x1    |
               +------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[
                    phi := Phi(x, [const := Constant(0x0), b]),
                    branch := Branch(Condition(OperationType.not_equal, [phi.destination, Constant(0x0)])),
                ],
            ),
            n1 := BasicBlock(
                1, instructions=[Assignment(b, Constant(0x1)), back_edge := Branch(Condition(OperationType.equal, [b, Constant(0x0)]))]
            ),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
        ]
    )
    variable_of_block = {n0: const, n1: b}
    phi.update_phi_function(variable_of_block)
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n2, n3),
            TrueCase(n1, n3),
            FalseCase(n1, n0),
        ]
    )
    _run_dead_loop_elimination(cfg)
    assert set(cfg) == {n0, n2, n3}
    assert n0.instructions == [phi]
    assert isinstance(cfg.get_edge(n0, n2), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)


def test_variable_in_phi():
    """
    if (a == 0 || b !=0) where b = Phi(a, c)
    case where block 1 will be removed:

    +----+     +----------------------------------+
    |    |     |                0.                |
    | 2. |     |         b#1 = ϕ(a#0,c#2)         |
    |    | <-- | if((a#0 == 0x0) || (b#1 != 0x0)) | <+
    +----+     +----------------------------------+  |
      |          |                                   |
      |          |                                   |
      |          v                                   |
      |        +----------------------------------+  |
      |        |                1.                |  |
      |        |            c#2 = 0x1             |  |
      |        |          if(b#1 == 0x0)          | -+
      |        +----------------------------------+
      |          |
      |          |
      |          v
      |        +----------------------------------+
      |        |                3.                |
      +------> |            return 0x1            |
               +----------------------------------+

    """
    phi = Phi(b, [a, c])
    cond1 = Condition(OperationType.equal, [a, Constant(0x0)])
    cond2 = Condition(OperationType.not_equal, [phi.destination, Constant(0x0)])
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[
                    phi,
                    branch := Branch(Condition(OperationType.bitwise_or, [cond1, cond2])),
                ],
            ),
            n1 := BasicBlock(
                1, instructions=[Assignment(c, Constant(0x1)), back_edge := Branch(Condition(OperationType.equal, [b, Constant(0x0)]))]
            ),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
        ]
    )
    variable_of_block = {n0: a, n1: c}
    phi.update_phi_function(variable_of_block)
    cfg.add_edges_from(
        [
            FalseCase(n0, n1),
            TrueCase(n0, n2),
            UnconditionalEdge(n2, n3),
            TrueCase(n1, n3),
            FalseCase(n1, n0),
        ]
    )
    _run_dead_loop_elimination(cfg)
    assert set(cfg.nodes) == {n0, n2, n3}
    assert n0.instructions == [phi]
    assert isinstance(cfg.get_edge(n0, n2), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)


def test_multiple_upstream_const_in_phi():
    """
    No block will be removed.
    After expression propagation:
    +-----------+     +---------------+
    |    2.     |     |      0.       |
    | x#2 = 0x2 | <-- | if(a#0 < 0x0) |
    +-----------+     +---------------+
      |                 |
      |                 |
      |                 v
      |               +---------------+
      |               |      1.       |
      |               |   x#1 = 0x1   |
      |               +---------------+
      |                 |
      |                 |
      |                 v
      |               +----------------------+     +------------+
      |               |          3.          |     |     5.     |
      |               | b#1 = ϕ(0x1,0x2,0x5) |     | return 0x0 |
      +-------------> |    if(b#1 == 0x5)    | --> |            |
                      +----------------------+     +------------+
                        |                ^
                        |                |
                        v                |
                      +---------------+  |
                      |      4.       |  |
                      |   x#3 = 0x5   | -+
                      +---------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[Branch(Condition(OperationType.less, [a, Constant(0x0)]))],
            ),
            n1 := BasicBlock(1, instructions=[Assignment(x1, Constant(0x1))]),
            n2 := BasicBlock(2, instructions=[Assignment(x2, Constant(0x2))]),
            n3 := BasicBlock(3, instructions=[phi := Phi(b, [x1, x2, x3]), Branch(Condition(OperationType.equal, [b, Constant(0x5)]))]),
            n4 := BasicBlock(4, instructions=[Assignment(x3, Constant(0x5))]),
            n5 := BasicBlock(5, instructions=[Return([Constant(0)])]),
        ]
    )
    variable_of_block = {n1: x1, n2: x2, n4: x3}
    phi.update_phi_function(variable_of_block)
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n1, n3),
            UnconditionalEdge(n2, n3),
            UnconditionalEdge(n4, n3),
            FalseCase(n3, n4),
            TrueCase(n3, n5),
        ]
    )
    _run_expression_propagation(cfg)
    _run_dead_loop_elimination(cfg)
    assert set(cfg.nodes) == {n0, n1, n2, n3, n4, n5}
    assert isinstance(cfg.get_edge(n0, n1), TrueCase)
    assert isinstance(cfg.get_edge(n0, n2), FalseCase)
    assert isinstance(cfg.get_edge(n1, n3), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n4, n3), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n3, n4), FalseCase)
    assert isinstance(cfg.get_edge(n3, n5), TrueCase)


def test_two_const_one_upstream_in_phi():
    """
    Block 2 will be removed.
    After expression propagation:
                       +------------------+
                       |        0.        |
                       |    x#1 = 0x1     |
                       +------------------+
                         |
                         |
                         v
    +------------+     +------------------+
    |     3.     |     |        1.        |
    | return 0x0 |     | b#1 = ϕ(0x1,0x5) |
    |            | <-- |  if(b#1 == 0x1)  | <+
    +------------+     +------------------+  |
                         |                   |
                         |                   |
                         v                   |
                       +------------------+  |
                       |        2.        |  |
                       |    x#3 = 0x5     | -+
                       +------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[Assignment(x1, Constant(0x1))]),
            n1 := BasicBlock(1, instructions=[phi := Phi(b, [x1, x3]), Branch(Condition(OperationType.equal, [b, Constant(0x1)]))]),
            n2 := BasicBlock(2, instructions=[Assignment(x3, Constant(0x5))]),
            n3 := BasicBlock(3, instructions=[Return([Constant(0)])]),
        ]
    )
    variable_of_block = {n0: x1, n2: x3}
    phi.update_phi_function(variable_of_block)
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            FalseCase(n1, n2),
            TrueCase(n1, n3),
            UnconditionalEdge(n2, n1),
        ]
    )
    _run_expression_propagation(cfg)
    _run_dead_loop_elimination(cfg)
    assert set(cfg.nodes) == {n0, n1, n3}
    assert len(n1.instructions) == 1
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n3), UnconditionalEdge)
