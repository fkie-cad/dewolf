from decompiler.pipeline.dataflowanalysis import DeadPathElimination
from decompiler.structures.graphs.cfg import BasicBlock, BasicBlockEdgeCondition, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Phi, Return
from decompiler.structures.pseudo.operations import Condition, ListOperation, OperationType
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def run_dead_path_elimination(cfg):
    options = Options()
    options.set("dead-path-elimination.timeout_satisfiable", 1000)
    options.set("logic-engine.engine", "z3")
    DeadPathElimination().run(DecompilerTask("test", cfg, options=options))


def test_trivial_no_change():
    """
    Simple case where no branch can be removed.

    +----+     +----------------+
    | 2. |     |       0.       |
    |    | <-- |   if(x < y)    |
    +----+     +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       1.       |
      |        +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       3.       |
      +------> |   return 0x1   |
               +----------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[branch := Branch(Condition(OperationType.less, [Variable("x"), Variable("y")]))]),
            n1 := BasicBlock(1, instructions=[]),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n1, n3),
            UnconditionalEdge(n2, n3),
        ]
    )
    run_dead_path_elimination(cfg)
    assert set(cfg) == {n0, n1, n2, n3}
    assert n0.instructions == [branch]
    assert isinstance(cfg.get_edge(n0, n1), TrueCase)
    assert isinstance(cfg.get_edge(n0, n2), FalseCase)
    assert isinstance(cfg.get_edge(n1, n3), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)


def test_trivial_true():
    """
    Simple case where the true branch is dead.

    +----+     +----------------+
    | 2. |     |       0.       |
    |    | <-- | if(0x0 == 0x1) |
    +----+     +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       1.       |
      |        +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       3.       |
      +------> |   return 0x1   |
               +----------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[Branch(Condition(OperationType.equal, [Constant(0), Constant(1)]))]),
            n1 := BasicBlock(1, instructions=[]),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n1, n3),
            UnconditionalEdge(n2, n3),
        ]
    )
    run_dead_path_elimination(cfg)
    assert set(cfg.nodes) == {n0, n2, n3}
    assert n0.instructions == []
    assert isinstance(cfg.get_edge(n0, n2), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)


def test_trivial_false():
    """
    Simple case where the false branch is dead.

    +----+     +----------------+
    | 2. |     |       0.       |
    |    | <-- | if(0x0 == 0x0) |
    +----+     +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       1.       |
      |        +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       3.       |
      +------> |   return 0x1   |
               +----------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[Branch(Condition(OperationType.equal, [Constant(0), Constant(0)]))]),
            n1 := BasicBlock(1, instructions=[]),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n1, n3),
            UnconditionalEdge(n2, n3),
        ]
    )
    run_dead_path_elimination(cfg)
    assert set(cfg.nodes) == {n0, n1, n3}
    assert n0.instructions == []
    assert [cfg.get_edge(n0, n1).condition_type, cfg.get_edge(n1, n3).condition_type] == [
        BasicBlockEdgeCondition.unconditional,
        BasicBlockEdgeCondition.unconditional,
    ]


def test_trivial_mixed():
    """
    Trivial test with mixed dead true and false branches.

    +----+     +----------------+     +----------------+
    | 5. |     |       2.       |     |       0.       |
    |    | <-- | if(0x0 == 0x0) | <-- |  if(x == 0x0)  |
    +----+     +----------------+     +----------------+
      |          |                      |
      |          |                      |
      |          v                      v
      |        +----------------+     +----------------+
      |        |       4.       |     |       1.       |
      |        |                |     | if(0x0 == 0x1) | -+
      |        +----------------+     +----------------+  |
      |          |                      |                 |
      |          |                      |                 |
      |          |                      v                 |
      |          |                    +----------------+  |
      |          |                    |       3.       |  |
      |          |                    +----------------+  |
      |          |                      |                 |
      |          |                      |                 |
      |          |                      v                 v
      |          |                    +---------------------+
      |          |                    |         6.          |
      |          +------------------> |     return 0x1      |
      |                               +---------------------+
      |                                 ^
      +---------------------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(0, instructions=[Branch(Condition(OperationType.equal, [Variable("x"), Constant(0)]))]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [Constant(0), Constant(1)]))]),
            n2 := BasicBlock(2, instructions=[Branch(Condition(OperationType.equal, [Constant(0), Constant(0)]))]),
            n3 := BasicBlock(3, instructions=[]),
            n4 := BasicBlock(4, instructions=[]),
            n5 := BasicBlock(5, instructions=[]),
            end := BasicBlock(6, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(start, n1),
            FalseCase(start, n2),
            TrueCase(n1, n3),
            FalseCase(n1, end),
            UnconditionalEdge(n3, end),
            TrueCase(n2, n4),
            FalseCase(n2, n5),
            UnconditionalEdge(n4, end),
            UnconditionalEdge(n5, end),
        ]
    )
    run_dead_path_elimination(cfg)
    assert set(cfg.nodes) == {start, n1, n2, n4, end}
    assert len(cfg.edges) == 5
    assert n1.instructions == n2.instructions == []
    assert [
        cfg.get_edge(start, n1).condition_type,
        cfg.get_edge(start, n2).condition_type,
        cfg.get_edge(n1, end).condition_type,
        cfg.get_edge(n2, n4).condition_type,
        cfg.get_edge(n4, end).condition_type,
    ] == [
        BasicBlockEdgeCondition.true,
        BasicBlockEdgeCondition.false,
        BasicBlockEdgeCondition.unconditional,
        BasicBlockEdgeCondition.unconditional,
        BasicBlockEdgeCondition.unconditional,
    ]


def test_dead_loop():
    """
    Check if a while-loop with an unsatisfyable condition is removed completely.

                       +----------------+
                       |       0.       |
                       +----------------+
                         |
                         |
                         v
    +------------+     +----------------+
    |     3.     |     |       1.       |
    | return 0x1 | <-- | if(0x2a < 0x0) | <+
    +------------+     +----------------+  |
                         |                 |
                         |                 |
                         v                 |
                       +----------------+  |
                       |       2.       | -+
                       +----------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(0, instructions=[]),
            loop_condition := BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [Constant(42), Constant(0)]))]),
            loop_body := BasicBlock(2, instructions=[]),
            end := BasicBlock(3, instructions=[Return([Constant(1)])]),
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
    run_dead_path_elimination(cfg)
    assert set(cfg.nodes) == {start, loop_condition, end}
    assert loop_condition.instructions == []
    assert len(cfg.edges) == 2
    assert [cfg.get_edge(start, loop_condition).condition_type, cfg.get_edge(loop_condition, end).condition_type] == [
        BasicBlockEdgeCondition.unconditional,
        BasicBlockEdgeCondition.unconditional,
    ]


def test_nested_loop():
    """
    Simple test with one dead branch with a nested loop inside.

         +----+     +----------------+
         | 1. |     |       0.       |
         |    | <-- | if(0x0 == 0x0) |
         +----+     +----------------+
           |          |
           |          |
           |          v
           |        +----------------+
           |        |       2.       |
           |        +----------------+
           |          |
           |          |
           |          v
           |        +----------------+     +----+
           |        |       3.       |     | 4. |
      +----+------> |  if(x == 0x0)  | --> |    |
      |    |        +----------------+     +----+
      |    |          |                      |
      |    |          |                      |
      |    |          v                      |
      |    |        +----------------+       |
      |    |        |       5.       |       |
      |    +------> |   return 0x1   |       |
      |             +----------------+       |
      |                                      |
      +--------------------------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(0, instructions=[Branch(Condition(OperationType.equal, [Constant(0), Constant(0)]))]),
            true := BasicBlock(1, instructions=[]),
            false := BasicBlock(2, instructions=[]),
            loop_branch := BasicBlock(3, instructions=[Branch(Condition(OperationType.equal, [Variable("x"), Constant(0)]))]),
            loop_body := BasicBlock(4, instructions=[]),
            end := BasicBlock(5, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(start, true),
            FalseCase(start, false),
            UnconditionalEdge(true, end),
            UnconditionalEdge(false, loop_branch),
            TrueCase(loop_branch, loop_body),
            FalseCase(loop_branch, end),
            UnconditionalEdge(loop_body, loop_branch),
        ]
    )
    run_dead_path_elimination(cfg)
    assert set(cfg.nodes) == {start, true, end}
    assert start.instructions == []
    assert [cfg.get_edge(start, true).condition_type, cfg.get_edge(true, end).condition_type] == [
        BasicBlockEdgeCondition.unconditional,
        BasicBlockEdgeCondition.unconditional,
    ]


def test_branch_block_remains():
    """
    Test that the block with the branch is not removed.

         +----+     +----------------+
         | 1. |     |       0.       |
         |    | <-- | if(0x0 == 0x0) |
         +----+     +----------------+
           |          |
           |          |
           |          v
           |        +----------------+
           |        |       2.       |
           |        +----------------+
           |          |
           |          |
           |          v
           |        +----------------+     +----+
           |        |       3.       |     | 4. |
      +----+------> |  if(x == 0x0)  | --> |    |
      |    |        +----------------+     +----+
      |    |          |                      |
      |    |          |                      |
      |    |          v                      |
      |    |        +----------------+       |
      |    |        |       5.       |       |
      |    +------> |   return 0x1   |       |
      |             +----------------+       |
      |                                      |
      +--------------------------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(0, instructions=[]),
            dead_branch_block := BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [Variable("x"), Variable("x")]))]),
            dead_loop_block := BasicBlock(2, instructions=[]),
            loop_branch_block := BasicBlock(3, instructions=[Branch(Condition(OperationType.less, [Variable("x"), Constant(2)]))]),
            end := BasicBlock(4, instructions=[Return([Variable("x")])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(start, dead_branch_block),
            TrueCase(dead_branch_block, dead_loop_block),
            UnconditionalEdge(dead_loop_block, dead_branch_block),
            TrueCase(dead_branch_block, loop_branch_block),
            FalseCase(loop_branch_block, dead_branch_block),
            TrueCase(loop_branch_block, end),
        ]
    )
    run_dead_path_elimination(cfg)
    assert set(cfg.nodes) == {start, dead_branch_block, loop_branch_block, end}
    assert dead_branch_block.instructions == []


def test_two_edges_one_node():
    """
    Test whether a block pointed to by two different dead edges is removed correctly.

         +------------+     +-------------+
         |     2.     |     |     0.      |
      +- | if(a != a) | <-- | if(a < 0xa) |
      |  +------------+     +-------------+
      |    |                  |
      |    |                  |
      |    |                  v
      |    |                +-------------+     +----+
      |    |                |     1.      |     | 4. |
      |    |                | if(a != a)  | --> |    |
      |    |                +-------------+     +----+
      |    |                  |                   |
      |    |                  |                   |
      |    |                  v                   |
      |    |                +-------------+       |
      |    +--------------> |     3.      |       |
      |                     +-------------+       |
      |                       |                   |
      |                       |                   |
      |                       v                   |
      |                     +-------------+       |
      |                     |     5.      |       |
      +-------------------> |  return a   | <-----+
                            +-------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            start := BasicBlock(0, instructions=[Branch(Condition(OperationType.less, [Variable("a"), Constant(10)]))]),
            dead_branch_block1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.not_equal, [Variable("a"), Variable("a")]))]),
            dead_branch_block2 := BasicBlock(2, instructions=[Branch(Condition(OperationType.not_equal, [Variable("a"), Variable("a")]))]),
            shared_block := BasicBlock(3),
            exclusive_block := BasicBlock(4),
            end := BasicBlock(5, instructions=[Return(ListOperation([Variable("a")]))]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(start, dead_branch_block1),
            FalseCase(start, dead_branch_block2),
            TrueCase(dead_branch_block1, shared_block),
            TrueCase(dead_branch_block2, shared_block),
            UnconditionalEdge(shared_block, end),
            FalseCase(dead_branch_block1, exclusive_block),
            FalseCase(dead_branch_block2, end),
            UnconditionalEdge(exclusive_block, end),
        ]
    )
    run_dead_path_elimination(cfg)
    assert list(cfg.nodes) == [start, dead_branch_block1, dead_branch_block2, exclusive_block, end]


def test_phi_function_gets_updated():
    """
    Simple case where the true branch is dead and Phi dependency of true branch gets removed.
    +----+     +----------------+
    |    |     |       0.       |
    | 2. |     |       a        |
    |    | <-- | if(0x0 == 0x1) |
    +----+     +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       1.       |
      |        |       b        |
      |        +----------------+
      |          |
      |          |
      |          v
      |        +----------------+
      |        |       3.       |
      |        |   x = ϕ(a,b)   |
      +------> |   return 0x1   |
               +----------------+
    """
    cfg = ControlFlowGraph()
    a = Variable("a")
    b = Variable("b")
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(
                0,
                instructions=[
                    assign_a := Assignment(a, Constant(0x42)),
                    Branch(Condition(OperationType.equal, [Constant(0), Constant(1)])),
                ],
            ),
            n1 := BasicBlock(1, instructions=[Assignment(b, Constant(0x1))]),
            n2 := BasicBlock(2, instructions=[]),
            n3 := BasicBlock(3, instructions=[phi := Phi(Variable("x"), [a, b]), Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            TrueCase(n0, n1),
            FalseCase(n0, n2),
            UnconditionalEdge(n1, n3),
            UnconditionalEdge(n2, n3),
        ]
    )
    origin_block = {n0: a, n1: b}
    phi.update_phi_function(origin_block)
    assert phi.origin_block == origin_block
    run_dead_path_elimination(cfg)
    assert phi.origin_block == {n0: a}
    assert set(cfg.nodes) == {n0, n2, n3}
    assert n0.instructions == [assign_a]
    assert isinstance(cfg.get_edge(n0, n2), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n2, n3), UnconditionalEdge)
