from dewolf.pipeline.preprocessing import RemoveStackCanary
from dewolf.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from dewolf.structures.pseudo.expressions import Constant, ImportedFunctionSymbol, Variable
from dewolf.structures.pseudo.instructions import Branch, Return
from dewolf.structures.pseudo.operations import Call, Condition, OperationType
from dewolf.task import DecompilerTask
from dewolf.util.options import Options


def _run_remove_stack_canary(cfg: ControlFlowGraph):
    options = Options()
    options.set("remove-stack-canary.remove_canary", True)
    RemoveStackCanary().run(DecompilerTask("test", cfg, options=options))


def test_trivial_no_change():
    """
    Simple case where nothing is changed.

               +-------------------+
               |        0.         |
               +-------------------+
                 |
                 |
                 v
    +----+     +-------------------+
    | 3. |     |        1.         |
    |    | <-- | if(canary == 0x0) |
    +----+     +-------------------+
                 |
                 |
                 v
               +-------------------+
               |        2.         |
               |    return 0x0     |
               +-------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[]),
            n1 := BasicBlock(1, instructions=[branch := Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[Return([Constant(0)])]),
            n3 := BasicBlock(3, instructions=[]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3)])
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {n0, n1, n2, n3}
    assert n1.instructions == [branch]
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n2), TrueCase)
    assert isinstance(cfg.get_edge(n1, n3), FalseCase)


def test_one_branch_to_stack_fail():

    """
    Check if one Branch to stack fail gets removed. Block 3 will be removed.

                               +-------------------+
                               |        0.         |
                               +-------------------+
                                 |
                                 |
                                 v
    +--------------------+     +-------------------+
    |         3.         |     |        1.         |
    | __stack_chk_fail() | <-- | if(canary == 0x0) |
    +--------------------+     +-------------------+
                                 |
                                 |
                                 v
                               +-------------------+
                               |        2.         |
                               |    return 0x0     |
                               +-------------------+

    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[Return([Constant(0)])]),
            n3 := BasicBlock(3, instructions=[Call(ImportedFunctionSymbol("__stack_chk_fail", 0), [])]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3)])
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {n0, n1, n2}
    assert n1.instructions == []
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n2), UnconditionalEdge)


def test_multiple_returns_multiple_stackchecks():
    """
    Test with multiple returns. Block 8 and 6 will be removed.

                                                          +-------------------+
                                                          |        0.         |
                                                          +-------------------+
                                                            |
                                                            |
                                                            v
    +--------------------+     +--------------------+     +-------------------+
    |         8.         |     |         3.         |     |        1.         |
    | __stack_chk_fail() | <-- | if(canary == 0x0)  | <-- |    if(a < 0x0)    | <+
    +--------------------+     +--------------------+     +-------------------+  |
                                 |                          |                    |
                                 |                          |                    |
                                 v                          v                    |
                               +--------------------+     +-------------------+  |
                               |         7.         |     |        2.         |  |
                               |     return 0x1     |     |    if(b < 0x1)    | -+
                               +--------------------+     +-------------------+
                                                            |
                                                            |
                                                            v
                               +--------------------+     +-------------------+
                               |         6.         |     |        4.         |
                               | __stack_chk_fail() | <-- | if(canary == 0x0) |
                               +--------------------+     +-------------------+
                                                            |
                                                            |
                                                            v
                                                          +-------------------+
                                                          |        5.         |
                                                          |    return 0x0     |
                                                          +-------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [Variable("a"), Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [Variable("b"), Constant(0x1)]))]),
            n3 := BasicBlock(3, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n4 := BasicBlock(4, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n5 := BasicBlock(5, instructions=[Return([Constant(0)])]),
            n6 := BasicBlock(6, instructions=[Call(ImportedFunctionSymbol("__stack_chk_fail", 0), [])]),
            n7 := BasicBlock(7, instructions=[Return([Constant(1)])]),
            n8 := BasicBlock(8, instructions=[Call(ImportedFunctionSymbol("__stack_chk_fail", 0), [])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            TrueCase(n1, n2),
            FalseCase(n1, n3),
            TrueCase(n2, n1),
            FalseCase(n2, n4),
            TrueCase(n3, n7),
            FalseCase(n3, n8),
            TrueCase(n4, n6),
            FalseCase(n4, n5),
        ]
    )
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {n0, n1, n2, n3, n4, n5, n7}
    assert n3.instructions == []
    assert n4.instructions == []
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n2), TrueCase)
    assert isinstance(cfg.get_edge(n1, n3), FalseCase)
    assert isinstance(cfg.get_edge(n2, n1), TrueCase)
    assert isinstance(cfg.get_edge(n2, n4), FalseCase)
    assert isinstance(cfg.get_edge(n3, n7), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n4, n5), UnconditionalEdge)


def test_multiple_returns_one_stackcheck():
    """
    Test with multiple returns that each share a branch to __stack_chk_fail (does this even happen?).
    Block 6 will be removed.
                                                  +-------------------+
                                                  |        0.         |
                                                  +-------------------+
                                                    |
                                                    |
                                                    v
    +------------+     +--------------------+     +-------------------+
    |     7.     |     |         3.         |     |        1.         |
    | return 0x1 | <-- | if(canary == 0x0)  | <-- |    if(a < 0x0)    | <+
    +------------+     +--------------------+     +-------------------+  |
                         |                          |                    |
                         |                          |                    |
                         v                          v                    |
                       +--------------------+     +-------------------+  |
                       |         6.         |     |        2.         |  |
                       | __stack_chk_fail() |     |    if(b < 0x1)    | -+
                       +--------------------+     +-------------------+
                         ^                          |
                         |                          |
                         |                          v
                         |                        +-------------------+
                         |                        |        4.         |
                         +----------------------- | if(canary == 0x0) |
                                                  +-------------------+
                                                    |
                                                    |
                                                    v
                                                  +-------------------+
                                                  |        5.         |
                                                  |    return 0x0     |
                                                  +-------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.less, [Variable("a"), Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[Branch(Condition(OperationType.less, [Variable("b"), Constant(0x1)]))]),
            n3 := BasicBlock(3, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n4 := BasicBlock(4, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n5 := BasicBlock(5, instructions=[Return([Constant(0)])]),
            n6 := BasicBlock(6, instructions=[Call(ImportedFunctionSymbol("__stack_chk_fail", 0), [])]),
            n7 := BasicBlock(7, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            TrueCase(n1, n2),
            FalseCase(n1, n3),
            TrueCase(n2, n1),
            FalseCase(n2, n4),
            TrueCase(n3, n7),
            FalseCase(n3, n6),
            TrueCase(n4, n6),
            FalseCase(n4, n5),
        ]
    )
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {n0, n1, n2, n3, n4, n5, n7}
    assert n3.instructions == []
    assert n4.instructions == []
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n2), TrueCase)
    assert isinstance(cfg.get_edge(n1, n3), FalseCase)
    assert isinstance(cfg.get_edge(n2, n1), TrueCase)
    assert isinstance(cfg.get_edge(n2, n4), FalseCase)
    assert isinstance(cfg.get_edge(n3, n7), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n4, n5), UnconditionalEdge)
