from decompiler.pipeline.preprocessing import RemoveStackCanary
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo.expressions import Constant, ImportedFunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Branch, Return
from decompiler.structures.pseudo.operations import Call, Condition, ListOperation, OperationType
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def _run_remove_stack_canary(cfg: ControlFlowGraph):
    options = Options()
    options.set("remove-stack-canary.remove_canary", True)
    RemoveStackCanary().run(DecompilerTask(name="test", function_identifier="", cfg=cfg, options=options))


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


def test_no_change_to_single_block_function():
    """
    +--------------------+
    |         0.         |
    | __stack_chk_fail() |
    +--------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            b := BasicBlock(0, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
        ]
    )
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {b}


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
            n3 := BasicBlock(3, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
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
            n6 := BasicBlock(6, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
            n7 := BasicBlock(7, instructions=[Return([Constant(1)])]),
            n8 := BasicBlock(8, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
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
            n6 := BasicBlock(6, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
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


def test_one_branch_single_empty_block_between_stack_fail():
    """
    Check if one Branch to stack fail gets removed.
    One empty block between __stack_chk_fail, should be removed as well.
                        +--------------------+
                        |         0.         |
                        +--------------------+
                            |
                            |
                            v
        +------------+     +--------------------+
        |     2.     |     |         1.         |
        | return 0x0 | <-- | if(canary == 0x0)  |
        +------------+     +--------------------+
                            |
                            |
                            v
                        +--------------------+
                        |         3.         |
                        +--------------------+
                            |
                            |
                            v
                        +--------------------+
                        |         4.         |
                        | __stack_chk_fail() |
                        +--------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[Return([Constant(0)])]),
            n3 := BasicBlock(3, instructions=[]),
            n4 := BasicBlock(4, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3), UnconditionalEdge(n3, n4)])
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {n0, n1, n2}
    assert n1.instructions == []
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n2), UnconditionalEdge)


def test_single_branch_multiple_empty_blocks_between_stack_fail():
    """
    Check if one Branch to stack fail gets removed.
    Multiple empty blocks in the __stack_chk_fail branch should all be removed.
                        +--------------------+
                        |         0.         |
                        +--------------------+
                            |
                            |
                            v
        +------------+     +--------------------+
        |     2.     |     |         1.         |
        | return 0x0 | <-- | if(canary == 0x0)  |
        +------------+     +--------------------+
                            |
                            |
                            v
                        +--------------------+
                        |         3.         |
                        +--------------------+
                            |
                            |
                            v
                        +--------------------+
                        |         4.         |
                        +--------------------+
                            |
                            |
                            v
                        +--------------------+
                        |         5.         |
                        | __stack_chk_fail() |
                        +--------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[Return([Constant(0)])]),
            n3 := BasicBlock(3, instructions=[]),
            n4 := BasicBlock(4, instructions=[]),
            n5 := BasicBlock(5, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
        ]
    )
    cfg.add_edges_from(
        [UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3), UnconditionalEdge(n3, n4), UnconditionalEdge(n4, n5)]
    )
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {n0, n1, n2}
    assert n1.instructions == []
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n2), UnconditionalEdge)


def test_one_branch_single_non_empty_block_between_stack_fail():
    """
    Check if cfg error will be detected.
    One block between __stack_chk_fail is not empty, should not be removed, should trigger runtimeError.
                        +--------------------+
                        |         0.         |
                        +--------------------+
                            |
                            |
                            v
        +------------+     +--------------------+
        |     2.     |     |         1.         |
        | return 0x0 | <-- | if(canary == 0x0)  |
        +------------+     +--------------------+
                            |
                            |
                            v
                        +--------------------+
                        |         3.         |
                        |     x_0 = 0x5      |
                        +--------------------+
                            |
                            |
                            v
                        +--------------------+
                        |         4.         |
                        | __stack_chk_fail() |
                        +--------------------+
    """
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            n0 := BasicBlock(0, instructions=[]),
            n1 := BasicBlock(1, instructions=[Branch(Condition(OperationType.equal, [Variable("canary"), Constant(0x0)]))]),
            n2 := BasicBlock(2, instructions=[Return([Constant(0)])]),
            n3 := BasicBlock(3, instructions=[Assignment(Variable("x_0"), Constant(5))]),
            n4 := BasicBlock(4, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
        ]
    )
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n2), FalseCase(n1, n3), UnconditionalEdge(n3, n4)])
    error = False
    try:
        _run_remove_stack_canary(cfg)
    except RuntimeError as e:
        if "did not expect to reach canary check this way" == f"{e}":
            error = True
    assert error is True


def test_multiple_returns_multiple_empty_blocks_one_stackcheck():
    """
    Test with multiple returns that each share a branch to __stack_chk_fail (does this even happen?).
    There are multiple empty blocks (2/1) between the two paths, should all be removed with the __stack_chk_fail.
                                                    +--------------------+
                                                    |         0.         |
                                                    +--------------------+
                                                    |
                                                    |
                                                    v
        +------------+     +-------------------+     +--------------------+
        |    10.     |     |        3.         |     |         1.         |
        | return 0x1 | <-- | if(canary == 0x0) | <-- |    if(a < 0x0)     | <+
        +------------+     +-------------------+     +--------------------+  |
                            |                         |                     |
                            |                         |                     |
                            v                         v                     |
                        +-------------------+     +--------------------+  |
                        |        6.         |     |         2.         |  |
                        |                   |     |    if(b < 0x1)     | -+
                        +-------------------+     +--------------------+
                            |                         |
                            |                         |
                            v                         v
                        +-------------------+     +--------------------+     +------------+
                        |        7.         |     |         4.         |     |     5.     |
                        |                   |     | if(canary == 0x0)  | --> | return 0x0 |
                        +-------------------+     +--------------------+     +------------+
                            |                         |
                            |                         |
                            |                         v
                            |                       +--------------------+
                            |                       |         8.         |
                            |                       +--------------------+
                            |                         |
                            |                         |
                            |                         v
                            |                       +--------------------+
                            |                       |         9.         |
                            +---------------------> | __stack_chk_fail() |
                                                    +--------------------+
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
            n6 := BasicBlock(6, instructions=[]),
            n7 := BasicBlock(7, instructions=[]),
            n8 := BasicBlock(8, instructions=[]),
            n9 := BasicBlock(9, instructions=[Assignment(ListOperation([]), Call(ImportedFunctionSymbol("__stack_chk_fail", 0), []))]),
            n10 := BasicBlock(10, instructions=[Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            TrueCase(n1, n2),
            FalseCase(n1, n3),
            TrueCase(n2, n1),
            FalseCase(n2, n4),
            TrueCase(n3, n10),
            FalseCase(n3, n6),
            UnconditionalEdge(n6, n7),
            UnconditionalEdge(n7, n9),
            TrueCase(n4, n8),
            UnconditionalEdge(n8, n9),
            FalseCase(n4, n5),
        ]
    )
    _run_remove_stack_canary(cfg)
    assert set(cfg) == {n0, n1, n2, n3, n4, n5, n10}
    assert n3.instructions == []
    assert n4.instructions == []
    assert isinstance(cfg.get_edge(n0, n1), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n1, n2), TrueCase)
    assert isinstance(cfg.get_edge(n1, n3), FalseCase)
    assert isinstance(cfg.get_edge(n2, n1), TrueCase)
    assert isinstance(cfg.get_edge(n2, n4), FalseCase)
    assert isinstance(cfg.get_edge(n3, n10), UnconditionalEdge)
    assert isinstance(cfg.get_edge(n4, n5), UnconditionalEdge)
