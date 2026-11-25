"""Pytest for the Boissinot et al. Out of SSA."""

from collections import defaultdict

import pytest

from decompiler.pipeline.ssa.boissinot import Boissinot
from decompiler.pipeline.ssa.parallel_spaces import COPY_SUFFIX, ParallelSpaces
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.pseudo import Assignment, BinaryOperation, Branch, Condition, Constant, Integer, OperationType, Phi, Relation, Return, Variable

from tests.pipeline.SSA.utils_out_of_ssa_tests import decompiler_task


def test_parameter_class_keeps_parameter_name():
    """The variable class containing a function parameter must be renamed to the parameter name.
    Each class was returned once per member, so it was renamed several times and ended up as a__4 instead of a.
    +------------------+     +------------------+
    |        0.        |     |        0.        |
    +------------------+     +------------------+
      |                        |
      v                        v
    +------------------+     +------------------+
    |        1.        |     |        1.        |
    | a#1 = ϕ(a#0,a#2) |     | a = a + 1        |
    | a#2 = a#1 + 1    |     | if(a < 10)       |
    | if(a#2 < 10)     |     +------------------+
    +------------------+       |
      |                        v
      v                      +------------------+
    +------------------+     |        2.        |
    |        2.        |     | return a         |
    | return a#2       |     +------------------+
    +------------------+
    """

    def var(label=None):
        return Variable("a", Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [])
    n1 = BasicBlock(
        1,
        [
            Phi(var(1), [var(0), var(2)]),
            Assignment(var(2), BinaryOperation(OperationType.plus, [var(1), Constant(1)])),
            Branch(Condition(OperationType.less, [var(2), Constant(10)])),
        ],
    )
    n2 = BasicBlock(2, [Return([var(2)])])
    n1.instructions[0]._origin_block = {n0: var(0), n1: var(2)}
    cfg.add_nodes_from([n0, n1, n2])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)])

    OutOfSsaTranslation().run(decompiler_task(cfg, "boissinot", [var(0)]))

    assert n0.instructions == []
    assert n1.instructions == [
        Assignment(var(), BinaryOperation(OperationType.plus, [var(), Constant(1)])),
        Branch(Condition(OperationType.less, [var(), Constant(10)])),
    ]
    assert n2.instructions == [Return([var()])]


def test_parameter_class_name_not_taken_by_other_class():
    """The class containing a parameter must get the parameter name even if another class with the same variable name comes first.
    Names were handed out first-come, so the loop class took a and the parameter class became a__0, which is never defined.
    +------------------+     +------------------+
    |        0.        |     |        0.        |
    | a#1 = 5          |     | a__0 = 5         |
    +------------------+     +------------------+
      |                        |
      v                        v
    +------------------+     +------------------+
    |        1.        |     |        1.        |
    | a#2 = ϕ(a#1,a#3) |     | a__0 = a__0 + a  |
    | a#3 = a#2 + a#0  |     | if(a__0 < 10)    |
    | if(a#3 < 10)     |     +------------------+
    +------------------+       |
      |                        v
      v                      +------------------+
    +------------------+     |        2.        |
    |        2.        |     | return a__0 + a  |
    | return a#3 + a#0 |     +------------------+
    +------------------+
    """

    def var(label=None, name="a"):
        return Variable(name, Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [Assignment(var(1), Constant(5))])
    n1 = BasicBlock(
        1,
        [
            Phi(var(2), [var(1), var(3)]),
            Assignment(var(3), BinaryOperation(OperationType.plus, [var(2), var(0)])),
            Branch(Condition(OperationType.less, [var(3), Constant(10)])),
        ],
    )
    n2 = BasicBlock(2, [Return([BinaryOperation(OperationType.plus, [var(3), var(0)])])])
    n1.instructions[0]._origin_block = {n0: var(1), n1: var(3)}
    cfg.add_nodes_from([n0, n1, n2])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)])

    OutOfSsaTranslation().run(decompiler_task(cfg, "boissinot", [var(0)]))

    loop = var(name="a__0")
    assert n0.instructions == [Assignment(loop, Constant(5))]
    assert n1.instructions == [
        Assignment(loop, BinaryOperation(OperationType.plus, [loop, var()])),
        Branch(Condition(OperationType.less, [loop, Constant(10)])),
    ]
    assert n2.instructions == [Return([BinaryOperation(OperationType.plus, [loop, var()])])]


def test_errors_are_not_swallowed(monkeypatch):
    """Errors in a translation step must propagate, perform() used to print them and leave the CFG half translated."""

    def var(label=None):
        return Variable("a", Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [])
    n1 = BasicBlock(
        1,
        [
            Phi(var(1), [var(0), var(2)]),
            Assignment(var(2), BinaryOperation(OperationType.plus, [var(1), Constant(1)])),
            Branch(Condition(OperationType.less, [var(2), Constant(10)])),
        ],
    )
    n2 = BasicBlock(2, [Return([var(2)])])
    n1.instructions[0]._origin_block = {n0: var(0), n1: var(2)}
    cfg.add_nodes_from([n0, n1, n2])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)])

    def fail(self):
        raise RuntimeError("step failed")

    monkeypatch.setattr(Boissinot, "_coalesce_and_rename", fail)

    with pytest.raises(RuntimeError, match="step failed"):
        OutOfSsaTranslation().run(decompiler_task(cfg, "boissinot", [var(0)]))


def test_parallel_copy_destinations_interfere():
    """The phi arguments are live-out of their predecessor as in the paper, so the copies of one parallel copy interfere.
    +------------------+
    |        0.        |
    | x#0 = 0x1        |
    | y#0 = 0x2        |
    +------------------+
      |
      v
    +------------------+  true
    |        1.        | -----+
    | x#1 = ϕ(x#0,y#1) |      |
    | y#1 = ϕ(y#0,x#1) |      |
    | if(x#1 < 0xa)    | <----+
    +------------------+
      | false
      v
    +------------------+
    |        2.        |
    | return x#1 - y#1 |
    +------------------+
    """

    def var(name, label=None):
        return Variable(name, Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [Assignment(var("x", 0), Constant(1)), Assignment(var("y", 0), Constant(2))])
    n1 = BasicBlock(
        1,
        [
            Phi(var("x", 1), [var("x", 0), var("y", 1)]),
            Phi(var("y", 1), [var("y", 0), var("x", 1)]),
            Branch(Condition(OperationType.less, [var("x", 1), Constant(10)])),
        ],
    )
    n2 = BasicBlock(2, [Return([BinaryOperation(OperationType.minus, [var("x", 1), var("y", 1)])])])
    n1.instructions[0]._origin_block = {n0: var("x", 0), n1: var("y", 1)}
    n1.instructions[1]._origin_block = {n0: var("y", 0), n1: var("x", 1)}
    cfg.add_nodes_from([n0, n1, n2])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2)])

    task = decompiler_task(cfg, "boissinot", [])
    boissinot = Boissinot(task, defaultdict(list, {n1: n1.instructions[:2]}))
    boissinot._to_cssa()
    boissinot._build_interference_graph()

    spaces = boissinot._parallel_spaces._block_spaces_of
    latch_address = next(address for address in spaces if address not in (0, 1, 2))
    graph = boissinot._interference_graph
    for address in (0, latch_address):
        destinations = [assignment.destination for assignment in spaces[address].end_of_block_assigns]
        assert len(destinations) == 2 and graph.are_interfering(*destinations)
    latch_destinations = [assignment.destination for assignment in spaces[latch_address].end_of_block_assigns]
    assert not graph.are_interfering(latch_destinations[0], var("x", 0))
    assert not graph.are_interfering(latch_destinations[1], var("y", 0))


def test_unreachable_predecessor():
    """A phi argument that comes from a block unreachable from the root must not break the search for back edges.
    +------------------+
    |        0.        |
    | x#1 = a#0        |
    +------------------+      +---------------------+
      |                       |         9.          |
      |                       +---------------------+
      |                         |
      v                         v
    +---------------------------------+  true
    |               1.                | -----+
    | x#2 = ϕ(x#1,x#3,0x5)            |      |
    | x#3 = x#2 + 0x1                 |      |
    | if(x#3 < 0x5)                   | <----+
    +---------------------------------+
      | false
      v
    +------------------+
    |        2.        |
    | return x#2       |
    +------------------+
    The immediate dominators have no entry for block 9, so looking up its dominator raised a KeyError.
    """

    def var(name, label=None):
        return Variable(name, Integer.int32_t(), ssa_label=label)

    cfg = ControlFlowGraph()
    n0 = BasicBlock(0, [Assignment(var("x", 1), var("a", 0))])
    n9 = BasicBlock(9, [])
    phi = Phi(var("x", 2), [var("x", 1), var("x", 3), Constant(5)])
    n1 = BasicBlock(
        1,
        [
            phi,
            Assignment(var("x", 3), BinaryOperation(OperationType.plus, [var("x", 2), Constant(1)])),
            Branch(Condition(OperationType.less, [var("x", 3), Constant(5)])),
        ],
    )
    n2 = BasicBlock(2, [Return([var("x", 2)])])
    phi._origin_block = {n0: var("x", 1), n1: var("x", 3), n9: Constant(5)}
    cfg.add_nodes_from([n0, n1, n2, n9])
    cfg.root = n0
    cfg.add_edges_from([UnconditionalEdge(n0, n1), TrueCase(n1, n1), FalseCase(n1, n2), UnconditionalEdge(n9, n1)])

    OutOfSsaTranslation().run(decompiler_task(cfg, "boissinot", [var("a", 0)]))

    latch = next(node for node in cfg.nodes if node not in (n0, n1, n2, n9))
    assert latch.address == -1
    assert n0.instructions == []
    assert n1.instructions == [
        Assignment(var("x"), BinaryOperation(OperationType.plus, [var("a"), Constant(1)])),
        Branch(Condition(OperationType.less, [var("x"), Constant(5)])),
    ]
    assert n2.instructions == [Return([var("a")])]
    assert n9.instructions == [Assignment(var("a"), Constant(5))]
    assert latch.instructions == [Assignment(var("a"), var("x"))]


def _loop_depths_of(cfg):
    """Returns the loop nesting depths that Boissinot computes for the given cfg."""
    boissinot = Boissinot(decompiler_task(cfg, "boissinot", []), defaultdict(list))
    boissinot._cfg_copy = cfg
    return boissinot._loop_depths(), boissinot._get_basic_blocks_by_loop_depth()


def test_loop_depth_self_loop_ignores_blocks_before_the_loop():
    """B0 -> B1 -> B2 -> B3 where B2 loops on itself, only B2 is in a loop."""
    cfg = ControlFlowGraph()
    n0, n1, n2, n3 = (BasicBlock(i, []) for i in range(4))
    cfg.add_nodes_from([n0, n1, n2, n3])
    cfg.add_edges_from([UnconditionalEdge(n0, n1), UnconditionalEdge(n1, n2), TrueCase(n2, n2), FalseCase(n2, n3)])

    depths, order = _loop_depths_of(cfg)

    assert depths == {n0: 0, n1: 0, n2: 1, n3: 0}
    assert order == [n2, n0, n1, n3]


def test_loop_depth_several_back_edges_count_once():
    """The loop header B1 has two back edges (one from a continue), the loop body is at depth 1 not 2.
    B0 -> B1 -> B2 -> B3 -> B1, B2 -> B1, B1 -> B4
    """
    cfg = ControlFlowGraph()
    n0, n1, n2, n3, n4 = (BasicBlock(i, []) for i in range(5))
    cfg.add_nodes_from([n0, n1, n2, n3, n4])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            TrueCase(n1, n2),
            FalseCase(n1, n4),
            TrueCase(n2, n1),
            FalseCase(n2, n3),
            UnconditionalEdge(n3, n1),
        ]
    )

    depths, _ = _loop_depths_of(cfg)

    assert depths == {n0: 0, n1: 1, n2: 1, n3: 1, n4: 0}


def test_loop_depth_nested_loops():
    """The inner loop B2 -> B3 -> B2 lies in the outer loop B1 -> B2 -> B3 -> B4 -> B1, so B2 and B3 are at depth 2."""
    cfg = ControlFlowGraph()
    n0, n1, n2, n3, n4, n5 = (BasicBlock(i, []) for i in range(6))
    cfg.add_nodes_from([n0, n1, n2, n3, n4, n5])
    cfg.add_edges_from(
        [
            UnconditionalEdge(n0, n1),
            TrueCase(n1, n2),
            FalseCase(n1, n5),
            UnconditionalEdge(n2, n3),
            TrueCase(n3, n2),
            FalseCase(n3, n4),
            UnconditionalEdge(n4, n1),
        ]
    )

    depths, order = _loop_depths_of(cfg)

    assert depths == {n0: 0, n1: 1, n2: 2, n3: 2, n4: 1, n5: 0}
    assert order[:2] == [n2, n3]


def _copy_sharing_classes(second_use_after_b_dies):
    """Returns the variable classes of a block with the copies b = a and c = a of the parameter a.
    The relation z = a puts z into the class of a, and z is live while b and c are, so b and c cannot join the class of a.
    Only the copy sharing pass can merge b and c.
    """

    def var(name):
        return Variable(name, Integer.int32_t(), ssa_label=0)

    a, b, c, d, z = var("a"), var("b"), var("c"), var("d"), var("z")
    if second_use_after_b_dies:  # b = a; d = b + 1; c = a; return c + d + z
        instructions = [
            Relation(z, a),
            Assignment(b, a),
            Assignment(d, BinaryOperation(OperationType.plus, [b, Constant(1)])),
            Assignment(c, a),
            Return([BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.plus, [c, d]), z])]),
        ]
    else:  # b = a; c = a; return b + c + z
        instructions = [
            Relation(z, a),
            Assignment(b, a),
            Assignment(c, a),
            Return([BinaryOperation(OperationType.plus, [BinaryOperation(OperationType.plus, [b, c]), z])]),
        ]
    cfg = ControlFlowGraph()
    n0, n1 = BasicBlock(0, []), BasicBlock(1, instructions)  # the dominator tree of a single block is empty, the value classes need two
    cfg.add_nodes_from([n0, n1])
    cfg.add_edge(UnconditionalEdge(n0, n1))

    boissinot = Boissinot(decompiler_task(cfg, "boissinot", [a]), defaultdict(list))
    boissinot._to_cssa()
    boissinot._build_interference_graph()
    classes = boissinot._construct_variable_classes()
    return {v.name: next(set(cls) for cls in classes if v in cls) for v in (a, b, c)}, var


def test_copy_sharing_merges_copies_with_intersecting_live_ranges_inside_a_block():
    """b = a; c = a; return b + c + z. b and c are live at the same time, but neither is live-out of a block, so the copy sharing pass must merge them."""
    classes, var = _copy_sharing_classes(second_use_after_b_dies=False)

    assert classes["b"] == classes["c"] == {var("b"), var("c")}
    assert classes["a"] == {var("a"), var("z")}


def test_copy_sharing_keeps_copies_with_disjoint_live_ranges_apart():
    """b = a; d = b + 1; c = a; return c + d + z. b is dead when c is defined, so the live ranges of b and c do not intersect."""
    classes, var = _copy_sharing_classes(second_use_after_b_dies=True)

    assert classes["b"] == {var("b")}
    assert classes["c"] == {var("c")}


def test_temporary_of_copy_cycle_avoids_used_names():
    """The swap x, y = y, x needs a temporary. Its default name x__copy__ is already used, so it gets a number."""
    x, y = Variable("x", Integer.int32_t()), Variable("y", Integer.int32_t())
    used = Variable(f"x{COPY_SUFFIX}", Integer.int32_t())
    block = BasicBlock(0, [Assignment(used, Constant(1)), Return([used])])
    cfg = ControlFlowGraph()
    cfg.add_node(block)
    spaces = ParallelSpaces({})
    spaces.add_end_of_block_assign(0, Assignment(y, x))
    spaces.add_end_of_block_assign(0, Assignment(x, y))  # the cycle is broken at the last destination, x

    spaces.sequentialize(cfg)
    spaces.insert_into_cfg(cfg)

    temporary = Variable(f"x{COPY_SUFFIX}1", Integer.int32_t())
    assert [str(instruction) for instruction in block.instructions[2:]] == [f"{temporary} = x", "x = y", f"y = {temporary}"]
