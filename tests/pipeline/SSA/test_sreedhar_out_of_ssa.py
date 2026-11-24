"""Regression tests for the Sreedhar out-of-SSA translation."""

from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation, SSAOptions
from decompiler.structures.graphs.branches import FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo import (
    Assignment,
    BinaryOperation,
    Branch,
    Condition,
    Constant,
    Integer,
    OperationType,
    Phi,
    Return,
    Variable,
)

from tests.pipeline.SSA.utils_out_of_ssa_tests import decompiler_task

INT = Integer.int32_t()


def _var(name: str, label: int) -> Variable:
    return Variable(name, INT, ssa_label=label)


def _phi(destination: Variable, origins: list) -> Phi:
    phi = Phi(destination, [value for _, value in origins])
    phi.update_phi_function({block: value for block, value in origins})
    return phi


def _cfg_with_copy_into_predecessor_ending_in_branch() -> tuple[ControlFlowGraph, list[Variable]]:
    """
    0: c#1 = p + 0; x#1 = q + 1; if (r < 5) -> 1 else 2
    1: if (c#1 == 0) -> 3 else 4
    2: -> 3
    3: y#1 = phi(x#1 from 1, c#1 from 2); return y#1
    4: return 7
    """
    p, q, r = _var("p", 0), _var("q", 0), _var("r", 0)
    c1, x1, y1 = _var("c", 1), _var("x", 1), _var("y", 1)
    blocks = [BasicBlock(i, []) for i in range(5)]
    blocks[0].instructions = [
        Assignment(c1, BinaryOperation(OperationType.plus, [p, Constant(0, INT)])),
        Assignment(x1, BinaryOperation(OperationType.plus, [q, Constant(1, INT)])),
        Branch(Condition(OperationType.less, [r, Constant(5, INT)])),
    ]
    blocks[1].instructions = [Branch(Condition(OperationType.equal, [c1, Constant(0, INT)]))]
    blocks[3].instructions = [_phi(y1, [(blocks[1], x1), (blocks[2], c1)]), Return([y1])]
    blocks[4].instructions = [Return([Constant(7, INT)])]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(blocks)
    cfg.add_edges_from(
        [
            TrueCase(blocks[0], blocks[1]),
            FalseCase(blocks[0], blocks[2]),
            TrueCase(blocks[1], blocks[3]),
            FalseCase(blocks[1], blocks[4]),
            UnconditionalEdge(blocks[2], blocks[3]),
        ]
    )
    cfg.root = blocks[0]
    return cfg, [p, q, r]


def test_copy_into_predecessor_with_successor_without_phis():
    """The copy for x#1 goes into block 1, whose successor 4 has no Phi; looking that block up must not change the
    Phi map while it is iterated (RuntimeError: dictionary changed size during iteration).
    """
    cfg, parameters = _cfg_with_copy_into_predecessor_ending_in_branch()

    OutOfSsaTranslation().run(decompiler_task(cfg, SSAOptions.sreedhar, parameters))

    assert not any(isinstance(instruction, Phi) for instruction in cfg.instructions)


def test_copy_before_branch_does_not_overwrite_branch_operand():
    """The copy for x#1 is placed before the branch in block 1, which reads c#1. Interference only used LiveOut of
    block 1, which lacks c#1, so c and the copy target were coalesced and the copy overwrote c before the branch.
    """
    cfg, parameters = _cfg_with_copy_into_predecessor_ending_in_branch()
    block_0, block_1 = (next(node for node in cfg.nodes if node.name == name) for name in (0, 1))

    OutOfSsaTranslation().run(decompiler_task(cfg, SSAOptions.sreedhar, parameters))

    *copies, branch = block_1.instructions
    assert isinstance(branch, Branch)
    assert not any(set(copy.definitions) & set(branch.requirements) for copy in copies)
    assert block_0.instructions[0].destination in branch.requirements


def _cfg_with_equal_constants_in_phi(copy_phi: bool) -> ControlFlowGraph:
    """
    0: if (p < 1) -> 1 else 5 ; 5: if (q < 1) -> 2 else 4
    1: -> 3 ; 2: -> 3 ; 4: y#1 = q + 10 -> 3
    3: x#1 = phi(c from 1, c from 2, y#1 from 4); return x#1   (c is one Constant object)
    """
    p, q, x1, y1 = _var("p", 0), _var("q", 0), _var("x", 1), _var("y", 1)
    c = Constant(4, INT)
    blocks = {i: BasicBlock(i, []) for i in (0, 5, 1, 2, 4, 3)}
    blocks[0].instructions = [Branch(Condition(OperationType.less, [p, Constant(1, INT)]))]
    blocks[5].instructions = [Branch(Condition(OperationType.less, [q, Constant(1, INT)]))]
    blocks[4].instructions = [Assignment(y1, BinaryOperation(OperationType.plus, [q, Constant(10, INT)]))]
    phi = _phi(x1, [(blocks[1], c), (blocks[2], c), (blocks[4], y1)])
    blocks[3].instructions = [phi.copy() if copy_phi else phi, Return([x1])]
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(blocks.values())
    cfg.add_edges_from(
        [
            TrueCase(blocks[0], blocks[1]),
            FalseCase(blocks[0], blocks[5]),
            TrueCase(blocks[5], blocks[2]),
            FalseCase(blocks[5], blocks[4]),
            UnconditionalEdge(blocks[1], blocks[3]),
            UnconditionalEdge(blocks[2], blocks[3]),
            UnconditionalEdge(blocks[4], blocks[3]),
        ]
    )
    cfg.root = blocks[0]
    return cfg


def _assert_every_path_defines_returned_variable(copy_phi: bool):
    cfg = _cfg_with_equal_constants_in_phi(copy_phi)
    blocks = {node.name: node for node in cfg.nodes}

    OutOfSsaTranslation().run(decompiler_task(cfg, SSAOptions.sreedhar, [_var("p", 0), _var("q", 0)]))

    assert not any(isinstance(instruction, Phi) for instruction in cfg.instructions)
    returned = blocks[3].instructions[-1].values[0]
    for name in (1, 2, 4):
        last = blocks[name].instructions[-1]
        assert isinstance(last, Assignment) and last.destination == returned


def test_phi_with_same_constant_object_on_two_edges():
    _assert_every_path_defines_returned_variable(copy_phi=False)


def test_phi_with_equal_constants_after_phi_copy():
    _assert_every_path_defines_returned_variable(copy_phi=True)
