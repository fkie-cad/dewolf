from decompiler.pipeline.expressions.bitfieldcomparisonunrolling import BitFieldComparisonUnrolling
from decompiler.structures.graphs.basicblock import BasicBlock
from decompiler.structures.graphs.branches import FalseCase, TrueCase, UnconditionalEdge
from decompiler.structures.graphs.cfg import ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Branch, Comment, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType


class MockTask:
    def __init__(self, cfg: ControlFlowGraph):
        self.graph = cfg


def get_tf_successors(cfg: ControlFlowGraph, block: BasicBlock):
    match cfg.get_out_edges(block):
        case (TrueCase() as true_edge, FalseCase() as false_edge):
            pass
        case (FalseCase() as false_edge, TrueCase() as true_edge):
            pass
        case _:
            raise ValueError("Block does not have outgoing T/F edges.")
    return true_edge.sink, false_edge.sink


def test_unrolling_with_bitmask():
    """
    +-------------------+     +------------------------------------------------+
    |        2.         |     |                       0.                       |
    | /* other block */ |     | if((((0x1 << var) & 0xffffffff) & 0x7) == 0x0) |
    |    return 0x1     | <-- |                                                |
    +-------------------+     +------------------------------------------------+
                                |
                                |
                                v
                              +------------------------------------------------+
                              |                       1.                       |
                              |                /* case block */                |
                              |                   return 0x0                   |
                              +------------------------------------------------+
    """
    cfg = ControlFlowGraph()
    switch_var = Variable("var")
    bit_field = Constant(0b111)
    branch_subexpr = BinaryOperation(
        OperationType.bitwise_and,
        [
            BinaryOperation(
                OperationType.bitwise_and,
                [BinaryOperation(OperationType.left_shift, [Constant(value=1), switch_var]), Constant(0xFFFFFFFF)],
            ),
            bit_field,
        ],
    )
    branch = Branch(condition=Condition(OperationType.equal, [branch_subexpr, Constant(0x0)]))
    cfg.add_nodes_from(
        [
            block := BasicBlock(
                0,
                [branch],
            ),
            case_block := BasicBlock(1, [Comment("case block"), Return([Constant(0)])]),
            other_block := BasicBlock(2, [Comment("other block"), Return([Constant(1)])]),
        ]
    )
    cfg.add_edges_from([TrueCase(block, other_block), FalseCase(block, case_block)])
    task = MockTask(cfg)
    BitFieldComparisonUnrolling().run(task)
    assert len(block) == 0, "removing of branch instruction failed"
    block_out_edges = cfg.get_out_edges(block)
    assert len(block_out_edges) == 1
    assert isinstance(block_out_edges[0], UnconditionalEdge)
    successors = cfg.get_successors(block)
    assert len(successors) == 1
    target, s2 = get_tf_successors(cfg, successors[0])
    assert target == case_block
    target, s3 = get_tf_successors(cfg, s2)
    assert target == case_block
    target, other = get_tf_successors(cfg, s3)
    assert target == case_block
    assert other == other_block
