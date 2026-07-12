from decompiler.pipeline.preprocessing import RemoveSEHExceptionList
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.structures.pseudo.operations import OperationType, UnaryOperation
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def _run(cfg: ControlFlowGraph, enabled: bool = True):
    options = Options()
    options.set("remove-seh-exception-list.remove_seh", enabled)
    RemoveSEHExceptionList().run(DecompilerTask(name="test", function_identifier="", cfg=cfg, options=options))


def _seh_block() -> tuple[ControlFlowGraph, BasicBlock]:
    """A block mirroring the lifted SEH prologue: read ExceptionList, then install a new head."""
    exception_list = Variable("ExceptionList", ssa_label=0)
    local = Variable("local_10", ssa_label=0)
    other = Variable("x", ssa_label=0)
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            block := BasicBlock(
                0,
                instructions=[
                    Assignment(local, exception_list),  # local_10 = ExceptionList   (read)
                    Assignment(exception_list, UnaryOperation(OperationType.address, [local])),  # ExceptionList = &local_10 (write)
                    Assignment(other, Constant(5)),  # unrelated -> kept unchanged
                ],
            )
        ]
    )
    return cfg, block


def test_removes_write_and_neutralizes_read():
    cfg, block = _seh_block()
    _run(cfg)
    # the write to ExceptionList is dropped; the read is neutralized; the unrelated instruction stays
    assert len(block.instructions) == 2
    assert all("ExceptionList" not in str(instruction) for instruction in block.instructions)
    # the reader keeps a definition (its ExceptionList source replaced by 0), so it is not left undefined
    assert block.instructions[0].definitions == [Variable("local_10", ssa_label=0)]
    assert isinstance(block.instructions[0].value, Constant)
    assert str(block.instructions[1]) == "x#0 = 0x5"


def test_disabled_option_keeps_everything():
    cfg, block = _seh_block()
    _run(cfg, enabled=False)
    assert len(block.instructions) == 3
    assert any("ExceptionList" in str(instruction) for instruction in block.instructions)
