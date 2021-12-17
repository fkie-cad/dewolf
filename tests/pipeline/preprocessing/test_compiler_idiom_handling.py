from dewolf.pipeline.preprocessing import CompilerIdiomHandling
from dewolf.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from dewolf.structures.pseudo.expressions import Constant, Tag, Variable
from dewolf.structures.pseudo.instructions import Assignment
from dewolf.structures.pseudo.operations import BinaryOperation, OperationType
from dewolf.structures.pseudo.typing import Integer


class MockTask:
    def __init__(self, cfg: ControlFlowGraph):
        self.graph = cfg


def test_instructions_without_tags():
    """
    In this example, none of the instructions are tagged.
    The stage should therefore do nothing
    """
    cfg = ControlFlowGraph()
    var_eax = Variable("eax", Integer.int32_t())
    arg = Variable("arg", Integer.int32_t())
    const_1 = Constant(1, Integer.int32_t())
    const_0 = Constant(0, Integer.int32_t())
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(var_eax, arg),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1])),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_0])),
            ],
        ),
    )
    task = MockTask(cfg)
    CompilerIdiomHandling().run(task)
    assert node.instructions == [
        Assignment(var_eax, arg),
        Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1])),
        Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_0])),
    ]


def test_instructions_only_with_tags():
    """
    Here, all instructions are tagged.
    As a consequence, a new instruction should be added at the end of the block.
    """
    cfg = ControlFlowGraph()
    var_eax = Variable("eax", Integer.int32_t())
    var_ecx = Variable("ecx", Integer.int32_t())
    const_1 = Constant(1, Integer.int32_t())
    const_10 = Constant(10, Integer.int32_t())
    const_0 = Constant(0, Integer.int32_t())
    tags = [Tag("compiler_idiom: division", "ecx,10")]
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(var_eax, var_ecx, tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_0]), tags=tags),
            ],
        ),
    )
    task = MockTask(cfg)
    CompilerIdiomHandling().run(task)
    assert node.instructions == [
        Assignment(var_eax, var_ecx, tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.divide, [var_ecx, const_10])),
    ]


def test_instructions_with_tags_at_end():
    """
    Here, all instructions are tagged except for the first one.
    As a consequence, a new instruction should be added at the end of the block.
    """
    cfg = ControlFlowGraph()
    var_eax = Variable("eax", Integer.int32_t())
    var_ecx = Variable("ecx", Integer.int32_t())
    const_1 = Constant(1, Integer.int32_t())
    const_10 = Constant(10, Integer.int32_t())
    const_0 = Constant(0, Integer.int32_t())
    tags = [Tag("compiler_idiom: division", "ecx,10")]
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(var_ecx, const_1),
                Assignment(var_eax, var_ecx, tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_0]), tags=tags),
            ],
        ),
    )
    task = MockTask(cfg)
    CompilerIdiomHandling().run(task)
    assert node.instructions == [
        Assignment(var_ecx, const_1),
        Assignment(var_eax, var_ecx, tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.divide, [var_ecx, const_10])),
    ]


def test_instructions_with_tags_at_start():
    """
    Here, all instructions are tagged except for the last one.
    As a consequence, a new instruction should be added before the last instruction.
    """
    cfg = ControlFlowGraph()
    var_eax = Variable("eax", Integer.int32_t())
    var_ecx = Variable("ecx", Integer.int32_t())
    const_1 = Constant(1, Integer.int32_t())
    const_10 = Constant(10, Integer.int32_t())
    const_0 = Constant(0, Integer.int32_t())
    tags = [Tag("compiler_idiom: division", "ecx,10")]
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(var_eax, var_ecx, tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_0]), tags=tags),
                Assignment(var_ecx, const_1),
            ],
        ),
    )
    task = MockTask(cfg)
    CompilerIdiomHandling().run(task)
    assert node.instructions == [
        Assignment(var_eax, var_ecx, tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.divide, [var_ecx, const_10])),
        Assignment(var_ecx, const_1),
    ]


def test_instructions_with_tags_in_middle():
    """
    Here, all instructions are tagged except for the first and the last one.
    As a consequence, a new instruction should be added before the last instruction.
    """
    cfg = ControlFlowGraph()
    var_eax = Variable("eax", Integer.int32_t())
    var_ecx = Variable("ecx", Integer.int32_t())
    const_1 = Constant(1, Integer.int32_t())
    const_10 = Constant(10, Integer.int32_t())
    const_0 = Constant(0, Integer.int32_t())
    tags = [Tag("compiler_idiom: division", "ecx,10")]
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(var_ecx, const_1),
                Assignment(var_eax, var_ecx, tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_0]), tags=tags),
                Assignment(var_ecx, const_1),
            ],
        ),
    )
    task = MockTask(cfg)
    CompilerIdiomHandling().run(task)
    assert node.instructions == [
        Assignment(var_ecx, const_1),
        Assignment(var_eax, var_ecx, tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
        Assignment(var_eax, BinaryOperation(OperationType.divide, [var_ecx, const_10])),
        Assignment(var_ecx, const_1),
    ]


def _get_task_with_idiom_type(idiom_type):
    cfg = ControlFlowGraph()
    var_eax = Variable("eax", Integer.int32_t())
    var_ecx = Variable("ecx", Integer.int32_t())
    const_1 = Constant(1, Integer.int32_t())
    const_10 = Constant(10, Integer.int32_t())
    const_0 = Constant(0, Integer.int32_t())
    tags = [Tag(f"compiler_idiom: {idiom_type}", "ecx,10")]
    cfg.add_node(
        node := BasicBlock(
            0,
            instructions=[
                Assignment(var_ecx, const_1),
                Assignment(var_eax, var_ecx, tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_1]), tags=tags),
                Assignment(var_eax, BinaryOperation(OperationType.plus, [var_eax, const_0]), tags=tags),
                Assignment(var_ecx, const_1),
            ],
        ),
    )
    return MockTask(cfg), node


def test_operation_types():
    for idiom_type, operation_type in [
        ("multiplication", OperationType.multiply),
        ("unsigned_multiplication", OperationType.multiply_us),
        ("division", OperationType.divide),
        ("division unsigned", OperationType.divide_us),
        ("modulo", OperationType.modulo),
        ("modulo unsigned", OperationType.modulo_us),
    ]:
        task, node = _get_task_with_idiom_type(idiom_type)
        CompilerIdiomHandling().run(task)
        assert node.instructions[3].value.operation == operation_type
