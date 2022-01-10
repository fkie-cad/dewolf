from typing import Optional

import pytest
from decompiler.pipeline.controlflowanalysis import ExpressionSimplification
from decompiler.structures.ast.ast_nodes import CodeNode
from decompiler.structures.ast.syntaxtree import AbstractSyntaxTree
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.logic.logic_condition import LogicCondition
from decompiler.structures.pseudo.expressions import Constant, Variable
from decompiler.structures.pseudo.instructions import Assignment
from decompiler.structures.pseudo.operations import BinaryOperation, OperationType, UnaryOperation
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask


def _task(ast: Optional[AbstractSyntaxTree] = None, cfg: Optional[ControlFlowGraph] = None) -> DecompilerTask:
    cfg = ControlFlowGraph() if cfg is None else cfg
    task = DecompilerTask("test_function", cfg, ast)
    return task


x = Variable("x")
y = Variable("y")
const_0 = Constant(0, Integer(32, signed=True))
const_m0 = Constant(-0, Integer(32, signed=True))
const_1 = Constant(1, Integer(32, signed=True))
const_m1 = Constant(-1, Integer(32, signed=True))


@pytest.mark.parametrize(
    "instruction, result",
    [
        (Assignment(y, BinaryOperation(OperationType.plus, [x, const_0])), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.plus, [const_0, x])), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.plus, [const_0, const_0])), Assignment(y, const_0)),
        (Assignment(y, BinaryOperation(OperationType.plus, [x, const_m0])), Assignment(y, x)),
        (
            Assignment(y, BinaryOperation(OperationType.plus, [x, BinaryOperation(OperationType.plus, [const_0, const_0])])),
            Assignment(y, x),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.plus, [const_0, BinaryOperation(OperationType.plus, [const_0, x])])),
            Assignment(y, x),
        ),
    ],
)
def test_easy_simplification_with_zero_addition(instruction, result):
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    task = _task(AbstractSyntaxTree(CodeNode([instruction], true_value.copy()), dict()))
    ExpressionSimplification().run(task)
    assert task.syntax_tree.root == CodeNode([result], true_value.copy())


@pytest.mark.parametrize(
    "instruction, result",
    [
        (Assignment(y, BinaryOperation(OperationType.multiply, [x, const_0])), Assignment(y, const_0)),
        (Assignment(y, BinaryOperation(OperationType.multiply, [const_0, x])), Assignment(y, const_0)),
        (Assignment(y, BinaryOperation(OperationType.multiply, [const_0, const_0])), Assignment(y, const_0)),
        (Assignment(y, BinaryOperation(OperationType.multiply, [x, const_m0])), Assignment(y, const_0)),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [x, BinaryOperation(OperationType.multiply, [x, const_0])])),
            Assignment(y, const_0),
        ),
    ],
)
def test_simplification_with_zero_multiplication(instruction, result):
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    task = _task(AbstractSyntaxTree(CodeNode([instruction], true_value.copy()), dict()))
    ExpressionSimplification().run(task)
    assert task.syntax_tree.root == CodeNode([result], true_value.copy())


@pytest.mark.parametrize(
    "instruction, result",
    [
        (Assignment(y, BinaryOperation(OperationType.minus, (x, const_0))), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.minus, (const_0, x))), Assignment(y, UnaryOperation(OperationType.negate, [x]))),
        (Assignment(y, BinaryOperation(OperationType.minus, [const_0, UnaryOperation(OperationType.negate, [x])])), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.minus, [const_0, const_m1])), Assignment(y, const_1)),
        (Assignment(y, BinaryOperation(OperationType.minus, (x, const_m0))), Assignment(y, x)),
    ],
)
def test_simplification_with_zero_subtraction(instruction, result):
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    task = _task(AbstractSyntaxTree(CodeNode([instruction], true_value.copy()), dict()))
    ExpressionSimplification().run(task)
    assert task.syntax_tree.root == CodeNode([result], true_value.copy())


@pytest.mark.parametrize(
    "instruction, result",
    [
        (
            Assignment(y, BinaryOperation(OperationType.plus, [x, BinaryOperation(OperationType.multiply, [x, const_0])])),
            Assignment(y, x),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.minus, [y, BinaryOperation(OperationType.minus, [x, const_0])])),
            Assignment(y, BinaryOperation(OperationType.minus, [y, x])),
        ),
    ],
)
def test_simplification_with_zero_mix(instruction, result):
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(1, [instruction]))
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    task = _task(AbstractSyntaxTree(CodeNode([instruction], true_value.copy()), dict()), cfg)
    ExpressionSimplification().run(task)
    assert task.syntax_tree.root == CodeNode([result], true_value.copy())


@pytest.mark.parametrize(
    "instruction, result",
    [
        (Assignment(y, BinaryOperation(OperationType.multiply, [x, const_1])), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.multiply, [const_1, x])), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.multiply, [const_1, const_1])), Assignment(y, const_1)),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [x, const_m1])),
            Assignment(y, UnaryOperation(OperationType.negate, [x])),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [Constant(2, Integer(32, signed=False)), const_m1])),
            Assignment(y, UnaryOperation(OperationType.negate, [Constant(2, Integer(32, signed=False))])),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [Constant(2, Integer(32, signed=True)), const_m1])),
            Assignment(y, Constant(-2, Integer(32, signed=True))),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [Constant(-2, Integer(32, signed=True)), const_m1])),
            Assignment(y, Constant(2, Integer(32, signed=True))),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [x, BinaryOperation(OperationType.multiply, [const_1, const_1])])),
            Assignment(y, x),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [const_1, BinaryOperation(OperationType.multiply, [x, const_1])])),
            Assignment(y, x),
        ),
    ],
)
def test_simplification_with_one_multiplication(instruction, result):
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    task = _task(AbstractSyntaxTree(CodeNode([instruction], true_value.copy()), dict()))
    ExpressionSimplification().run(task)
    assert task.syntax_tree.root == CodeNode([result], true_value.copy())


@pytest.mark.parametrize(
    "instruction, result",
    [
        (Assignment(y, BinaryOperation(OperationType.divide, [x, const_1])), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.divide, [const_1, const_1])), Assignment(y, const_1)),
        (Assignment(y, BinaryOperation(OperationType.divide, [const_m1, const_1])), Assignment(y, const_m1)),
        (Assignment(y, BinaryOperation(OperationType.divide, [const_1, const_m1])), Assignment(y, const_m1)),
        (Assignment(y, BinaryOperation(OperationType.divide, [const_m1, const_m1])), Assignment(y, const_1)),
        (Assignment(y, BinaryOperation(OperationType.divide, [x, const_m1])), Assignment(y, UnaryOperation(OperationType.negate, [x]))),
        (
            Assignment(y, BinaryOperation(OperationType.divide, [const_0, const_1])),
            Assignment(y, const_0),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.divide, [const_0, const_m1])),
            Assignment(y, const_0),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.divide, [Constant(2, Integer(32, signed=False)), const_m1])),
            Assignment(y, UnaryOperation(OperationType.negate, [Constant(2, Integer(32, signed=False))])),
        ),
    ],
)
def test_simplification_with_one_division(instruction, result):
    true_value = LogicCondition.initialize_true(LogicCondition.generate_new_context())
    task = _task(AbstractSyntaxTree(CodeNode([instruction], true_value.copy()), dict()))
    ExpressionSimplification().run(task)
    assert task.syntax_tree.root == CodeNode([result], true_value.copy())


@pytest.mark.parametrize(
    "instruction, result",
    [
        (Assignment(y, BinaryOperation(OperationType.divide, [x, const_1])), Assignment(y, x)),
        (Assignment(y, BinaryOperation(OperationType.divide, [const_1, const_1])), Assignment(y, const_1)),
        (Assignment(y, BinaryOperation(OperationType.multiply, [const_1, const_1])), Assignment(y, const_1)),
        (
            Assignment(y, BinaryOperation(OperationType.multiply, [x, const_m1])),
            Assignment(y, UnaryOperation(OperationType.negate, [x])),
        ),
        (
            Assignment(y, BinaryOperation(OperationType.plus, [x, BinaryOperation(OperationType.multiply, [x, const_0])])),
            Assignment(y, x),
        ),
        (Assignment(y, BinaryOperation(OperationType.plus, [x, const_m0])), Assignment(y, x)),
    ],
)
def test_for_cfg(instruction, result):
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [instruction]))
    task = _task(cfg=cfg)
    ExpressionSimplification().run(task)
    assert list(task.graph.instructions) == [result]
