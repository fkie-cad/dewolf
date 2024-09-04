"""Pytest for InsertingMissingDefinitions."""

from typing import Dict

import pytest
from decompiler.pipeline.preprocessing import Coherence
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, FunctionSymbol, Variable
from decompiler.structures.pseudo.instructions import Assignment, Return
from decompiler.structures.pseudo.operations import Call
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask

i32 = Integer.int32_t()
i64 = Integer.int64_t()
u32 = Integer.uint32_t()


@pytest.mark.parametrize(
    "before, after",
    [
        (
            {
                "a": {0: [Variable("a", i32), Variable("a", u32)], 1: [Variable("a", u32)]},
                "b": {42: [Variable("b")]},
                "c": {0: [Variable("c", u32)], 2: [Variable("c", i64)]},
            },
            {
                "a": {0: [Variable("a", i32), Variable("a", i32)], 1: [Variable("a", u32)]},
                "b": {42: [Variable("b")]},
                "c": {0: [Variable("c", u32)], 2: [Variable("c", i64)]},
            },
        )
    ],
)
def test_type_harmonization(before: Dict, after: Dict):
    """Test whether type harmonization sets all variables with the same name and label to the same type."""
    stage = Coherence()
    stage.enforce_same_types(before)
    assert before == after


@pytest.mark.parametrize(
    "before, after",
    [
        (
            {
                "a": {0: [Variable("a", is_aliased=False), Variable("a", is_aliased=True)], 1: [Variable("a", is_aliased=False)]},
                "b": {42: [Variable("b", is_aliased=False)]},
                "c": {0: [Variable("c", is_aliased=False)], 2: [Variable("c", is_aliased=True)]},
            },
            {
                "a": {0: [Variable("a", is_aliased=True), Variable("a", is_aliased=True)], 1: [Variable("a", is_aliased=True)]},
                "b": {42: [Variable("b", is_aliased=False)]},
                "c": {0: [Variable("c", is_aliased=True)], 2: [Variable("c", is_aliased=True)]},
            },
        )
    ],
)
def test_aliased_harmonization(before: Dict, after: Dict):
    """Test whether type harmonization sets all variables with the same name and label to the same type."""
    stage = Coherence()
    stage.enforce_same_aliased_value(before)
    assert before == after


def test_acceptance():
    """Test running the pipeline stages as it is supposed to be."""
    cfg = ControlFlowGraph()
    cfg.add_nodes_from(
        [
            BasicBlock(
                0,
                instructions=[
                    Assignment(x01 := Variable("x", i32, ssa_label=0), Constant(0x1337, i32)),
                    Assignment(
                        x10 := Variable("x", i32, is_aliased=True, ssa_label=1),
                        Call(FunctionSymbol("foo", 0x42), [x02 := Variable("x", u32, ssa_label=0)]),
                    ),
                    Return([x12 := Variable("x", i32, is_aliased=False, ssa_label=1)]),
                ],
            )
        ]
    )
    Coherence().run(DecompilerTask(name="test", function_identifier="", cfg=cfg))
    assert {variable.type for variable in [x01, x02]} == {i32}
    assert {variable.is_aliased for variable in [x01, x02, x10, x12]} == {True}
