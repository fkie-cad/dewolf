"""Variables joined by a Relation must get one name even if both are live at the same time.

Binary Ninja sometimes still reads the old version of an aliased variable after the instruction a
Relation belongs to (e.g. after a call that was given the variable's address). The interference
graph then has an edge between the two versions, which must not keep the renamers from giving them
the one name a Relation demands.
"""

import pytest
from decompiler.pipeline.ssa.variable_renaming import (
    ConditionalVariableRenamer,
    MinimalVariableRenamer,
    SimpleVariableRenamer,
    remove_interference_between_related_variables,
)
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Assignment, BinaryOperation, Constant, Integer, OperationType, Relation, Return, Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options


def _variables():
    int32 = Integer.int32_t()
    x0, x1 = (Variable("x", int32, ssa_label=label, is_aliased=True) for label in (0, 1))
    y, z = Variable("y", int32, ssa_label=0), Variable("z", int32, ssa_label=0)
    return x0, x1, y, z


def _task():
    """x#0 = 1; x#1 -> x#0; y = x#0 + 1; z = x#1 + y; return z   -   x#0 is still read after x#1 is defined."""
    x0, x1, y, z = _variables()
    one = Constant(1, Integer.int32_t())
    cfg = ControlFlowGraph()
    cfg.add_node(
        BasicBlock(
            0,
            [
                Assignment(x0, one),
                Relation(x1, x0),
                Assignment(y, BinaryOperation(OperationType.plus, [x0, one])),
                Assignment(z, BinaryOperation(OperationType.plus, [x1, y])),
                Return([z]),
            ],
        )
    )
    return DecompilerTask(name="relation-test", function_identifier="", cfg=cfg, options=Options())


def test_the_two_sides_of_the_relation_interfere_by_liveness():
    """The precondition of the tests below."""
    x0, x1, _, _ = _variables()
    assert InterferenceGraph(_task().graph).are_interfering(x0, x1)


def test_interference_between_related_variables_is_removed_and_only_that():
    x0, x1, y, _ = _variables()
    task = _task()
    interference_graph = InterferenceGraph(task.graph)
    assert interference_graph.are_interfering(x1, y)
    remove_interference_between_related_variables(task.graph, interference_graph)
    assert not interference_graph.are_interfering(x0, x1)
    assert interference_graph.are_interfering(x1, y)


@pytest.mark.parametrize("renamer_class", [SimpleVariableRenamer, MinimalVariableRenamer])
def test_base_renamers_give_related_variables_one_name(renamer_class):
    x0, x1, _, _ = _variables()
    task = _task()
    renamer = renamer_class(task, InterferenceGraph(task.graph))
    assert renamer.renaming_map[x0].name == renamer.renaming_map[x1].name
    renamer.rename()  # raises if a Relation's variables ended up with different names


@pytest.mark.parametrize("strategy", [0, 1, 4])
def test_conditional_renamer_gives_related_variables_one_name(strategy):
    x0, x1, y, _ = _variables()
    task = _task()
    # no pair scores above 0: only the Relation joins variables
    renamer = ConditionalVariableRenamer(task, InterferenceGraph(task.graph), [0.0] * 18, -1.0, set(), strategy)
    assert renamer.renaming_map[x0].name == renamer.renaming_map[x1].name
    assert renamer.renaming_map[y].name != renamer.renaming_map[x1].name
    renamer.rename()
