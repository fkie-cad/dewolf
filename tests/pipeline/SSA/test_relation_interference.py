"""Variables joined by a Relation must get one name even if both are live at the same time.

Binary Ninja sometimes still reads the old version of an aliased variable after the instruction a
Relation belongs to (e.g. after a call that was given the variable's address). The interference
graph then has an edge between the two versions, which must not keep the renamers from giving them
the one name a Relation demands.
"""

import pytest
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation, SSAOptions
from decompiler.pipeline.ssa.variable_renaming import (
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


def _transitive_task():
    """x#0 = 1; x#1 -> x#0; x#2 -> x#1; y = x#0 + x#2; return y   -   x#0 and x#2 interfere but share no Relation."""
    int32 = Integer.int32_t()
    x0, x1, x2 = (Variable("x", int32, ssa_label=label, is_aliased=True) for label in (0, 1, 2))
    y = Variable("y", int32, ssa_label=0)
    cfg = ControlFlowGraph()
    cfg.add_node(
        BasicBlock(
            0,
            [
                Assignment(x0, Constant(1, int32)),
                Relation(x1, x0),
                Relation(x2, x1),
                Assignment(y, BinaryOperation(OperationType.plus, [x0, x2])),
                Return([y]),
            ],
        )
    )
    return DecompilerTask(name="relation-test", function_identifier="", cfg=cfg, options=Options()), (x0, x1, x2)


def test_interference_is_removed_within_the_whole_relation_chain():
    task, (x0, _, x2) = _transitive_task()
    interference_graph = InterferenceGraph(task.graph)
    assert interference_graph.are_interfering(x0, x2)
    remove_interference_between_related_variables(task.graph, interference_graph)
    assert not interference_graph.are_interfering(x0, x2)


@pytest.mark.parametrize("renamer_class", [SimpleVariableRenamer, MinimalVariableRenamer])
def test_base_renamers_give_a_relation_chain_one_name(renamer_class):
    task, variables = _transitive_task()
    renamer = renamer_class(task, InterferenceGraph(task.graph))
    assert len({renamer.renaming_map[variable].name for variable in variables}) == 1
    renamer.rename()


@pytest.mark.parametrize("mode", [mode for mode in SSAOptions if mode in OutOfSsaTranslation.out_of_ssa_strategy])
@pytest.mark.parametrize("make_task", [lambda: _task(), lambda: _transitive_task()[0]], ids=["relation", "relation_chain"])
def test_out_of_ssa_succeeds_in_every_mode(mode, make_task):
    task = make_task()
    task.options.set("out-of-ssa-translation.mode", mode.value)
    OutOfSsaTranslation().run(task)
    assert not task.failed
    assert not any(isinstance(variable, Variable) and variable.ssa_label is not None for variable in task.graph.get_variables())
