"""A function argument joined to other variables by Relations: all of them must get the argument name.

coreutils users add_utmp: the parameter a#0 has a field write, a#2 -> a#0 joins the new version to it.
"""

import pytest
from decompiler.pipeline.ssa.outofssatranslation import OutOfSsaTranslation, SSAOptions
from decompiler.pipeline.ssa.variable_renaming import MinimalVariableRenamer, SimpleVariableRenamer
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Assignment, BinaryOperation, Constant, Integer, OperationType, Relation, Return, Variable
from decompiler.task import DecompilerTask
from decompiler.util.options import Options

def _argument_relation_task():
    """a is a parameter: y = a#0 + 1; a#2 -> a#0; z = a#2 + y; return z   (coreutils users add_utmp)."""
    int32 = Integer.int32_t()
    a0, a2 = (Variable("a", int32, ssa_label=label, is_aliased=True) for label in (0, 2))
    y, z = Variable("y", int32, ssa_label=0), Variable("z", int32, ssa_label=0)
    cfg = ControlFlowGraph()
    cfg.add_node(
        BasicBlock(
            0,
            [
                Assignment(y, BinaryOperation(OperationType.plus, [a0, Constant(1, int32)])),
                Relation(a2, a0),
                Assignment(z, BinaryOperation(OperationType.plus, [a2, y])),
                Return([z]),
            ],
        )
    )
    task = DecompilerTask(name="relation-test", function_identifier="", cfg=cfg, options=Options())
    task.function_parameters = [Variable("a", int32)]
    return task, (a0, a2)


@pytest.mark.parametrize("renamer_class", [SimpleVariableRenamer, MinimalVariableRenamer])
def test_variables_related_to_an_argument_get_the_argument_name(renamer_class):
    task, (a0, a2) = _argument_relation_task()
    renamer = renamer_class(task, InterferenceGraph(task.graph))
    assert renamer.renaming_map[a0].name == renamer.renaming_map[a2].name == "a"
    renamer.rename()


@pytest.mark.parametrize("mode", [mode for mode in SSAOptions if mode in OutOfSsaTranslation.out_of_ssa_strategy])
def test_relation_on_an_argument_survives_out_of_ssa_in_every_mode(mode):
    task, _ = _argument_relation_task()
    task.options.set("out-of-ssa-translation.mode", mode.value)
    OutOfSsaTranslation().run(task)
    assert not task.failed
