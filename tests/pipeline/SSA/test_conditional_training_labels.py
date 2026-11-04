"""The training goal compares DWARF identities, not names (two distinct `i` are different sources)."""

from decompiler.pipeline.ssa.conditional_attribute_helper import TrainingAttributeHelper
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.interferencegraph import InterferenceGraph
from decompiler.structures.pseudo import Assignment, Integer, Return, Variable, VariableProvenance


def _variable(name, source_name, source_id, storage):
    origin = VariableProvenance(source_type="StackVariableSourceType", storage=storage, source_name=source_name, source_id=source_id)
    return Variable(name, Integer.int32_t(), ssa_label=1, origin=origin)


def _goals(x, y):
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [Assignment(x, y), Return([x])]))
    helper = TrainingAttributeHelper(set(), InterferenceGraph(cfg))
    return [record.training_goal for record in helper.iter_training_data(cfg)]


def test_same_name_different_identity_is_a_negative_pair():
    assert _goals(_variable("x", "i", 0x40, -20), _variable("y", "i", 0x80, -24)) == [0]


def test_same_identity_is_a_positive_pair():
    assert _goals(_variable("x", "i", 0x40, -20), _variable("y", "i", 0x40, -24)) == [1]
