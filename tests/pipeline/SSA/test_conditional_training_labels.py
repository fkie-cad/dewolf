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


def test_candidate_pairs_include_unlabeled_and_skip_self_pairs():
    from decompiler.structures.pseudo import OperationType, UnaryOperation

    x = _variable("x", "i", 0x40, -20)
    temp = Variable("temp", Integer.int32_t(), ssa_label=1)  # no DWARF origin
    p = _variable("p", "p", 0x50, -28)
    store = Assignment(UnaryOperation(OperationType.dereference, [p]), p)  # *(p) = p: only the pair (p, p)
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [Assignment(x, temp), store, Return([x])]))
    helper = TrainingAttributeHelper(set(), InterferenceGraph(cfg))
    assert [(pair.x.name, pair.y.name) for pair in helper.iter_candidate_pairs(cfg)] == [("x", "temp")]
    assert list(helper.iter_training_data(cfg)) == []  # x-temp is unlabeled


def _three_kinds_cfg():
    """a#1 = s#0; a#2 = a#1 + 1; b#1 = s#0  -  a#2 follows a#1, and a#1 / b#1 are copies of the same variable."""
    from decompiler.structures.pseudo import BinaryOperation, Constant, OperationType

    variable = lambda name, label, storage: Variable(
        name, Integer.int32_t(), ssa_label=label, origin=VariableProvenance(source_type="StackVariableSourceType", storage=storage, source_name=name, source_id=storage)
    )
    s0, a1, a2, b1 = variable("s", 0, -8), variable("a", 1, -12), variable("a", 2, -12), variable("b", 1, -16)
    cfg = ControlFlowGraph()
    increment = BinaryOperation(OperationType.plus, [a1, Constant(1, Integer.int32_t())])
    cfg.add_node(BasicBlock(0, [Assignment(a1, s0), Assignment(a2, increment), Assignment(b1, s0), Return([a2, b1])]))
    return cfg


def test_candidate_pairs_cover_following_definitions_and_copies_of_the_same_variable():
    from decompiler.pipeline.ssa.conditional_attribute_helper import INDEX_FOLLOWING_DEFINITIONS, INDEX_SAME_SOURCE

    cfg = _three_kinds_cfg()
    pairs = list(TrainingAttributeHelper(set(), InterferenceGraph(cfg)).iter_candidate_pairs(cfg))
    kind = lambda pair: "following" if pair.vector[INDEX_FOLLOWING_DEFINITIONS] else "same_rhs" if pair.vector[INDEX_SAME_SOURCE] else "assignment"
    found = {(kind(pair), str(pair.x), str(pair.y)) for pair in pairs}
    assert ("following", "a#1", "a#2") in found
    assert ("same_rhs", "a#1", "b#1") in found
    assert ("assignment", "b#1", "s#0") in found  # a#1 and s#0 interfere: s#0 is still read by b#1


def test_candidate_pairs_are_the_pairs_the_renamer_scores():
    """Same pairs and vectors as ConditionalAttributeHelper.iter_edge_data, minus self-pairs and interfering pairs."""
    from decompiler.pipeline.ssa.conditional_attribute_helper import ConditionalAttributeHelper, variablesAreInterfering

    cfg = _three_kinds_cfg()
    interference_graph = InterferenceGraph(cfg)
    scored = [
        (vector, x, y)
        for vector, (x, y) in ConditionalAttributeHelper(set()).iter_edge_data(cfg)
        if x != y and not variablesAreInterfering(interference_graph, x, y)
    ]
    candidates = [(pair.vector, pair.x, pair.y) for pair in TrainingAttributeHelper(set(), interference_graph).iter_candidate_pairs(cfg)]
    assert candidates == scored and candidates


def test_candidate_pairs_and_the_renamer_separate_the_same_pairs():
    """A pair of different types is no candidate even if the sizes agree: the renamer never merges it.
    variablesAreInterfering and ConditionalVariableRenamer._must_separate have to agree on every pair."""
    from itertools import combinations
    from types import SimpleNamespace

    from decompiler.pipeline.ssa.conditional_attribute_helper import variablesAreInterfering
    from decompiler.pipeline.ssa.variable_renaming import ConditionalVariableRenamer
    from decompiler.structures.pseudo import GlobalVariable, Pointer

    signed, unsigned, narrow, pointer = Integer.int32_t(), Integer.uint32_t(), Integer.int8_t(), Pointer(Integer.int32_t())
    variables = [
        Variable("a", signed, ssa_label=1),
        Variable("b", signed, ssa_label=1),
        Variable("c", unsigned, ssa_label=1),  # same size as a, other type
        Variable("d", narrow, ssa_label=1),
        Variable("e", pointer, ssa_label=1),
        Variable("f", signed, ssa_label=1, is_aliased=True),
        Variable("f", signed, ssa_label=2, is_aliased=True),
        Variable("h", signed, ssa_label=1, is_aliased=True),
        GlobalVariable("g", signed, Integer.int32_t(), ssa_label=1),
    ]
    interference_graph = InterferenceGraph()  # no liveness interference at all: only the other rules decide
    interference_graph.add_nodes_from(variables)
    renamer = SimpleNamespace(interference_graph=interference_graph)
    for x, y in combinations(variables, 2):
        assert variablesAreInterfering(interference_graph, x, y) == ConditionalVariableRenamer._must_separate(renamer, (x,), (y,)), (x, y)
    a, b, c = variables[:3]
    assert not variablesAreInterfering(interference_graph, a, b)
    assert variablesAreInterfering(interference_graph, a, c)
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [Assignment(a, c), Return([a])]))
    assert list(TrainingAttributeHelper(set(), InterferenceGraph(cfg)).iter_candidate_pairs(cfg)) == []


def test_training_stage_writes_no_pairs_with_a_global(tmp_path, monkeypatch):
    """The renamer scores pairs with a global too, but they are no training data and would make every
    count of unlabeled pairs a count of globals."""
    import json

    from decompiler.pipeline.ssa.conditionalSSATraining import ConditionalOutOfSSATraining
    from decompiler.structures.pseudo import Constant, GlobalVariable
    from decompiler.task import DecompilerTask
    from decompiler.util.options import Options

    int32 = Integer.int32_t()
    x, y = _variable("x", "i", 0x40, -20), _variable("y", "i", 0x40, -24)
    g1, g2 = (GlobalVariable("counter", int32, Constant(0, int32), ssa_label=label) for label in (1, 2))
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, [Assignment(x, y), Assignment(g2, g1), Return([x, g2])]))
    helper = TrainingAttributeHelper(set(), InterferenceGraph(cfg))
    all_pairs = [{pair.x.name, pair.y.name} for pair in helper.iter_candidate_pairs(cfg)]
    assert {"counter"} in all_pairs and {"x", "y"} in all_pairs  # the helper itself still yields the global pair

    monkeypatch.setenv("ConditionalResultPath", str(tmp_path / "result.json"))
    monkeypatch.setenv("ConditionalErrorLogPath", str(tmp_path / "errors.log"))
    task = DecompilerTask(name="f", function_identifier="", cfg=cfg, options=Options())
    ConditionalOutOfSSATraining(task, {})._extract_and_write(set(), InterferenceGraph(cfg))
    result = json.loads((tmp_path / "result.json").read_text())
    names = [name.split("#")[0] for name, _ in result["variables"]]
    assert "counter" not in names and set(names) == {"x", "y"}
    assert [[names[a], names[b]] for a, b, *_ in result["pairs"]] == [["x", "y"]]
