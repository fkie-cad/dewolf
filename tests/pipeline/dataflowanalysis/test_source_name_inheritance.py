"""Evaluation-only DWARF source-name inheritance in expression propagation, CSE and identity elimination.

A variable that replaces a named variable takes over its source name (name_via = the replaced variable's chain + the
mechanism), but only when unambiguous; conflicting candidates give no name and existing names are never overwritten.
The decompiled IR itself must not change because of names.
"""

from decompiler.pipeline.dataflowanalysis import CommonSubexpressionElimination, DeadCodeElimination, ExpressionPropagation
from decompiler.pipeline.dataflowanalysis.identity_elimination import IdentityElimination
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph, FalseCase, TrueCase
from decompiler.structures.pseudo.expressions import Constant, Variable, VariableProvenance
from decompiler.structures.pseudo.instructions import Assignment, Branch, Return
from decompiler.structures.pseudo.operations import BinaryOperation, Condition, OperationType
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask
from decompiler.util.name_inheritance import apply_names, collect_occurrences
from decompiler.util.options import Options

int32 = Integer.int32_t()


def _var(name, label, source_name=None, via=("dwarf",)):
    origin = VariableProvenance(source_name=source_name, name_via=via) if source_name else None
    return Variable(name, int32, ssa_label=label, origin=origin)


def _sub(a, b):
    return BinaryOperation(OperationType.minus, [a, b])


def _options() -> Options:
    options = Options()
    for kind in ("instruction", "branch", "call", "assignment"):
        options.set(f"expression-propagation.maximum_{kind}_complexity", 100)
    options.set("common-subexpression-elimination.threshold", 2)
    options.set("common-subexpression-elimination.intra", False)
    options.set("common-subexpression-elimination.string_threshold", 2)
    options.set("common-subexpression-elimination.min_string_length", 8)
    return options


def _task(cfg, parameters=()) -> DecompilerTask:
    return DecompilerTask(name="test", function_identifier="", cfg=cfg, options=_options(), function_parameters=list(parameters))


def _names(cfg):
    """{'name#label': {(source_name, name_via), ...}} over all occurrences (None for unnamed occurrences)."""
    result = {}
    for (name, label), occurrences in collect_occurrences(cfg.instructions).items():
        result[f"{name}#{label}"] = {
            (v.origin.source_name, v.origin.name_via) if v.origin is not None and v.origin.source_name else None for v in occurrences
        }
    return result


def _single_block(instructions):
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions))
    return cfg


# --- expression propagation -------------------------------------------------------------------------------------------


def test_propagation_inherits_name_of_replaced_variable():
    """dist#1 = p#0; return dist#1  ->  return p#0, p#0 takes over 'dist' via propagation."""
    cfg = _single_block([Assignment(_var("dist", 1, "dist"), _var("p", 0)), Return([_var("dist", 1, "dist")])])
    ExpressionPropagation().run(_task(cfg))
    assert str(cfg.nodes[0].instructions[-1]) == "return p#0"
    assert _names(cfg)["p#0"] == {("dist", ("dwarf", "propagation"))}


def test_propagation_extends_inferred_chain():
    cfg = _single_block([Assignment(_var("dist", 1, "dist", ("coherence",)), _var("p", 0)), Return([_var("dist", 1, "dist", ("coherence",))])])
    ExpressionPropagation().run(_task(cfg))
    assert _names(cfg)["p#0"] == {("dist", ("coherence", "propagation"))}


def test_propagation_conflict_gives_no_name():
    """a#1 = p#0; b#1 = p#0; return a#1 + b#1: p#0 stands for both a and b -> no name."""
    cfg = _single_block(
        [
            Assignment(_var("a", 1, "a"), _var("p", 0)),
            Assignment(_var("b", 1, "b"), _var("p", 0)),
            Return([BinaryOperation(OperationType.plus, [_var("a", 1, "a"), _var("b", 1, "b")])]),
        ]
    )
    task = _task(cfg)
    ExpressionPropagation().run(task)
    assert str(cfg.nodes[0].instructions[-1]) == "return p#0 + p#0"
    assert _names(cfg)["p#0"] == {None}
    assert ("p", 0) in task.propagated_source_values.conflicts


def test_propagation_never_overwrites_existing_name():
    cfg = _single_block([Assignment(_var("dist", 1, "dist"), _var("p", 0, "q")), Return([_var("dist", 1, "dist")])])
    ExpressionPropagation().run(_task(cfg))
    assert _names(cfg)["p#0"] == {("q", ("dwarf",))}


def test_propagation_does_not_change_ir():
    """The propagated IR is the same with and without names."""

    def build(named):
        name = "dist" if named else None
        return _single_block(
            [
                Assignment(_var("dist", 1, name), _var("p", 0)),
                Assignment(_var("x", 1, name), _sub(_var("dist", 1, name), Constant(1, int32))),
                Return([_var("x", 1, name)]),
            ]
        )

    named, unnamed = build(True), build(False)
    ExpressionPropagation().run(_task(named))
    ExpressionPropagation().run(_task(unnamed))
    assert [str(i) for i in named.instructions] == [str(i) for i in unnamed.instructions]


# --- common subexpression elimination ---------------------------------------------------------------------------------


def _branching_cfg(definitions, condition_value, return_value):
    """block 0: definitions; if(condition_value < 0) -> return return_value | return 0"""
    cfg = ControlFlowGraph()
    head = BasicBlock(0, definitions + [Branch(Condition(OperationType.less, [condition_value, Constant(0, int32)]))])
    true_block = BasicBlock(1, [Return([return_value])])
    false_block = BasicBlock(2, [Return([Constant(0, int32)])])
    cfg.add_nodes_from([head, true_block, false_block])
    cfg.add_edges_from([TrueCase(head, true_block), FalseCase(head, false_block)])
    return cfg


def _run_ep_dce_cse(cfg):
    task = _task(cfg)
    for stage in (ExpressionPropagation, DeadCodeElimination, CommonSubexpressionElimination):
        stage().run(task)
    return task


def test_cse_temporary_inherits_name_of_propagated_value():
    """lead#1 = a#0 - b#0 propagated into both uses and removed; CSE's c0 = a#0 - b#0 takes over 'lead'."""
    lead = lambda: _var("lead", 1, "lead")
    cfg = _branching_cfg([Assignment(lead(), _sub(_var("a", 0), _var("b", 0)))], lead(), lead())
    _run_ep_dce_cse(cfg)
    assert str(cfg.nodes[0].instructions[0]) == "c0#0 = a#0 - b#0"
    assert _names(cfg)["c0#0"] == {("lead", ("dwarf", "cse"))}


def test_cse_conflict_gives_no_name_and_blocks_later_stages():
    """lead#1 and other#1 both hold a#0 - b#0 -> c0 stands for both -> no name, also not later via identity."""
    lead, other = (lambda: _var("lead", 1, "lead")), (lambda: _var("other", 1, "other"))
    cfg = _branching_cfg(
        [Assignment(lead(), _sub(_var("a", 0), _var("b", 0))), Assignment(other(), _sub(_var("a", 0), _var("b", 0)))], lead(), other()
    )
    task = _run_ep_dce_cse(cfg)
    assert str(cfg.nodes[0].instructions[0]) == "c0#0 = a#0 - b#0"
    assert _names(cfg)["c0#0"] == {None}
    assert ("c0", 0) in task.propagated_source_values.conflicts


def test_cse_temporary_from_named_definition_rhs():
    """
    block 1: winner#1 = a#0 - b#0; return winner#1   |   block 2: return a#0 - b#0
    Neither occurrence dominates the other, so CSE inserts c0#0 = a#0 - b#0 in block 0 and winner#1 = c0#0:
    c0 is the value of winner (a plain copy source of it) -> c0 takes over 'winner' via cse.
    """
    cfg = ControlFlowGraph()
    head = BasicBlock(0, [Branch(Condition(OperationType.less, [_var("a", 0), Constant(0, int32)]))])
    left = BasicBlock(1, [Assignment(_var("winner", 1, "winner"), _sub(_var("a", 0), _var("b", 0))), Return([_var("winner", 1, "winner")])])
    right = BasicBlock(2, [Return([_sub(_var("a", 0), _var("b", 0))])])
    cfg.add_nodes_from([head, left, right])
    cfg.add_edges_from([TrueCase(head, left), FalseCase(head, right)])
    CommonSubexpressionElimination().run(_task(cfg))
    assert str(head.instructions[0]) == "c0#0 = a#0 - b#0"
    assert str(left.instructions[0]) == "winner#1 = c0#0"
    assert _names(cfg)["c0#0"] == {("winner", ("dwarf", "cse"))}


def test_existing_subexpression_replacement_inherits_from_registry():
    """z#1 = a#0 - b#0 replaces an occurrence registered as the value of the eliminated lead#1 -> z inherits 'lead'."""
    occurrence = _sub(_var("a", 0), _var("b", 0))
    cfg = _branching_cfg([Assignment(_var("z", 1), _sub(_var("a", 0), _var("b", 0)))], occurrence, _var("z", 1))
    task = _task(cfg)
    task.propagated_source_values.register(occurrence, [("lead", 1)])
    task.propagated_source_values.names[("lead", 1)] = ("lead", ("dwarf",))
    CommonSubexpressionElimination().run(task)
    assert str(cfg.nodes[0].instructions[-1]) == "if(z#1 < 0x0)"
    assert _names(cfg)["z#1"] == {("lead", ("dwarf", "cse"))}


def test_registry_ignored_while_replaced_variable_still_exists():
    """lead#1 still exists in the cfg -> its name is not handed to a temporary (no duplicate name)."""
    first, second = _sub(_var("a", 0), _var("b", 0)), _sub(_var("a", 0), _var("b", 0))
    cfg = _branching_cfg([Assignment(_var("lead", 1, "lead"), Constant(1, int32))], first, second)
    task = _task(cfg)
    for occurrence in (first, second):
        task.propagated_source_values.register(occurrence, [("lead", 1)])
    task.propagated_source_values.names[("lead", 1)] = ("lead", ("dwarf",))
    CommonSubexpressionElimination().run(task)
    assert _names(cfg)["c0#0"] == {None}


# --- identity elimination ---------------------------------------------------------------------------------------------


def test_identity_elimination_inherits_agreeing_name():
    """x#1 = p#0; return x#1 -> merged into p#0, which takes over 'x' via identity."""
    cfg = _single_block([Assignment(_var("x", 1, "x"), _var("p", 0)), Return([_var("x", 1, "x")])])
    IdentityElimination().run(_task(cfg, [_var("p", 0)]))
    assert [str(i) for i in cfg.instructions] == ["return p#0"]
    assert _names(cfg)["p#0"] == {("x", ("dwarf", "identity"))}


def test_identity_elimination_conflict_gives_no_name():
    cfg = _single_block(
        [
            Assignment(_var("x", 1, "x"), _var("p", 0)),
            Assignment(_var("y", 1, "y"), _var("x", 1, "x")),
            Return([_var("y", 1, "y")]),
        ]
    )
    IdentityElimination().run(_task(cfg, [_var("p", 0)]))
    assert [str(i) for i in cfg.instructions] == ["return p#0"]
    assert _names(cfg)["p#0"] == {None}


def test_identity_elimination_never_overwrites():
    cfg = _single_block([Assignment(_var("x", 1, "x"), _var("p", 0, "p")), Return([_var("x", 1, "x")])])
    IdentityElimination().run(_task(cfg, [_var("p", 0)]))
    assert _names(cfg)["p#0"] == {("p", ("dwarf",))}


def test_identity_elimination_respects_known_conflict():
    cfg = _single_block([Assignment(_var("x", 1, "x"), _var("p", 0)), Return([_var("x", 1, "x")])])
    task = _task(cfg, [_var("p", 0)])
    task.propagated_source_values.conflicts.add(("p", 0))
    IdentityElimination().run(task)
    assert _names(cfg)["p#0"] == {None}


def test_apply_names_skips_dwarf_ambiguous_version():
    """An inherited name never lands on a version where the DWARF lookup matched several source variables."""
    i32 = Integer.int32_t()
    x = Variable("x", i32, ssa_label=1, origin=VariableProvenance(value_address=0x20, dwarf_ambiguous=True))
    assert apply_names([Return([x])], {("x", 1): ("num", ("dwarf", "propagation"))}) == []
    assert x.origin.source_name is None
