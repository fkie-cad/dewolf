"""Tests for the evaluation-only source-name provenance rules of the Coherence stage (name_via tagging, copy rule)."""

from decompiler.pipeline.preprocessing import Coherence
from decompiler.pipeline.preprocessing.register_pair_handling import RegisterPairHandling
from decompiler.structures.graphs.cfg import BasicBlock, ControlFlowGraph
from decompiler.structures.pseudo.expressions import Constant, GlobalVariable, RegisterPair, Variable, VariableProvenance
from decompiler.structures.pseudo.instructions import Assignment, Phi, Return
from decompiler.structures.pseudo.operations import BinaryOperation, OperationType
from decompiler.structures.pseudo.typing import Integer
from decompiler.task import DecompilerTask
from decompiler.util.name_inheritance import synthesized_version_origin

i32 = Integer.int32_t()


def dwarf(name: str, **kwargs) -> VariableProvenance:
    return VariableProvenance(source_name=name, name_via=("dwarf",), **kwargs)


def var(name: str, label: int, origin=None, **kwargs) -> Variable:
    return Variable(name, i32, ssa_label=label, origin=origin, **kwargs)


def run_coherence(*instructions):
    cfg = ControlFlowGraph()
    cfg.add_node(BasicBlock(0, instructions=list(instructions)))
    Coherence().run(DecompilerTask(name="test", function_identifier="", cfg=cfg))


def naming(variable: Variable):
    return (variable.origin.source_name, variable.origin.name_via) if variable.origin is not None else (None, ())


def test_coherence_tags_filled_names_and_keeps_dwarf():
    """Unnamed versions of a consistently named base name get the name with ("coherence",); dwarf names stay ("dwarf",)."""
    shared = VariableProvenance(value_address=0x10)  # unnamed origin shared by two occurrences of x#2 (as copy() does)
    other = var("y", 0, origin=shared)  # another SSA variable sharing that very object must stay untouched
    run_coherence(
        Assignment(x1 := var("x", 1, dwarf("count", value_address=0x8)), Constant(0, i32)),
        Assignment(x2 := var("x", 2, shared), BinaryOperation(OperationType.plus, [x1u := var("x", 1, dwarf("count")), Constant(1, i32)])),
        Assignment(x3 := var("x", 3), x2u := var("x", 2, shared)),
        Return([x3u := var("x", 3), other]),
    )
    assert naming(x1) == naming(x1u) == ("count", ("dwarf",))
    assert naming(x2) == naming(x2u) == naming(x3) == naming(x3u) == ("count", ("coherence",))
    # the shared object was not mutated, both x#2 occurrences carry the same new record that kept its location fields
    assert shared.source_name is None and shared.name_via == ()
    assert x2.origin is x2u.origin and x2.origin.value_address == 0x10
    assert x3.origin is x3u.origin
    assert naming(other) == (None, ())


def test_coherence_conflict_gives_no_name():
    run_coherence(
        Assignment(var("x", 1, dwarf("a")), Constant(0, i32)),
        Assignment(var("x", 2, dwarf("b")), Constant(1, i32)),
        Return([x3 := var("x", 3)]),
    )
    assert naming(x3) == (None, ())


def test_copy_rule_names_unnamed_side():
    """`t#0 = x#1` with only x named: t#0 (all occurrences) gets x's name via ("copy",); both directions work."""
    run_coherence(
        Assignment(var("x", 1, dwarf("count")), Constant(0, i32)),
        Assignment(t0 := var("t", 0, VariableProvenance(value_address=0x20)), var("x", 1, dwarf("count"))),
        Assignment(var("y", 1, dwarf("total")), u1 := var("u", 1)),
        Return([t0u := var("t", 0), u1u := var("u", 1)]),
    )
    assert naming(t0) == naming(t0u) == ("count", ("copy",))
    assert t0.origin is t0u.origin and t0.origin.value_address == 0x20
    assert naming(u1) == naming(u1u) == ("total", ("copy",))


def test_copy_rule_conflict_gives_no_name():
    """t#0 copied to/from two differently named variables: ambiguous -> no name."""
    run_coherence(
        Assignment(t0 := var("t", 0), var("x", 1, dwarf("count"))),
        Assignment(var("y", 1, dwarf("total")), var("t", 0)),
        Return([t0u := var("t", 0)]),
    )
    assert naming(t0) == naming(t0u) == (None, ())


def test_copy_rule_never_overwrites_and_ignores_both_named():
    run_coherence(
        Assignment(x1 := var("x", 1, dwarf("count")), y1 := var("y", 1, dwarf("total"))),
        Return([x1, y1]),
    )
    assert naming(x1) == ("count", ("dwarf",))
    assert naming(y1) == ("total", ("dwarf",))


def test_copy_rule_is_one_hop_only():
    """u#1 = t#0 = x#1: t#0 gets the name, u#1 does not (no chaining of inferred names)."""
    run_coherence(
        Assignment(t0 := var("t", 0), var("x", 1, dwarf("count"))),
        Assignment(u1 := var("u", 1), var("t", 0)),
        Return([u1]),
    )
    assert naming(t0) == ("count", ("copy",))
    assert naming(u1) == (None, ())


def test_copy_rule_ignores_non_plain_copies():
    """Phis, aliased variables, globals and operations are not copies for the rule."""
    run_coherence(
        Phi(p1 := var("p", 1), [var("x", 1, dwarf("count")), var("x", 2, dwarf("count"))]),
        Assignment(a1 := var("a", 1, is_aliased=True), var("x", 1, dwarf("count"))),
        Assignment(g := GlobalVariable("g", i32, Constant(0, i32), ssa_label=1), var("x", 1, dwarf("count"))),
        Assignment(n1 := var("n", 1), BinaryOperation(OperationType.plus, [var("x", 1, dwarf("count")), Constant(1, i32)])),
        Return([p1, a1, g, n1]),
    )
    for variable in (p1, a1, g, n1):
        assert naming(variable) == (None, ())


def test_copy_rule_uses_coherence_names():
    """Names filled by Coherence count as existing names for the copy rule."""
    run_coherence(
        Assignment(var("x", 1, dwarf("count")), Constant(0, i32)),
        Assignment(t0 := var("t", 0), var("x", 2)),
        Return([var("x", 2)]),
    )
    assert naming(t0) == ("count", ("copy",))


def test_register_pair_replacement_name():
    low, high = var("eax", 1, dwarf("v")), var("edx", 1, dwarf("v"))
    assert naming(RegisterPairHandling._get_replacement_variable(RegisterPair(high, low, Integer.int64_t()), 0)) == ("v", ("dwarf",))
    low, high = var("eax", 1, dwarf("v")), var("edx", 1)
    assert RegisterPairHandling._get_replacement_variable(RegisterPair(high, low, Integer.int64_t()), 0).origin is None
    low, high = var("eax", 1, dwarf("v")), var("edx", 1, dwarf("w"))
    assert RegisterPairHandling._get_replacement_variable(RegisterPair(high, low, Integer.int64_t()), 0).origin is None


def test_synthesized_version_prefers_existing_then_lifted_dwarf():
    """A synthesized aliased version takes its own SSA version's origin: from the cfg, else from the lifter's DWARF lookup."""
    existing, lifted = dwarf("a"), dwarf("b", value_address=0x20)
    assert synthesized_version_origin(("x", 1), {("x", 1): existing}, {("x", 1): lifted}, {"a"}, None) is existing
    assert synthesized_version_origin(("x", 2), {}, {("x", 2): lifted}, {"a"}, None) is lifted


def test_synthesized_version_falls_back_to_coherence_with_lifted_address():
    """No DWARF name at this memory version: Coherence names it, keeping the lifter's storage and value_address."""
    lifted = VariableProvenance(storage=-36, value_address=0x20)
    origin = synthesized_version_origin(("x", 2), {}, {("x", 2): lifted}, {"a"}, None)
    assert (origin.source_name, origin.name_via, origin.storage, origin.value_address) == ("a", ("coherence",), -36, 0x20)


def test_synthesized_version_conflict_is_unnamed_and_drops_foreign_name():
    """Versions disagree: no name; a fallback (another version's origin) loses its name and value_address."""
    assert synthesized_version_origin(("x", 2), {}, {("x", 2): (lifted := VariableProvenance(value_address=0x20))}, {"a", "b"}, None) is lifted
    origin = synthesized_version_origin(("x", 2), {}, {}, {"a", "b"}, dwarf("a", storage=-36, value_address=0x8))
    assert (origin.source_name, origin.name_via, origin.storage, origin.value_address) == (None, (), -36, None)


def test_coherence_skips_dwarf_ambiguous_version():
    """A version where DWARF matched several source variables is not named by Coherence."""
    ambiguous = VariableProvenance(value_address=0x20, dwarf_ambiguous=True)
    run_coherence(
        Assignment(x1 := var("x", 1, dwarf("count")), Constant(0, i32)),
        Assignment(x2 := var("x", 2, ambiguous), BinaryOperation(OperationType.plus, [var("x", 1, dwarf("count")), Constant(1, i32)])),
        Assignment(x3 := var("x", 3), x2u := var("x", 2, ambiguous)),
        Return([x3u := var("x", 3)]),
    )
    assert naming(x2) == naming(x2u) == (None, ())
    assert naming(x3) == naming(x3u) == ("count", ("coherence",))


def test_synthesized_version_ambiguous_gets_no_coherence_name():
    """DWARF was ambiguous at this memory version: no Coherence name for the synthesized version."""
    lifted = VariableProvenance(storage=-17, value_address=0x20, dwarf_ambiguous=True)
    assert synthesized_version_origin(("x", 2), {}, {("x", 2): lifted}, {"a"}, None) is lifted



def test_synthesized_version_in_shared_storage_gets_no_coherence_name():
    """DWARF places several source variables in this storage: no Coherence name for the synthesized version."""
    lifted = VariableProvenance(storage=-36, value_address=0x20, dwarf_storage_names=frozenset({"a", "b"}))
    assert synthesized_version_origin(("x", 2), {}, {("x", 2): lifted}, {"a"}, None) is lifted
    single = VariableProvenance(storage=-36, value_address=0x20, dwarf_storage_names=frozenset({"a"}))
    assert synthesized_version_origin(("x", 2), {}, {("x", 2): single}, {"a"}, None).source_name == "a"

def test_copy_rule_skips_dwarf_ambiguous_version():
    """The copy rule does not name a version where DWARF matched several source variables."""
    ambiguous = VariableProvenance(value_address=0x20, dwarf_ambiguous=True)
    run_coherence(
        Assignment(x1 := var("x", 1, ambiguous), Constant(0, i32)),
        Assignment(y1 := var("y", 1, dwarf("num")), x1u := var("x", 1, ambiguous)),
        Return([y1u := var("y", 1, dwarf("num"))]),
    )
    assert naming(x1) == naming(x1u) == (None, ())


def test_copy_rule_refuses_target_with_dwarf_storage_names():
    """A copy never names a version whose storage DWARF uses for a source variable."""
    shared = VariableProvenance(storage=5, dwarf_storage_names=frozenset({"i"}))
    run_coherence(
        Assignment(x1 := var("x", 1, shared), Constant(0, i32)),
        Assignment(y1 := var("y", 1, dwarf("num")), x1u := var("x", 1, shared)),
        Return([var("y", 1, dwarf("num"))]),
    )
    assert naming(x1) == naming(x1u) == (None, ())


def test_copy_rule_still_names_pure_temporary():
    """A temporary in storage DWARF never uses for a source variable still gets the copy name."""
    temporary = VariableProvenance(storage=5)
    run_coherence(
        Assignment(x1 := var("x", 1, temporary), Constant(0, i32)),
        Assignment(y1 := var("y", 1, dwarf("num")), x1u := var("x", 1, temporary)),
        Return([var("y", 1, dwarf("num"))]),
    )
    assert naming(x1) == naming(x1u) == ("num", ("copy",))


def _coherence_case(storage_names):
    named = dwarf("a", storage=5, dwarf_storage_names=frozenset(storage_names))
    unnamed = VariableProvenance(storage=5, dwarf_storage_names=frozenset(storage_names))
    run_coherence(
        Assignment(x1 := var("x", 1, named), Constant(0, i32)),
        Assignment(x2 := var("x", 2, unnamed), BinaryOperation(OperationType.plus, [var("x", 1, named), Constant(1, i32)])),
        Return([x2u := var("x", 2, unnamed)]),
    )
    return x2, x2u


def test_coherence_refuses_when_storage_holds_two_names():
    x2, x2u = _coherence_case({"a", "b"})
    assert naming(x2) == naming(x2u) == (None, ())


def test_coherence_still_names_when_storage_holds_one_name():
    x2, x2u = _coherence_case({"a"})
    assert naming(x2) == naming(x2u) == ("a", ("coherence",))
