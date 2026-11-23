"""Unit tests for the pure merge-quality metric functions of report_variable_matching.py (repo root)."""

import pytest
from report_variable_matching import DEFAULT_LEVELS, Level, Unit, compute_function_metrics, first_level, format_chain, labeled_units, level_metrics, parse_levels, total_metrics

L1, L2, L3, L4, L5 = DEFAULT_LEVELS


def _unit(uid, output, source=None, *via):
    return Unit(id=uid, output=output, source=source, via=tuple(via))


# i#1, i#2 merged (TP); i#3 split off (2 FN); j#1 merged into var_0 with i (2 FP vs i#1, i#2)
UNITS = [
    _unit("i#1", "var_0", "i", "dwarf"),
    _unit("i#2", "var_0", "i", "dwarf", "propagation"),
    _unit("i#3", "var_1", "i", "coherence"),
    _unit("j#1", "var_0", "j", "copy"),
    _unit("t#1", "var_2"),  # unnamed
]


def test_levels_and_chains():
    assert L1.admits(("dwarf",)) and not L1.admits(("dwarf", "propagation"))
    assert L2.admits(("dwarf", "propagation")) and L2.admits(("dwarf", "cse")) and not L2.admits(("coherence",))
    assert L3.admits(("coherence", "cse")) and not L3.admits(("copy",))
    assert L4.admits(("copy",)) and not L4.admits(("dwarf", "identity"))
    assert L5.admits(("dwarf", "identity")) and not L5.admits(())
    assert first_level(("coherence", "propagation")) == "L3 +coherence"
    assert format_chain(("dwarf", "propagation")) == "dwarf>propagation"
    assert [u.id for u in labeled_units(UNITS, L2)] == ["i#1", "i#2"]
    custom = parse_levels("dwarf, copy")[-1]
    assert custom.name == "custom" and custom.mechanisms == {"dwarf", "copy"}
    assert len(parse_levels(None)) == len(DEFAULT_LEVELS)


def test_pairwise_counts_per_level():
    l1, _ = level_metrics(UNITS, L1, None)
    assert (l1.labeled, l1.units, l1.tp, l1.fp, l1.fn) == (1, 5, 0, 0, 0)
    assert l1.precision is None and l1.recall is None and l1.f1 is None

    l2, _ = level_metrics(UNITS, L2, None)
    assert (l2.tp, l2.fp, l2.fn) == (1, 0, 0)
    assert l2.precision == 1.0 and l2.recall == 1.0 and l2.f1 == 1.0

    l3, errors = level_metrics(UNITS, L3, None)
    assert (l3.tp, l3.fp, l3.fn) == (1, 0, 2)
    assert l3.recall == pytest.approx(1 / 3)
    assert {(e.kind, e.a.id, e.b.id) for e in errors} == {("FN", "i#1", "i#3"), ("FN", "i#2", "i#3")}

    l4, _ = level_metrics(UNITS, L4, None)
    assert (l4.tp, l4.fp, l4.fn, l4.sources) == (1, 2, 2, 2)
    assert l4.precision == pytest.approx(1 / 3)
    assert l4.f1 == pytest.approx(1 / 3)


def test_achievable_recall_excludes_interfering_fn():
    interference = {frozenset(("i#1", "i#3")), frozenset(("i#1", "j#1"))}
    metrics, errors = level_metrics(UNITS, L4, interference)
    assert metrics.fn == 2 and metrics.fn_interfering == 1
    assert metrics.recall == pytest.approx(1 / 3)
    assert metrics.recall_achievable == pytest.approx(1 / 2)
    assert metrics.f1_achievable == pytest.approx(2 * (1 / 3) * (1 / 2) / (1 / 3 + 1 / 2))
    # interference on an FP pair is recorded but does not change precision
    fp = [e for e in errors if e.kind == "FP" and {e.a.id, e.b.id} == {"i#1", "j#1"}]
    assert fp and fp[0].interfering and metrics.precision == pytest.approx(1 / 3)


def test_function_metrics_coverage():
    metrics = compute_function_metrics(UNITS, DEFAULT_LEVELS, {frozenset(("i#1", "i#3"))}, dwarf_variables=["i", "gone"])
    assert metrics.units == 5 and metrics.named_units == 4
    assert metrics.lost == ["gone"]
    assert [m.labeled for m in metrics.levels] == [1, 2, 3, 4, 4]
    # errors are taken from the union of all levels
    assert sorted(e.kind for e in metrics.errors) == ["FN", "FN", "FP", "FP"]


def test_total_sums_counts():
    perfect = compute_function_metrics([_unit("a#1", "v", "a", "dwarf"), _unit("a#2", "v", "a", "dwarf")], DEFAULT_LEVELS, None)
    split = compute_function_metrics([_unit("a#1", "v", "a", "dwarf"), _unit("a#2", "w", "a", "dwarf")], DEFAULT_LEVELS, None)
    total_l1 = total_metrics([perfect, split], DEFAULT_LEVELS)[0]
    assert (total_l1.tp, total_l1.fp, total_l1.fn, total_l1.labeled) == (1, 0, 1, 4)
    assert total_l1.recall == 0.5 and total_l1.f1 == pytest.approx(2 / 3)


def test_custom_level_in_union():
    levels = list(DEFAULT_LEVELS[:2]) + [Level("custom", frozenset({"copy"}))]
    metrics = compute_function_metrics(UNITS, levels, None)
    # union = L2 ∪ {copy}: i#1, i#2, j#1 -> 2 FP pairs, no FN (i#3 coherence not admitted)
    assert sorted(e.kind for e in metrics.errors) == ["FP", "FP"]
    assert metrics.levels[2].labeled == 1
