import pytest

from cvpipeline.metrics import average_over_splits, compute_algorithm_metrics, compute_metrics, restrict_to_common


def test_bcubed_by_hand():
    # function f: output var v1 holds sources a, a, b (over-merge); source a also appears under v2
    # (under-merge); one record without source (inserted).
    binaries = {("p", "bin"): {"f": [("v1", "a"), ("v1", "a"), ("v1", "b"), ("v2", "a"), ("v3", None)]}}
    m = compute_algorithm_metrics(binaries)
    # precision clusters: v1 -> [a, a, b] scores 2/3, 2/3, 1/3 ; v2 -> [a] score 1  => 8/3 / 4
    assert m.micro_precision == pytest.approx(100 * (8 / 3) / 4)
    # recall clusters: a -> [v1, v1, v2] scores 2/3, 2/3, 1/3 ; b -> [v1] score 1 => same
    assert m.micro_recall == pytest.approx(100 * (8 / 3) / 4)
    assert (m.overmerged, m.overmerged_total) == (1, 2)
    assert (m.undermerged, m.undermerged_total) == (1, 2)
    assert (m.inserted, m.inserted_total) == (1, 5)
    assert (m.output_variables, m.output_variables_matched) == (3, 2)  # v1, v2, v3; v3 has no source
    assert m.macro_f1 == pytest.approx(m.micro_f1)  # one binary: macro == micro


def test_macro_averages_over_binaries_micro_pools_elements():
    perfect = {"f": [("v", "a")] * 3}
    bad = {"g": [("w", "a"), ("w", "b")]}  # precision 0.5, recall 1
    m = compute_algorithm_metrics({("p", "x"): perfect, ("p", "y"): bad})
    assert m.macro_precision == pytest.approx(100 * (1 + 0.5) / 2)
    assert m.micro_precision == pytest.approx(100 * (3 + 1) / 5)


def test_only_functions_successful_for_all_algorithms_are_compared():
    results = {
        "conditional": {("p", "b"): {"f": [("v", "a")], "g": [("v", "a")]}},
        "min": {("p", "b"): {"f": [("v", "a")]}, ("p", "only_min"): {"h": [("v", "a")]}},
    }
    common = restrict_to_common(results)
    assert common == {"conditional": {("p", "b"): {"f": [("v", "a")]}}, "min": {("p", "b"): {"f": [("v", "a")]}}}
    assert set(compute_metrics(results)) == {"conditional", "min"}


def test_average_over_splits_is_arithmetic_mean():
    s1 = compute_metrics({"c": {("p", "b"): {"f": [("v", "a")]}}})  # P = 100
    s2 = compute_metrics({"c": {("p", "b"): {"f": [("v", "a"), ("v", "b")]}}})  # P = 50
    summary = average_over_splits([s1, s2])["c"]
    assert summary.splits == 2
    assert summary.mean["micro_precision"] == pytest.approx(75)
    assert summary.std["micro_precision"] == pytest.approx(25)


def test_only_locals_and_unmatched_variables_are_scored(tmp_path):
    """Globals and string constants are never renamed by out-of-SSA, so their records are left out."""
    from cvpipeline.metrics import load_results
    from cvpipeline.storage import write_json_atomic

    records = [("x", "a@0x1", "dwarf-local"), ("tmp", None, "unmatched"), ("g", "g@0x9", "dwarf-global"), ("data_1", "%d", "const-string")]
    variables = [{"variable": v, "lifted": None, "source": s, "kind": k} for v, s, k in records]
    write_json_atomic(tmp_path / "p" / "conditional" / "b.json", {"functions": {"f": {"status": "success", "result": {"variables": variables}}}})
    assert load_results(tmp_path) == {"conditional": {("p", "b"): {"f": [("x", "a@0x1"), ("tmp", None)]}}}
