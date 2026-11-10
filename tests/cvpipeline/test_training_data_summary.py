"""Training data from the cached candidate pairs: function filter, row weighting, the kept/dropped
report and the unlabeled-edge counts."""

import pytest

from cvpipeline import config
from cvpipeline.corpus import make_key
from cvpipeline.edge_labels import edge_label_counts, function_edge_counts
from cvpipeline.features import (
    FEATURES,
    FunctionData,
    describe_training_data,
    feature_path,
    iter_training_rows,
    passes_filter,
    training_data_summary,
    training_rows,
)
from cvpipeline.model import Params
from cvpipeline.storage import write_json_atomic

A, B, I = [1, "a"], [2, "b"], [3, "i"]  # DWARF sources [source_id, source_name]
I_OTHER = [4, "i"]  # a different source variable that is also called i
STRONG = [1] + [0] * (len(FEATURES) - 1)  # is_strong set
ZERO = [0] * len(FEATURES)


def result(sources, pairs, interfering=()):
    """A training-stage result: sources per variable, pairs as (x, y, vector)."""
    return {
        "variables": [[f"v{i}#0", source] for i, source in enumerate(sources)],
        "pairs": [[x, y, *vector] for x, y, vector in pairs],
        "interfering": None if interfering is None else [list(pair) for pair in interfering],
    }


def success(data):
    return {"status": "success", "message": None, "result": data}


def _write(work, project, binary, functions):
    write_json_atomic(feature_path(work, project, binary), {"binary": binary, "functions": functions})


ONLY_SAME = result([A, A, None], [(0, 1, STRONG), (1, 2, STRONG)])  # one labeled positive, one unlabeled
ONLY_DIFFERENT = result([A, B], [(0, 1, ZERO)])
BOTH = result([A, A, B], [(0, 1, STRONG), (0, 2, ZERO)])
SAME_NAME_TWO_SOURCES = result([I, I_OTHER], [(0, 1, ZERO)])
UNLABELED_ONLY = result([None, A], [(0, 1, STRONG)])


@pytest.mark.parametrize(
    "function_filter, expected",
    [
        ("none", [True, True, True, True, False]),
        ("source-names", [False, True, True, True, False]),
        ("both-classes", [False, False, True, False, False]),
    ],
)
def test_function_filters(function_filter, expected):
    functions = [ONLY_SAME, ONLY_DIFFERENT, BOTH, SAME_NAME_TWO_SOURCES, UNLABELED_ONLY]
    assert [passes_filter(FunctionData.from_result(f), function_filter) for f in functions] == expected


def test_edge_weighting_gives_every_distinct_pair_weight_one():
    # pair {0, 1} occurs three times (once reversed), pair {0, 2} once, pair {1, 3} is unlabeled
    data = FunctionData.from_result(result([A, A, B, None], [(0, 1, STRONG), (1, 0, STRONG), (0, 1, ZERO), (0, 2, ZERO), (1, 3, ZERO)]))
    edge = training_rows(data, "edge")
    assert [weight for _, weight in edge] == pytest.approx([1 / 3, 1 / 3, 1 / 3, 1.0])
    assert [row[-1] for row, _ in edge] == [1, 1, 1, 0]
    assert [weight for _, weight in training_rows(data, "row")] == [1.0] * 4


def test_iter_training_rows_applies_filter_and_weighting(tmp_path):
    _write(tmp_path, "p", "b", {"same": success(ONLY_SAME), "both": success(BOTH)})
    keys = [make_key("p", "b", "same"), make_key("p", "b", "both")]
    rows = list(iter_training_rows(tmp_path, keys, "both-classes", "edge"))
    assert [key for key, _, _ in rows] == [make_key("p", "b", "both")] * 2
    assert [len(row) for _, row, _ in rows] == [len(FEATURES) + 1] * 2
    assert len(list(iter_training_rows(tmp_path, keys, "none", "edge"))) == 3


def test_every_category_is_counted_per_project_and_in_total(tmp_path):
    _write(
        tmp_path,
        "p1",
        "a",
        {
            "both": success(BOTH),
            "only_same": success(ONLY_SAME),
            "unlabeled_only": success(UNLABELED_ONLY),
            "no_pairs": success(result([], [])),
            "timed_out": {"status": "timeout", "message": "exceeded", "result": None},
            "failed": {"status": "failed", "message": "stage", "result": None},
        },
    )
    _write(tmp_path, "p2", "b", {"different": success(ONLY_DIFFERENT)})
    keys = [make_key("p1", "a", name) for name in ("both", "only_same", "unlabeled_only", "no_pairs", "timed_out", "failed", "not_in_file")]
    keys += [make_key("p2", "b", "different"), make_key("p2", "no_file", "f")]

    summary = training_data_summary(tmp_path, keys, "source-names")
    p1, p2, total = summary["projects"]["p1"], summary["projects"]["p2"], summary["total"]
    assert {k: p1[k] for k in ("functions", "kept", "dropped_no_labeled_pairs", "dropped_by_filter", "not_extracted", "missing")} == {
        "functions": 7, "kept": 1, "dropped_no_labeled_pairs": 2, "dropped_by_filter": 1, "not_extracted": 2, "missing": 1,
    }
    assert p1["not_extracted_by_status"] == {"failed": 1, "timeout": 1}
    assert (p1["only_same_source"], p1["only_different_source"], p1["single_source"]) == (1, 0, 1)
    assert (p1["rows"], p1["positive_rows"], p1["edges"], p1["positive_edges"], p1["unlabeled_pairs"]) == (2, 1, 2, 1, 2)
    assert (p2["functions"], p2["kept"], p2["missing"], p2["only_different_source"]) == (2, 1, 1, 1)
    assert (total["functions"], total["kept"], total["missing"], total["rows"]) == (9, 2, 2, 3)
    line = describe_training_data(total, "source-names")
    assert line.startswith("2 of 9 functions kept") and "1 by filter 'source-names'" in line and "timeout 1" in line


def test_edge_counts_follow_the_scores_and_contested_components():
    # strong copies score > 0, zero vectors do not (intercept -1, is_strong +2)
    params = Params(coef={name: (2.0 if name == "is_strong" else 0.0) for name in FEATURES}, intercept=-1.0)
    data = FunctionData.from_result(
        result(
            [A, None, None, B, B],
            # component {0, 1, 2}: 0-1 (one unlabeled), 1-2 (both unlabeled, occurs twice), 0-2 scores <= 0
            # component {3, 4}: 3-4 labeled; 0 and 2 must stay separate -> only the first is contested
            [(0, 1, STRONG), (1, 2, STRONG), (2, 1, STRONG), (0, 2, ZERO), (3, 4, STRONG)],
            interfering=[(0, 2)],
        )
    )
    counts = function_edge_counts(data, params.coefficients(), params.intercept)
    assert {k: counts[k] for k in ("edges", "edges_one_unlabeled", "edges_both_unlabeled")} == {
        "edges": 3, "edges_one_unlabeled": 1, "edges_both_unlabeled": 1,
    }
    assert {k: counts[k] for k in ("contested_edges", "contested_edges_one_unlabeled", "contested_edges_both_unlabeled")} == {
        "contested_edges": 2, "contested_edges_one_unlabeled": 1, "contested_edges_both_unlabeled": 1,
    }
    unknown = FunctionData.from_result(result([A, None], [(0, 1, STRONG)], interfering=None))
    counts = function_edge_counts(unknown, params.coefficients(), params.intercept)
    assert (counts["edges"], counts["contested_edges"], counts["functions_interference_unknown"]) == (1, 0, 1)


def test_edge_label_counts_sums_over_functions(tmp_path):
    params = Params(coef={name: (2.0 if name == "is_strong" else 0.0) for name in FEATURES}, intercept=-1.0)
    _write(tmp_path, "p", "b", {"same": success(ONLY_SAME), "both": success(BOTH)})
    counts = edge_label_counts(tmp_path, [make_key("p", "b", "same"), make_key("p", "b", "both")], params)
    assert (counts["functions"], counts["edges"], counts["edges_one_unlabeled"]) == (2, 3, 1)


def test_retraining_a_split_discards_its_old_conditional_evaluation(tmp_path):
    """Results evaluated with earlier weights must not be reused after the split's params.json was deleted."""
    from cvpipeline.crossval import OutputLayout, _load_or_train_split
    from cvpipeline.folds import Split

    layout = OutputLayout(tmp_path)
    split = Split(index=0, train_blocks=(0,), holdout_blocks=(1,))
    _write(layout.work, "p", "b", {"f0": success(BOTH), "f1": success(BOTH)})
    blocks = {make_key("p", "b", "f0"): 0, make_key("p", "b", "f1"): 1}
    old_result = layout.split_eval(split) / "p" / "conditional" / "b.json"
    old_checkpoint = layout.split_eval(split) / "p" / "conditional" / "c.json.partial"
    kept = [layout.split_holdout(split), layout.baselines / "p" / "min" / "b.json"]
    for path in [old_result, *kept]:
        write_json_atomic(path, {"functions": {}})
    old_checkpoint.write_text("{}\n")

    assert _load_or_train_split(layout, split, blocks, C=1.0, function_filter="none") is not None
    assert not old_result.exists() and not old_checkpoint.exists()
    assert all(path.exists() for path in kept)

    # a split that is already trained is only loaded: its results stay
    write_json_atomic(old_result, {"functions": {}})
    assert _load_or_train_split(layout, split, blocks, C=1.0, function_filter="none") is not None
    assert old_result.exists()
