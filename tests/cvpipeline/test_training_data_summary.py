"""training_data_summary: which functions have training data, and why the others were dropped."""

from cvpipeline.corpus import make_key
from cvpipeline.features import describe_training_data, feature_path, training_data_summary
from cvpipeline.storage import write_json_atomic

MARKER = {"min_same_source": 1, "min_different_source": 1}


def _write(work, project, binary, functions):
    write_json_atomic(feature_path(work, project, binary), {"binary": binary, "functions": functions})


def test_every_category_is_counted_per_project_and_in_total(tmp_path):
    success = lambda result: {"status": "success", "message": None, "result": result}
    _write(
        tmp_path,
        "p1",
        "a",
        {
            "kept": success({"rows": [[0] * 16 + [1], [0] * 16 + [0], [0] * 16 + [1]]}),
            "no_pairs": success({"rows": [], "same_source": 0, "different_source": 0, **MARKER}),
            "only_same": success({"rows": [], "same_source": 4, "different_source": 0, **MARKER}),
            "only_different": success({"rows": [], "same_source": 0, "different_source": 2, **MARKER}),
            "old_marker": success({"rows": []}),
            "timed_out": {"status": "timeout", "message": "exceeded", "result": None},
            "failed": {"status": "failed", "message": "stage", "result": None},
        },
    )
    _write(tmp_path, "p2", "b", {"kept": success({"rows": [[0] * 16 + [0]]})})
    keys = [make_key("p1", "a", name) for name in ("kept", "no_pairs", "only_same", "only_different", "old_marker", "timed_out", "failed", "not_in_file")]
    keys += [make_key("p2", "b", "kept"), make_key("p2", "no_file", "f")]

    summary = training_data_summary(tmp_path, keys)
    p1, p2, total = summary["projects"]["p1"], summary["projects"]["p2"], summary["total"]
    assert {k: p1[k] for k in ("functions", "kept", "dropped_no_pairs", "dropped_only_same_source", "dropped_only_different_source", "dropped_reason_unknown", "not_extracted", "missing")} == {
        "functions": 8, "kept": 1, "dropped_no_pairs": 1, "dropped_only_same_source": 1, "dropped_only_different_source": 1,
        "dropped_reason_unknown": 1, "not_extracted": 2, "missing": 1,
    }
    assert p1["not_extracted_by_status"] == {"failed": 1, "timeout": 1}
    assert (p1["rows"], p1["positive_rows"]) == (3, 2)
    assert (p2["functions"], p2["kept"], p2["missing"], p2["rows"], p2["positive_rows"]) == (2, 1, 1, 1, 0)
    assert (total["functions"], total["kept"], total["missing"], total["rows"]) == (10, 2, 2, 4)
    line = describe_training_data(total)
    assert line.startswith("2 of 10 functions kept") and "1 only same-source pairs" in line and "timeout 1" in line
