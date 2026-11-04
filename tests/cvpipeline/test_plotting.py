"""plot_eval_dir on a cross-validation folder: plots averaged over the splits and per split."""

import pytest

from cvpipeline.corpus import make_key
from cvpipeline.plotting import plot_eval_dir
from cvpipeline.storage import read_json, write_json_atomic

pytest.importorskip("matplotlib")


def _evaluation(path, algorithm, functions):
    write_json_atomic(
        path,
        {
            "binary": "b",
            "project": "p",
            "algorithm": algorithm,
            "functions": {
                name: {"status": "success", "message": None, "result": {"variables": [{"variable": v, "lifted": None, "source": s, "kind": "dwarf-local"} for v, s in records]}}
                for name, records in functions.items()
            },
        },
    )


def test_averaged_and_per_split_plots(tmp_path):
    out = tmp_path / "out"
    for index, (function, auc) in enumerate((("f0", 0.75), ("f1", 0.9))):
        split = f"split_{index:03d}"
        write_json_atomic(out / "eval" / split / "holdout.json", {"split": split, "train_blocks": [1 - index], "holdout_blocks": [index], "functions": [make_key("p", "b", function)]})
        _evaluation(out / "eval" / split / "p" / "conditional" / "b.json", "conditional", {function: [("x", "a@0x1"), ("x", "b@0x2")]})
        write_json_atomic(out / "params" / split / "params.json", {"intercept": 0.5, "coef": {"is_strong": 1.0}, "auc": auc, "split": split})
    _evaluation(out / "eval" / "baselines" / "p" / "min" / "b.json", "min", {"f0": [("x", "a@0x1")], "f1": [("y", "b@0x2")]})

    plot_eval_dir(out / "eval", out / "plots")

    averaged = read_json(out / "plots" / "averaged" / "metrics.json")
    assert set(averaged) == {"conditional", "min"} and averaged["conditional"]["splits"] == 2
    for index, auc in enumerate((0.75, 0.9)):
        folder = out / "plots" / "splits" / f"split_{index:03d}"
        assert (folder / "micro_metrics.png").exists()
        metrics = read_json(folder / "metrics.json")
        assert metrics["split"]["auc"] == auc and metrics["split"]["train_blocks"] == [1 - index]
        assert metrics["split"]["intercept"] == 0.5
        assert metrics["conditional"]["splits"] == 1 and metrics["conditional"]["mean"]["functions"] == 1
