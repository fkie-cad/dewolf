"""End-to-end smoke test: the full pipeline (cv_pipeline.py) on a few CHStone binaries, then a
second invocation that must resume without recomputing anything.

Needs BinaryNinja (skipped otherwise) and takes a few minutes. Run explicitly with
``pytest tests/cvpipeline/test_smoke.py -n 0``.
"""

import shutil
from pathlib import Path

import pytest

pytest.importorskip("binaryninja")

import cv_pipeline  # noqa: E402
from cvpipeline.storage import read_json  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SAMPLE_BINARIES = ["aes", "blowfish", "jpeg", "sha"]  # CHStone, contain functions with training data


@pytest.fixture
def projects(tmp_path):
    source = REPO / "input" / "chstone"
    if not all((source / name).exists() for name in SAMPLE_BINARIES):
        pytest.skip(f"sample binaries not found in {source}")
    target = tmp_path / "projects" / "chstone"
    target.mkdir(parents=True)
    for name in SAMPLE_BINARIES:
        shutil.copy(source / name, target / name)
    return tmp_path / "projects"


def test_full_pipeline_and_resume(projects, tmp_path):
    out = tmp_path / "out"
    argv = ["-i", str(projects), "-o", str(out), "-k", "3", "-w", "4", "--baselines", "min", "--function-timeout", "300"]
    assert cv_pipeline.main(argv) == 0

    for i in range(3):  # C(3, 2) = 3 splits
        split = f"split_{i:03d}"
        assert (out / "params" / split / "params.json").exists()
        assert "auc:" in (out / "params" / split / "auc.txt").read_text()
        assert (out / "eval" / split / "holdout.json").exists()
    plots = ["micro_metrics.png", "averaged_metrics.png", "overmerged.png", "undermerged.png", "inserted.png", "output_variables.png"]
    for folder in [out / "plots" / "averaged"] + [out / "plots" / "splits" / f"split_{i:03d}" for i in range(3)]:
        assert set(plots) <= {p.name for p in folder.iterdir()}, folder
        metrics = read_json(folder / "metrics.json")
        assert {"conditional", "min"} <= set(metrics)
        if folder.parent.name == "splits":  # a split's own plots carry its blocks and AUC
            assert metrics["split"]["split"] == folder.name and "auc" in metrics["split"] and metrics["split"]["train_blocks"]
        else:
            assert "split" not in metrics
    assert not (out / "params" / "averaged.json").exists() and not (out / "final_eval").exists() and not (out / "plots" / "final").exists()

    summary = read_json(out / "training_data.json")["total"]
    kept_functions = len(read_json(out / "work" / "dedup.json")["kept"])
    categories = ["kept", "dropped_no_labeled_pairs", "dropped_by_filter", "not_extracted", "missing"]
    assert summary["functions"] == kept_functions == sum(summary[c] for c in categories)
    assert summary["kept"] > 0 and summary["missing"] == 0
    split_params = read_json(out / "params" / "split_000" / "params.json")
    assert split_params["function_filter"] == "source-names" and split_params["holdout_edges"]["edges"] > 0
    assert "TOTAL" in (out / "training_data.csv").read_text()

    # Resume: nothing may be recomputed, so no result file may change (training_data.json is cheap
    # and deliberately recomputed from the feature files every run).
    results = [p for p in out.rglob("*.json") if "plots" not in p.parts and p.name != "training_data.json"]
    before = {p: p.stat().st_mtime_ns for p in results}
    assert cv_pipeline.main(argv) == 0
    assert {p: p.stat().st_mtime_ns for p in results} == before
