"""End-to-end smoke test: the full pipeline (cv_pipeline.py) on a few CHStone binaries, then a
second invocation that must resume without recomputing anything.

Needs BinaryNinja (skipped otherwise) and takes a few minutes. Run explicitly with
``pytest tests/cvpipeline/test_smoke.py -p no:xdist``.
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
    averaged = read_json(out / "params" / "averaged.json")
    assert averaged["splits"] == 3 and len(averaged["coef"]) == 16
    for plots in (out / "plots" / "averaged", out / "plots" / "final"):
        assert {"micro_metrics.png", "averaged_metrics.png", "overmerged.png", "undermerged.png", "inserted.png", "output_variables.png"} <= {
            p.name for p in plots.iterdir()
        }
        assert set(read_json(plots / "metrics.json")) == {"conditional", "min"}
    assert any((out / "final_eval" / "chstone" / "conditional").glob("*.json"))

    # Resume: nothing may be recomputed, so no result file may change (averaged.json is cheap and
    # deliberately rewritten from the split params every run).
    results = [p for p in out.rglob("*.json") if "plots" not in p.parts and p.name != "averaged.json"]
    before = {p: p.stat().st_mtime_ns for p in results}
    assert cv_pipeline.main(argv) == 0
    assert {p: p.stat().st_mtime_ns for p in results} == before
