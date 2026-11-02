import os
from pathlib import Path

import pytest

from cvpipeline import config
from cvpipeline.crossval import OutputLayout, _load_or_train_split
from cvpipeline.folds import Split
from cvpipeline.model import Params
from cvpipeline.features import FEATURES
from cvpipeline.storage import FunctionCheckpoint, is_valid_json, write_json_atomic
from cvpipeline.workers import Job, PoolSettings, run_jobs

# --------------------------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------------------------- #


def test_atomic_write_and_truncated_files_count_as_missing(tmp_path):
    path = tmp_path / "x" / "result.json"
    write_json_atomic(path, {"a": 1})
    assert is_valid_json(path)
    assert not (tmp_path / "x" / "result.json.tmp").exists()
    path.write_text('{"a": ')  # what a kill during a non-atomic write would leave behind
    assert not is_valid_json(path)
    assert not is_valid_json(tmp_path / "missing.json")


def test_checkpoint_reuses_done_functions_and_gives_up_on_repeated_kills(tmp_path):
    output = tmp_path / "bin.json"
    checkpoint = FunctionCheckpoint(output)
    checkpoint.start("ok")
    checkpoint.finish("ok", {"status": "success"})
    checkpoint.start("killer")  # the process dies while analyzing this one
    checkpoint.close()

    resumed = FunctionCheckpoint(output)
    assert resumed.done == {"ok": {"status": "success"}}
    assert not resumed.killed_too_often("killer")  # one attempt: retried once
    resumed.start("killer")
    resumed.close()

    again = FunctionCheckpoint(output)
    assert again.killed_too_often("killer")
    assert not again.killed_too_often("ok")
    again.close_and_remove()
    assert not Path(str(output) + ".partial").exists()


def test_checkpoint_tolerates_cut_off_last_line(tmp_path):
    output = tmp_path / "bin.json"
    checkpoint = FunctionCheckpoint(output)
    checkpoint.finish("a", {"status": "success"})
    checkpoint.close()
    with open(str(output) + ".partial", "a") as f:
        f.write('{"event": "done", "name": "b", "en')
    resumed = FunctionCheckpoint(output)
    assert set(resumed.done) == {"a"}
    resumed.finish("c", {"status": "success"})
    resumed.close()
    assert set(FunctionCheckpoint(output).done) == {"a", "c"}


# --------------------------------------------------------------------------------------------- #
# run manifest
# --------------------------------------------------------------------------------------------- #


def test_manifest_mismatch_aborts(tmp_path):
    run = config.RunConfig(projects_dir="/x", k=5, t=4, seed=0, C=1.0)
    config.check_or_write(tmp_path, run)
    config.check_or_write(tmp_path, run)  # same parameters: fine
    with pytest.raises(config.ConfigMismatch, match="k: was 5, now 6"):
        config.check_or_write(tmp_path, config.RunConfig(projects_dir="/x", k=6, t=4, seed=0, C=1.0))


# --------------------------------------------------------------------------------------------- #
# finished splits are not retrained
# --------------------------------------------------------------------------------------------- #


def test_trained_split_is_loaded_not_recomputed(tmp_path):
    layout = OutputLayout(tmp_path)
    split = Split(index=0, train_blocks=(0,), holdout_blocks=(1,))
    stored = Params(coef={name: float(i) for i, name in enumerate(FEATURES)}, intercept=-1.0, metadata={"auc": 0.5})
    stored.save(layout.split_params(split))
    # No feature files exist: training would yield no data and fail, so a returned result proves
    # the cached params.json was used.
    loaded = _load_or_train_split(layout, split, blocks={"p/b::f": 0}, C=1.0)
    assert loaded.coef == stored.coef and loaded.intercept == -1.0


def test_untrainable_split_is_skipped(tmp_path):
    layout = OutputLayout(tmp_path)
    split = Split(index=0, train_blocks=(0,), holdout_blocks=(1,))
    assert _load_or_train_split(layout, split, blocks={"p/b::f": 0}, C=1.0) is None
    assert not layout.split_params(split).exists()


# --------------------------------------------------------------------------------------------- #
# job runner: skips finished jobs, resumes killed jobs that made progress
# --------------------------------------------------------------------------------------------- #


def write_output(path: str, marker: str) -> None:
    open(marker, "a").close()
    write_json_atomic(path, {"done": True})


def die_after_progress(path: str) -> None:
    """Simulates a worker that is killed mid-binary: first attempt checkpoints one function and
    dies, the second attempt finishes."""
    partial = path + ".partial"
    if not os.path.exists(partial):
        with open(partial, "w") as f:
            f.write('{"event": "done", "name": "f", "entry": {}}\n')
        os._exit(1)
    write_json_atomic(path, {"done": True})
    os.remove(partial)


def die_without_progress(path: str) -> None:
    os._exit(1)


def test_run_jobs_skips_done_and_resumes_progressing_jobs(tmp_path):
    settings = PoolSettings(workers=2, mem_limit_gb=4, job_timeout_s=60)
    done = tmp_path / "done.json"
    write_json_atomic(done, {"done": True})
    marker = tmp_path / "ran"
    jobs = [
        Job("already-done", str(done), write_output, (str(done), str(marker))),
        Job("progress", str(tmp_path / "p.json"), die_after_progress, (str(tmp_path / "p.json"),)),
        Job("stuck", str(tmp_path / "s.json"), die_without_progress, (str(tmp_path / "s.json"),)),
    ]
    unfinished = run_jobs(jobs, settings, "test")
    assert not marker.exists(), "a finished job must not run again"
    assert is_valid_json(tmp_path / "p.json")
    assert [job.label for job in unfinished] == ["stuck"]
