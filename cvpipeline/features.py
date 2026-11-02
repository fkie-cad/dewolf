"""Extracting the training vectors (one row per variable pair) for every deduplicated function.

Uses dewolf's own ``conditional_training`` out-of-SSA mode (decompiler/pipeline/ssa/
conditionalSSATraining.py), which writes a function's records to the path given in the
``ConditionalResultPath`` environment variable - or a ``.noTrainingData`` marker if the function
has too few distinct source variables to be useful. The vectors do not depend on the split, so
they are extracted exactly once and cached per binary in ``<work>/features/<project>/<binary>.json``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple

from cvpipeline.corpus import FunctionKey, group_by_binary, make_key
from cvpipeline.logs import get_logger
from cvpipeline.storage import read_json
from cvpipeline.workers import Job, PoolSettings, run_jobs

log = get_logger("features")

# Must match the vector layout documented in decompiler/pipeline/ssa/conditional_attribute_helper.py
# and the parameter order ConditionalOutOfSSA expects.
FEATURES = ["is_strong", "is_mid", "same_base_name", "same_storage", "def_by_usage", "func_call", "same_phi"] + [
    f"usage_{i}" for i in range(1, 10)
]


def feature_path(work_dir: Path, project: str, binary: str) -> Path:
    return work_dir / "features" / project / f"{binary}.json"


def extract_binary_features(binary_path: str, functions: List[str], output_path: str, error_log: str, timeout_s: float | None) -> None:
    """Worker: write ``{"functions": {name: entry}}``; a successful entry's result is
    ``{"rows": [[f_1, ..., f_16, goal], ...]}`` (empty rows: no usable training data)."""
    from cvpipeline.decompilation import make_options, process_binary

    scratch = output_path + ".function.json"

    def prepare(_name: str) -> None:
        for leftover in (scratch, scratch + ".noTrainingData"):
            if os.path.exists(leftover):
                os.remove(leftover)
        os.environ["ConditionalResultPath"] = scratch
        os.environ["ConditionalErrorLogPath"] = error_log

    def analyze(_name, _task) -> dict:
        if os.path.exists(scratch):
            with open(scratch) as f:
                records = json.load(f)
            return {"rows": [list(record["parameters"]) + [record["goal"]] for record in records.values()]}
        if os.path.exists(scratch + ".noTrainingData"):
            return {"rows": []}
        raise RuntimeError("the training stage wrote neither data nor a no-data marker (see worker_errors.log)")

    process_binary(
        binary_path=binary_path,
        functions=functions,
        output_path=output_path,
        options=make_options("conditional_training"),
        analyze=analyze,
        timeout_s=timeout_s,
        error_log=error_log,
        metadata={"binary": binary_path},
        prepare=prepare,
    )
    for leftover in (scratch, scratch + ".noTrainingData"):
        if os.path.exists(leftover):
            os.remove(leftover)


def extract_features(
    projects_dir: Path, work_dir: Path, keys: Iterable[FunctionKey], settings: PoolSettings, error_log: str, timeout_s: float | None
) -> None:
    jobs = []
    for (project, binary), functions in group_by_binary(keys).items():
        output = feature_path(work_dir, project, binary)
        jobs.append(
            Job(
                label=f"{project}/{binary}",
                output_path=str(output),
                func=extract_binary_features,
                args=(str(projects_dir / project / binary), functions, str(output), error_log, timeout_s),
            )
        )
    run_jobs(jobs, settings, "feature extraction")


def iter_rows(work_dir: Path, keys: Iterable[FunctionKey]) -> Iterator[Tuple[FunctionKey, List[float]]]:
    """Yield (function, row) for every training row of the given functions. Reads one binary's
    cache file at a time, so only one binary's rows are in memory besides the caller's result."""
    for (project, binary), functions in group_by_binary(keys).items():
        path = feature_path(work_dir, project, binary)
        if not path.exists():
            log.warning(f"no feature file for {project}/{binary}; its functions are skipped")
            continue
        entries: Dict[str, dict] = read_json(path)["functions"]
        for function in functions:
            entry = entries.get(function)
            if entry is None or entry["status"] != "success":
                continue
            for row in entry["result"]["rows"]:
                yield make_key(project, binary, function), row


def functions_with_data(work_dir: Path, keys: Iterable[FunctionKey]) -> List[FunctionKey]:
    return sorted({key for key, _ in iter_rows(work_dir, keys)})
