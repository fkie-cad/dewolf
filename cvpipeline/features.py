"""Extracting the training vectors (one row per variable pair) for every deduplicated function.

Uses dewolf's own ``conditional_training`` out-of-SSA mode (decompiler/pipeline/ssa/
conditionalSSATraining.py), which writes a function's records to the path given in the
``ConditionalResultPath`` environment variable - or a ``.noTrainingData`` marker if the function
does not have at least MIN_SAME_SOURCE_RECORDS same-source and MIN_DIFFERENT_SOURCE_RECORDS
different-source pairs (the marker holds both counts and thresholds). The vectors do not depend on
the split, so they are extracted exactly once and cached per binary in
``<work>/features/<project>/<binary>.json``. ``training_data_summary`` reports how many functions
were kept and why the others were dropped.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from collections import Counter
from typing import Any, Dict, Iterable, Iterator, List, Tuple

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
    ``{"rows": [[f_1, ..., f_16, goal], ...]}``. Empty rows mean no usable training data; the
    result then also carries the marker's counts (``same_source``, ``different_source``,
    ``min_same_source``, ``min_different_source``), if the marker has them."""
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
            with open(scratch + ".noTrainingData") as f:
                content = f.read().strip()
            return {"rows": [], **(json.loads(content) if content else {})}  # an empty marker: older stage
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


# Categories of training_data_summary, in report order.
KEPT = "kept"
DROPPED_NO_PAIRS = "dropped_no_pairs"
DROPPED_ONLY_SAME = "dropped_only_same_source"
DROPPED_ONLY_DIFFERENT = "dropped_only_different_source"
DROPPED_UNKNOWN = "dropped_reason_unknown"
NOT_EXTRACTED = "not_extracted"
MISSING = "missing"
CATEGORIES = (KEPT, DROPPED_NO_PAIRS, DROPPED_ONLY_SAME, DROPPED_ONLY_DIFFERENT, DROPPED_UNKNOWN, NOT_EXTRACTED, MISSING)


def classify_entry(entry: Dict[str, Any] | None) -> str:
    """The category of one function's feature entry (None: not in the feature file)."""
    if entry is None:
        return MISSING
    if entry.get("status") != "success":
        return NOT_EXTRACTED
    result = entry.get("result") or {}
    if result.get("rows"):
        return KEPT
    if "same_source" not in result:
        return DROPPED_UNKNOWN
    same, different = result["same_source"], result["different_source"]
    if same == 0 and different == 0:
        return DROPPED_NO_PAIRS
    if different < result.get("min_different_source", 1):
        return DROPPED_ONLY_SAME
    return DROPPED_ONLY_DIFFERENT


def _empty_counts() -> Dict[str, Any]:
    return {"functions": 0, **{category: 0 for category in CATEGORIES}, "not_extracted_by_status": Counter(), "rows": 0, "positive_rows": 0}


def training_data_summary(work_dir: Path, keys: Iterable[FunctionKey]) -> Dict[str, Any]:
    """How many of the given functions have training data, and why the others have none.

    Reads one binary's feature file at a time. Returns ``{"total": counts, "projects": {project:
    counts}}``, where counts holds the number of functions per category (see CATEGORIES; the
    categories add up to ``functions``), ``not_extracted_by_status`` (failed, timeout, ...) and the
    number of rows and positive (same-source) rows of the kept functions.
    """
    total, projects = _empty_counts(), {}
    for (project, binary), functions in group_by_binary(keys).items():
        counts = projects.setdefault(project, _empty_counts())
        path = feature_path(work_dir, project, binary)
        entries: Dict[str, dict] = read_json(path)["functions"] if path.exists() else {}
        for function in functions:
            entry = entries.get(function)
            category = classify_entry(entry)
            for target in (total, counts):
                target["functions"] += 1
                target[category] += 1
                if category == NOT_EXTRACTED:
                    target["not_extracted_by_status"][entry.get("status", "?")] += 1
                if category == KEPT:
                    rows = entry["result"]["rows"]
                    target["rows"] += len(rows)
                    target["positive_rows"] += sum(1 for row in rows if row[-1] == 1)
    for counts in [total, *projects.values()]:
        counts["not_extracted_by_status"] = dict(sorted(counts["not_extracted_by_status"].items()))
    return {"total": total, "projects": dict(sorted(projects.items()))}


def describe_training_data(counts: Dict[str, Any]) -> str:
    """One log line for the counts of training_data_summary."""
    statuses = ", ".join(f"{status} {n}" for status, n in counts["not_extracted_by_status"].items())
    text = (
        f"{counts[KEPT]} of {counts['functions']} functions kept ({counts['rows']} rows, {counts['positive_rows']} same source); "
        f"dropped: {counts[DROPPED_ONLY_SAME]} only same-source pairs, {counts[DROPPED_ONLY_DIFFERENT]} only different-source pairs, "
        f"{counts[DROPPED_NO_PAIRS]} no pairs"
    )
    if counts[DROPPED_UNKNOWN]:
        text += f", {counts[DROPPED_UNKNOWN]} reason unknown (feature cache from an older version)"
    text += f"; {counts[NOT_EXTRACTED]} not extracted" + (f" ({statuses})" if statuses else "")
    if counts[MISSING]:
        text += f"; {counts[MISSING]} missing"
    return text
