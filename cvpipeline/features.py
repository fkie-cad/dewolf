"""Extracting the training data (every candidate variable pair) for every deduplicated function.

Uses dewolf's own ``conditional_training`` out-of-SSA mode (decompiler/pipeline/ssa/
conditionalSSATraining.py), which writes a function's candidate pairs - the pairs the conditional
renamer scores, labeled or not, with their variables' DWARF sources and the variable pairs that
must stay separate - to the path given in the ``ConditionalResultPath`` environment variable. The
data does not depend on the split, so it is extracted exactly once and cached per binary in
``<work>/features/<project>/<binary>.json``.

Which functions and rows are used for training is decided here, from the cached data: the function
filter (config.FUNCTION_FILTERS) and the row weighting (config.PAIR_WEIGHTINGS) are run parameters,
so changing them needs no new extraction. ``training_data_summary`` reports how many functions were
kept and why the others were dropped.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from cvpipeline import config
from cvpipeline.corpus import FunctionKey, group_by_binary, make_key
from cvpipeline.logs import get_logger
from cvpipeline.storage import read_json
from cvpipeline.workers import Job, PoolSettings, run_jobs

log = get_logger("features")

# Must match the vector layout documented in decompiler/pipeline/ssa/conditional_attribute_helper.py
# and the parameter order ConditionalOutOfSSA expects.
FEATURES = ["is_strong", "is_mid", "same_base_name", "same_storage", "def_by_usage", "func_call", "same_phi"] + [
    f"usage_{i}" for i in range(1, 10)
] + ["following_definitions", "same_rhs_source"]


def feature_path(work_dir: Path, project: str, binary: str) -> Path:
    return work_dir / "features" / project / f"{binary}.json"


def extract_binary_features(binary_path: str, functions: List[str], output_path: str, error_log: str, timeout_s: float | None) -> None:
    """Worker: write ``{"functions": {name: entry}}``; a successful entry's result is the function's
    result file of the conditional_training stage (see FunctionData)."""
    from cvpipeline.decompilation import make_options, process_binary

    scratch = output_path + ".function.json"

    def prepare(_name: str) -> None:
        if os.path.exists(scratch):
            os.remove(scratch)
        os.environ["ConditionalResultPath"] = scratch
        os.environ["ConditionalErrorLogPath"] = error_log

    def analyze(_name, _task) -> dict:
        if not os.path.exists(scratch):
            raise RuntimeError("the training stage wrote no data (see worker_errors.log)")
        with open(scratch) as f:
            return json.load(f)

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
    if os.path.exists(scratch):
        os.remove(scratch)


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


# --------------------------------------------------------------------------------------------- #
# one function's data
# --------------------------------------------------------------------------------------------- #

Source = Tuple[Optional[int], str]  # (DWARF source_id, source_name)
PairKey = Tuple[int, int]  # variable indices, smaller first (the dependency graph is undirected)


@dataclass
class FunctionData:
    """One function's candidate pairs. ``sources[i]`` is the source of variable i (None: no label);
    ``pairs`` are ``(x, y, vector)`` per occurrence; ``interfering`` the variable pairs that must stay
    separate (None: not computed, the function was too large)."""

    names: List[str]
    sources: List[Optional[Source]]
    pairs: List[Tuple[int, int, List[float]]]
    interfering: Optional[List[PairKey]]

    @classmethod
    def from_result(cls, result: Dict[str, Any]) -> "FunctionData":
        names = [name for name, _ in result["variables"]]
        sources = [None if source is None else (source[0], source[1]) for _, source in result["variables"]]
        pairs = [(row[0], row[1], row[2:]) for row in result["pairs"]]
        interfering = None if result["interfering"] is None else [pair_key(i, j) for i, j in result["interfering"]]
        return cls(names, sources, pairs, interfering)

    def goal(self, x: int, y: int) -> Optional[int]:
        """1 if both variables come from the same source, 0 if from different ones, None if unlabeled."""
        if self.sources[x] is None or self.sources[y] is None:
            return None
        return int(self.sources[x] == self.sources[y])

    def labeled_pairs(self) -> List[Tuple[PairKey, List[float], int]]:
        """(pair key, vector, goal) for every labeled occurrence."""
        result = []
        for x, y, vector in self.pairs:
            goal = self.goal(x, y)
            if goal is not None:
                result.append((pair_key(x, y), vector, goal))
        return result


def pair_key(x: int, y: int) -> PairKey:
    return (x, y) if x <= y else (y, x)


def passes_filter(data: FunctionData, function_filter: str) -> bool:
    """Whether the function contributes training rows (see config.FUNCTION_FILTERS). A function
    without labeled pairs never does."""
    labeled = data.labeled_pairs()
    if not labeled:
        return False
    if function_filter == "none":
        return True
    if function_filter == "source-names":
        return len({data.sources[i] for key, _, _ in labeled for i in key}) >= 2
    if function_filter == "both-classes":
        goals = {goal for _, _, goal in labeled}
        return goals == {0, 1}
    raise ValueError(f"unknown function filter '{function_filter}', choose from {config.FUNCTION_FILTERS}")


def training_rows(data: FunctionData, pair_weighting: str) -> List[Tuple[List[float], float]]:
    """``([f_1, ..., f_18, goal], weight)`` for every labeled occurrence (see config.PAIR_WEIGHTINGS)."""
    labeled = data.labeled_pairs()
    if pair_weighting == "row":
        return [([*vector, goal], 1.0) for _, vector, goal in labeled]
    if pair_weighting == "edge":
        occurrences = Counter(key for key, _, _ in labeled)
        return [([*vector, goal], 1.0 / occurrences[key]) for key, vector, goal in labeled]
    raise ValueError(f"unknown pair weighting '{pair_weighting}', choose from {config.PAIR_WEIGHTINGS}")


def iter_function_data(work_dir: Path, keys: Iterable[FunctionKey]) -> Iterator[Tuple[FunctionKey, FunctionData]]:
    """Yield (function, data) for every successfully extracted function among the keys. Reads one
    binary's cache file at a time."""
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
            yield make_key(project, binary, function), FunctionData.from_result(entry["result"])


def iter_training_rows(
    work_dir: Path,
    keys: Iterable[FunctionKey],
    function_filter: str = config.DEFAULT_FUNCTION_FILTER,
    pair_weighting: str = config.DEFAULT_PAIR_WEIGHTING,
) -> Iterator[Tuple[FunctionKey, List[float], float]]:
    """Yield (function, row, weight) for every training row of the functions that pass the filter."""
    for key, data in iter_function_data(work_dir, keys):
        if passes_filter(data, function_filter):
            for row, weight in training_rows(data, pair_weighting):
                yield key, row, weight


# --------------------------------------------------------------------------------------------- #
# kept / dropped report
# --------------------------------------------------------------------------------------------- #

# Categories of training_data_summary, in report order (they add up to "functions").
KEPT = "kept"
DROPPED_NO_LABELED_PAIRS = "dropped_no_labeled_pairs"
DROPPED_BY_FILTER = "dropped_by_filter"
NOT_EXTRACTED = "not_extracted"
MISSING = "missing"
CATEGORIES = (KEPT, DROPPED_NO_LABELED_PAIRS, DROPPED_BY_FILTER, NOT_EXTRACTED, MISSING)
# Properties of the extracted functions with labeled pairs, counted whatever the filter (they show
# what the other filters would drop): only one class of pairs, only one source variable.
SHAPES = ("only_same_source", "only_different_source", "single_source")
# Row counts of the kept functions; "edges" are the distinct labeled pairs, "unlabeled_pairs" the
# candidate pairs without a label (of all extracted functions).
ROW_COUNTS = ("rows", "positive_rows", "edges", "positive_edges", "unlabeled_pairs")
COLUMNS = ("functions", *CATEGORIES, *SHAPES, *ROW_COUNTS)


def entry_data(entry: Dict[str, Any] | None) -> Optional[FunctionData]:
    """The data of a successfully extracted function's entry, else None."""
    return FunctionData.from_result(entry["result"]) if entry is not None and entry.get("status") == "success" else None


def classify_entry(entry: Dict[str, Any] | None, data: Optional[FunctionData], function_filter: str) -> str:
    """The category of one function's feature entry (None: not in the feature file) and its data."""
    if entry is None:
        return MISSING
    if data is None:
        return NOT_EXTRACTED
    if not data.labeled_pairs():
        return DROPPED_NO_LABELED_PAIRS
    return KEPT if passes_filter(data, function_filter) else DROPPED_BY_FILTER


def _empty_counts() -> Dict[str, Any]:
    return {"functions": 0, **{column: 0 for column in COLUMNS[1:]}, "not_extracted_by_status": Counter()}


def _add_function(target: Dict[str, Any], category: str, entry: Dict[str, Any] | None, data: Optional[FunctionData]) -> None:
    target["functions"] += 1
    target[category] += 1
    if category == NOT_EXTRACTED:
        target["not_extracted_by_status"][entry.get("status", "?")] += 1
    if data is None:
        return
    labeled = data.labeled_pairs()
    target["unlabeled_pairs"] += len(data.pairs) - len(labeled)
    if labeled:
        goals = {goal for _, _, goal in labeled}
        target["only_same_source"] += goals == {1}
        target["only_different_source"] += goals == {0}
        target["single_source"] += len({data.sources[i] for key, _, _ in labeled for i in key}) == 1
    if category == KEPT:
        edges = {key: goal for key, _, goal in labeled}
        target["rows"] += len(labeled)
        target["positive_rows"] += sum(goal for _, _, goal in labeled)
        target["edges"] += len(edges)
        target["positive_edges"] += sum(edges.values())


def training_data_summary(work_dir: Path, keys: Iterable[FunctionKey], function_filter: str = config.DEFAULT_FUNCTION_FILTER) -> Dict[str, Any]:
    """How many of the given functions have training data, and why the others have none.

    Reads one binary's feature file at a time. Returns ``{"total": counts, "projects": {project:
    counts}}``, where counts holds the number of functions per category (CATEGORIES, adding up to
    ``functions``), per shape (SHAPES), ``not_extracted_by_status`` (failed, timeout, ...) and the
    row counts (ROW_COUNTS).
    """
    total, projects = _empty_counts(), {}
    for (project, binary), functions in group_by_binary(keys).items():
        counts = projects.setdefault(project, _empty_counts())
        path = feature_path(work_dir, project, binary)
        entries: Dict[str, dict] = read_json(path)["functions"] if path.exists() else {}
        for function in functions:
            entry = entries.get(function)
            data = entry_data(entry)
            category = classify_entry(entry, data, function_filter)
            for target in (total, counts):
                _add_function(target, category, entry, data)
    for counts in [total, *projects.values()]:
        counts["not_extracted_by_status"] = dict(sorted(counts["not_extracted_by_status"].items()))
    return {"total": total, "projects": dict(sorted(projects.items()))}


def describe_training_data(counts: Dict[str, Any], function_filter: str = config.DEFAULT_FUNCTION_FILTER) -> str:
    """One log line for the counts of training_data_summary."""
    statuses = ", ".join(f"{status} {n}" for status, n in counts["not_extracted_by_status"].items())
    text = (
        f"{counts[KEPT]} of {counts['functions']} functions kept ({counts['rows']} rows, {counts['positive_rows']} same source; "
        f"{counts['edges']} distinct pairs, {counts['positive_edges']} same source); "
        f"dropped: {counts[DROPPED_BY_FILTER]} by filter '{function_filter}', {counts[DROPPED_NO_LABELED_PAIRS]} no labeled pairs; "
        f"{counts['unlabeled_pairs']} candidate pairs without label; "
        f"with labeled pairs: {counts['only_same_source']} only same-source, {counts['only_different_source']} only different-source, "
        f"{counts['single_source']} single source"
    )
    text += f"; {counts[NOT_EXTRACTED]} not extracted" + (f" ({statuses})" if statuses else "")
    if counts[MISSING]:
        text += f"; {counts[MISSING]} missing"
    return text
