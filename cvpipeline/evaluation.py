"""Evaluation: decompile functions with a given out-of-SSA algorithm and match the resulting
variables against DWARF (variable_matching.py).

Result layout (same in every place it is used):
``<root>/<project>/<algorithm>/<binary>.json`` with
``{"binary", "project", "algorithm", "functions": {name: {"status", "message", "result"}}}``.

``cv_train.py`` uses ``make_jobs`` per split (root ``<out>/eval/split_i``) and once for the
baselines (root ``<out>/eval/baselines``); ``cv_evaluate.py`` uses ``evaluate_corpus``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from cvpipeline.corpus import FunctionKey, group_by_binary, load_or_deduplicate
from cvpipeline.logs import get_logger
from cvpipeline.model import Params
from cvpipeline.workers import Job, PoolSettings, run_jobs

log = get_logger("evaluation")

CONDITIONAL = "conditional"
# Out-of-SSA modes that make sense as comparison baselines (conditional_training only extracts
# training data and does not rename variables).
BASELINE_ALGORITHMS = ("simple", "min", "lift_minimal", "sreedhar", "boissinot2008")


@dataclass(frozen=True)
class Algorithm:
    """What to evaluate: an out-of-SSA mode, plus fixed weights for the conditional mode."""

    name: str
    weights: Optional[Tuple[Tuple[float, ...], float]] = None  # (coefficients in FEATURES order, intercept)

    @classmethod
    def conditional(cls, params: Params) -> "Algorithm":
        return cls(CONDITIONAL, (tuple(params.coefficients()), params.intercept))

    @classmethod
    def baseline(cls, name: str) -> "Algorithm":
        if name not in BASELINE_ALGORITHMS:
            raise ValueError(f"unknown baseline '{name}', choose from {', '.join(BASELINE_ALGORITHMS)}")
        return cls(name)


def result_path(root: Path, project: str, algorithm: str, binary: str) -> Path:
    return root / project / algorithm / f"{binary}.json"


def evaluate_binary(
    binary_path: str,
    project: str,
    functions: List[str],
    output_path: str,
    algorithm: Algorithm,
    error_log: str,
    timeout_s: float | None,
) -> None:
    """Worker entry point."""
    from cvpipeline.decompilation import install_conditional_weights, make_options, process_binary
    from cvpipeline.variable_matching import build_report

    if algorithm.weights is not None:
        coefficients, intercept = algorithm.weights
        install_conditional_weights(list(coefficients), intercept)
    process_binary(
        binary_path=binary_path,
        functions=functions,
        output_path=output_path,
        options=make_options(algorithm.name),
        analyze=lambda _name, task: build_report(task),
        timeout_s=timeout_s,
        error_log=error_log,
        metadata={"binary": binary_path, "project": project, "algorithm": algorithm.name},
    )


def make_jobs(
    projects_dir: Path,
    root: Path,
    keys: Iterable[FunctionKey],
    algorithm: Algorithm,
    error_log: str,
    timeout_s: float | None,
    label_prefix: str = "",
) -> List[Job]:
    """One job per binary that has at least one of ``keys``."""
    jobs = []
    for (project, binary), functions in group_by_binary(keys).items():
        output = result_path(root, project, algorithm.name, binary)
        jobs.append(
            Job(
                label=f"{label_prefix}{project}/{algorithm.name}/{binary}",
                output_path=str(output),
                func=evaluate_binary,
                args=(str(projects_dir / project / binary), project, functions, str(output), algorithm, error_log, timeout_s),
            )
        )
    return jobs


def evaluate_corpus(
    projects_dir: Path,
    params: Params,
    output_dir: Path,
    settings: PoolSettings,
    error_log: str,
    baselines: Sequence[str] = (),
    timeout_s: float | None = None,
    work_dir: Optional[Path] = None,
) -> None:
    """Evaluate every deduplicated function of ``projects_dir`` with fixed weights (and optional
    baselines). Results go to ``<output_dir>/<project>/<algorithm>/<binary>.json`` (single-eval
    layout for cv_plot.py); the dedup cache to ``work_dir`` (default ``<output_dir>/work``)."""
    dedup = load_or_deduplicate(projects_dir, work_dir or output_dir / "work", settings, error_log)
    algorithms = [Algorithm.conditional(params)] + [Algorithm.baseline(name) for name in baselines]
    jobs = []
    for algorithm in algorithms:
        jobs += make_jobs(projects_dir, output_dir, dedup.kept, algorithm, error_log, timeout_s)
    run_jobs(jobs, settings, "evaluation")
