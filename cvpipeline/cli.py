"""Argument definitions shared by the cv_*.py entry points."""

from __future__ import annotations

import argparse
from pathlib import Path

from cvpipeline import config
from cvpipeline.crossval import CrossValidationSettings
from cvpipeline.evaluation import BASELINE_ALGORITHMS
from cvpipeline.workers import PoolSettings


def add_worker_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-w", "--workers", type=int, default=4, help="number of worker processes (default: 4)")
    parser.add_argument("--mem-limit", type=float, default=10.0, help="address-space limit per worker in GB (default: 10)")
    parser.add_argument("--job-timeout", type=float, default=4 * 3600, help="wall-clock limit per binary job in seconds (default: 4h)")
    parser.add_argument(
        "--function-timeout", type=float, default=600.0, help="limit per function in seconds; 0 disables it (default: 600)"
    )


def add_baseline_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--baselines",
        nargs="*",
        default=[],
        choices=BASELINE_ALGORITHMS,
        help="out-of-SSA algorithms to evaluate for comparison (default: none)",
    )


def add_strategy_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--strategy",
        type=int,
        default=config.DEFAULT_CONDITIONAL_STRATEGY,
        choices=config.CONDITIONAL_STRATEGIES,
        help=f"variable-class strategy of the conditional renamer (default: {config.DEFAULT_CONDITIONAL_STRATEGY}, greedy merging)",
    )


def add_training_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-i", "--projects", type=Path, required=True, help="folder with one subfolder of binaries per project")
    parser.add_argument("-o", "--output", type=Path, required=True, help="output folder")
    parser.add_argument("-k", type=int, required=True, help="number of blocks")
    parser.add_argument("-t", type=int, default=None, help="training blocks per split (default: k-1)")
    parser.add_argument("--seed", type=int, default=0, help="seed for the block assignment (default: 0)")
    parser.add_argument("--C", type=float, default=1.0, help="inverse L2 regularization strength (default: 1.0)")
    add_strategy_arg(parser)
    parser.add_argument(
        "--function-filter",
        choices=config.FUNCTION_FILTERS,
        default=config.DEFAULT_FUNCTION_FILTER,
        help="which functions contribute training rows: all with labeled pairs (none), those with at least two DWARF source "
        "variables (source-names) or with same- and different-source pairs (both-classes) "
        f"(default: {config.DEFAULT_FUNCTION_FILTER})",
    )
    parser.add_argument(
        "--pair-weighting",
        choices=config.PAIR_WEIGHTINGS,
        default=config.DEFAULT_PAIR_WEIGHTING,
        help="weight of a training row: 1/n for each of the n occurrences of a variable pair, i.e. one per dependency-graph "
        f"edge (edge), or 1 (row) (default: {config.DEFAULT_PAIR_WEIGHTING})",
    )
    add_baseline_arg(parser)
    add_worker_args(parser)


def pool_settings(args: argparse.Namespace) -> PoolSettings:
    return PoolSettings(workers=args.workers, mem_limit_gb=args.mem_limit, job_timeout_s=args.job_timeout)


def function_timeout(args: argparse.Namespace) -> float | None:
    return args.function_timeout or None


def crossval_settings(args: argparse.Namespace) -> CrossValidationSettings:
    """Settings for the arguments added by add_training_args; t defaults to k-1."""
    return CrossValidationSettings(
        projects_dir=args.projects,
        output_dir=args.output,
        k=args.k,
        t=args.k - 1 if args.t is None else args.t,
        seed=args.seed,
        C=args.C,
        strategy=args.strategy,
        function_filter=args.function_filter,
        pair_weighting=args.pair_weighting,
        baselines=tuple(args.baselines),
        pool=pool_settings(args),
        function_timeout_s=function_timeout(args),
    )
