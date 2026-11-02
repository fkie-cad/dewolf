#!/usr/bin/env python3
"""Full pipeline: (1) cross-validation training with per-split evaluation, (2) plots averaged
over the splits, (3) evaluation with the averaged params, (4) plots of that evaluation.
Rerun with the same arguments to resume after a crash.

Outputs below <output>: params/, eval/, plots/averaged/, final_eval/, plots/final/."""

import argparse
import sys
from pathlib import Path

from cvpipeline import cli
from cvpipeline.crossval import run_cross_validation
from cvpipeline.evaluation import evaluate_corpus
from cvpipeline.logs import error_log_path, setup_logging
from cvpipeline.plotting import plot_eval_dir


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    cli.add_training_args(parser)
    parser.add_argument(
        "--final-projects",
        type=Path,
        default=None,
        help="project folder for the evaluation with the averaged params (default: --projects; then the result is in-sample)",
    )
    args = parser.parse_args(argv)
    output: Path = args.output
    log = setup_logging(output)

    try:
        log.info("=== 1/4 cross-validation ===")
        averaged = run_cross_validation(cli.crossval_settings(args))

        log.info("=== 2/4 plots averaged over splits ===")
        plot_eval_dir(output / "eval", output / "plots" / "averaged")

        log.info("=== 3/4 evaluation with averaged params ===")
        final_projects = (args.final_projects or args.projects).resolve()
        same_projects = final_projects == args.projects.resolve()
        if same_projects:
            log.warning("final evaluation runs on the training projects: its numbers are in-sample")
        evaluate_corpus(
            # same corpus as training: reuse its fingerprints/dedup instead of recomputing them
            work_dir=output / "work" if same_projects else None,
            projects_dir=final_projects,
            params=averaged,
            output_dir=output / "final_eval",
            settings=cli.pool_settings(args),
            error_log=str(error_log_path(output)),
            baselines=args.baselines,
            timeout_s=cli.function_timeout(args),
        )

        log.info("=== 4/4 plots of the final evaluation ===")
        plot_eval_dir(output / "final_eval", output / "plots" / "final")
    except Exception:
        log.exception("pipeline aborted")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
