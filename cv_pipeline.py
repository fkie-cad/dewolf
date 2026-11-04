#!/usr/bin/env python3
"""Full pipeline: (1) cross-validation training with per-split evaluation (every split's model is
evaluated on its holdout functions with its own params), (2) plots - averaged over the splits and
one set per split. Rerun with the same arguments to resume after a crash.

Outputs below <output>: params/, eval/, training_data.json/csv, plots/averaged/, plots/splits/<split>/."""

import argparse
import sys

from cvpipeline import cli
from cvpipeline.crossval import run_cross_validation
from cvpipeline.logs import setup_logging
from cvpipeline.plotting import plot_eval_dir


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    cli.add_training_args(parser)
    args = parser.parse_args(argv)
    output = args.output
    log = setup_logging(output)

    try:
        log.info("=== 1/2 cross-validation ===")
        run_cross_validation(cli.crossval_settings(args))

        log.info("=== 2/2 plots: averaged over the splits and per split ===")
        plot_eval_dir(output / "eval", output / "plots")
    except Exception:
        log.exception("pipeline aborted")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
