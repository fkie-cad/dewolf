#!/usr/bin/env python3
"""k-fold cross-validation training: trains one model per split, computes its AUC on the holdout
blocks and evaluates it on the holdout functions. Rerun with the same arguments to resume."""

import argparse
import sys

from cvpipeline import cli
from cvpipeline.crossval import run_cross_validation
from cvpipeline.logs import setup_logging


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    cli.add_training_args(parser)
    args = parser.parse_args(argv)
    log = setup_logging(args.output)
    try:
        run_cross_validation(cli.crossval_settings(args))
    except Exception:
        log.exception("cross-validation aborted")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
