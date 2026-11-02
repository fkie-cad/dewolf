#!/usr/bin/env python3
"""Plot micro/averaged precision, recall, F1 and the over-/undermerged and inserted variables.
Given a cross-validation eval folder (<out>/eval) the metrics are averaged over the splits;
given a single evaluation folder (e.g. cv_evaluate.py output) they are plotted directly."""

import argparse
import sys
from pathlib import Path

from cvpipeline.logs import setup_logging
from cvpipeline.plotting import plot_eval_dir


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-e", "--eval-dir", type=Path, required=True, help="<out>/eval of cv_train.py, or a cv_evaluate.py output folder")
    parser.add_argument("-o", "--output", type=Path, required=True, help="folder for the plots")
    args = parser.parse_args(argv)

    log = setup_logging(args.output)
    try:
        plot_eval_dir(args.eval_dir, args.output)
    except Exception:
        log.exception("plotting aborted")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
