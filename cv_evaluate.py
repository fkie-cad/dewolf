#!/usr/bin/env python3
"""Evaluate fixed weights from a params.json on every (deduplicated) function of a project
folder. Output layout: <output>/<project>/<algorithm>/<binary>.json. Rerun to resume."""

import argparse
import sys
from pathlib import Path

from cvpipeline import cli
from cvpipeline.evaluation import evaluate_corpus
from cvpipeline.logs import error_log_path, setup_logging
from cvpipeline.model import Params


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--projects", type=Path, required=True, help="folder with one subfolder of binaries per project")
    parser.add_argument("-p", "--params", type=Path, required=True, help="params.json with the weights to evaluate")
    parser.add_argument("-o", "--output", type=Path, required=True, help="output folder")
    cli.add_baseline_arg(parser)
    cli.add_worker_args(parser)
    args = parser.parse_args(argv)

    log = setup_logging(args.output)
    try:
        evaluate_corpus(
            projects_dir=args.projects.resolve(),
            params=Params.load(args.params),
            output_dir=args.output,
            settings=cli.pool_settings(args),
            error_log=str(error_log_path(args.output)),
            baselines=args.baselines,
            timeout_s=cli.function_timeout(args),
        )
    except Exception:
        log.exception("evaluation aborted")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
