"""Logging setup: everything goes to ``<out>/logs/pipeline.log``, warnings and errors additionally
to ``<out>/logs/errors.log``, and INFO and above to the console."""

from __future__ import annotations

import logging
from pathlib import Path

LOGGER_NAME = "cvpipeline"


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(LOGGER_NAME if name is None else f"{LOGGER_NAME}.{name}")


def setup_logging(output_dir: str | Path) -> logging.Logger:
    """Configure the package logger once per output directory (idempotent)."""
    log_dir = Path(output_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = get_logger()
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    handlers = [
        (logging.FileHandler(log_dir / "pipeline.log"), logging.DEBUG),
        (logging.FileHandler(log_dir / "errors.log"), logging.WARNING),
        (logging.StreamHandler(), logging.INFO),
    ]
    for handler, level in handlers:
        handler.setLevel(level)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def error_log_path(output_dir: str | Path) -> Path:
    """Plain-text log that worker processes append tracebacks to (they do not share the parent's
    logging handlers, since they are spawned, not forked)."""
    path = Path(output_dir) / "logs" / "worker_errors.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def append_worker_error(path: str | Path, message: str) -> None:
    with open(path, "a") as f:
        f.write(message.rstrip("\n") + "\n")
