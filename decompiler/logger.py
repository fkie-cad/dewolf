"""Module in charge of logger initialization and settings."""
import logging.config
from typing import Optional

from binaryninja import core_ui_enabled
from decompiler.util.options import Options

DEFAULT_FORMAT = "[%(filename)s:%(lineno)s %(funcName)s()] %(levelname)s - %(message)s"
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
        "standard": {"format": DEFAULT_FORMAT},
    },
    "handlers": {
        "default": {
            "level": "DEBUG",
            "formatter": "standard",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",  # Default is stderr
        },
    },
    "loggers": {
        "": {"handlers": ["default"], "level": "WARNING", "propagate": False},  # root logger
    },
}


def configure_logging(level: Optional[str] = None):
    if core_ui_enabled():
        all_options = Options.from_gui()
        stream = "ext://sys.stdout"
    else:
        all_options = Options.load_default_options()
        stream = "ext://sys.stderr"
    if level is not None:
        log_level = level
    else:
        log_level = all_options.getstring("logging.log_level", fallback="DEBUG")
    LOGGING_CONFIG["loggers"][""]["level"] = log_level
    LOGGING_CONFIG["handlers"]["default"]["stream"] = stream
    logging.config.dictConfig(LOGGING_CONFIG)
