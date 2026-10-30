"""Logging setup (rotating file log; never crashes if the file is unwritable)."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from .constants import LOGGER_NAME


def setup_logging(log_dir: Optional[Path], enabled: bool = True,
                  level: str = "INFO") -> logging.Logger:
    """Configure and return the application logger."""
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.propagate = False
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    if enabled and log_dir is not None:
        try:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(Path(log_dir) / "examiner.log",
                                          maxBytes=1_000_000, backupCount=3,
                                          encoding="utf-8")
            handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"))
            logger.addHandler(handler)
            return logger
        except OSError:
            pass
    logger.addHandler(logging.NullHandler())
    return logger


def file_logging_active(logger: logging.Logger) -> bool:
    """True if the logger writes to a file."""
    return any(isinstance(h, RotatingFileHandler) for h in logger.handlers)
