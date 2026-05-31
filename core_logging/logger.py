import json
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config.settings import (
    LOG_DIR, LOG_FILE_SYSTEM,
    LOG_ROTATION_BYTES, LOG_ROTATION_COUNT,
    NODE_ID, NODE_ROLE,
)


def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "node_id":   NODE_ID,
            "node_role": NODE_ROLE,
            "hostname":  socket.gethostname(),
            "logger":    record.name,
            "message":   record.getMessage(),
        }
        if hasattr(record, "event_data"):
            entry.update(record.event_data)
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def get_logger(name: str, log_file: Optional[str] = None) -> logging.Logger:
    _ensure_log_dir()
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = JSONFormatter()

    fh = RotatingFileHandler(
        filename=log_file or LOG_FILE_SYSTEM,
        maxBytes=LOG_ROTATION_BYTES,
        backupCount=LOG_ROTATION_COUNT,
        encoding="utf-8",
    )
    fh.setFormatter(formatter)
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    return logger


def log_event(logger, level: str, message: str, event_data=None):
    extra = {"event_data": event_data or {}}
    getattr(logger, level.lower(), logger.info)(message, extra=extra)