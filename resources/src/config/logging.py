import logging
import logging.config
import re
from typing import Literal

import structlog

from src.config.settings import settings

_shared_processors = [
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
]

_MUTED_ACCESS_PATH_PREFIXES = ("/health", "/metrics")
_ACCESS_LOGGER_NAMES = {"uvicorn.access", "gunicorn.access"}
_ACCESS_LOG_PATH_PATTERN = re.compile(r'"(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(?P<path>\S+)\s+HTTP/[0-9.]+"')

type LoggerType = Literal["normal", "noisy"]

_MANAGED_LOGGERS: list[dict[str, str]] = [
    {"name": "uvicorn", "type": "normal"},
    {"name": "uvicorn.access", "type": "normal"},
    {"name": "uvicorn.error", "type": "normal"},
    {"name": "gunicorn", "type": "normal"},
    {"name": "gunicorn.access", "type": "normal"},
    {"name": "gunicorn.error", "type": "normal"},
    {"name": "watchfiles", "type": "normal"},
    {"name": "watchfiles.main", "type": "noisy"},
    {"name": "sqlalchemy", "type": "noisy"},
    {"name": "sqlalchemy.engine", "type": "noisy"},
    {"name": "sqlalchemy.engine.Engine", "type": "noisy"},
    {"name": "sqlalchemy.pool", "type": "noisy"},
    {"name": "sqlalchemy.dialects", "type": "noisy"},
    {"name": "sqlalchemy.orm", "type": "noisy"},
]


def _safe_add_logger_name(logger, method_name, event_dict):
    """Read logger name from stdlib LogRecord (always present), fall back to logger.name."""
    record = event_dict.get("_record")
    if record is not None:
        event_dict["logger"] = record.name
    elif logger is not None:
        event_dict["logger"] = getattr(logger, "name", None)
    return event_dict


def _level_for(logger_type: LoggerType) -> str:
    return settings.NOISE_LOG_LEVEL if logger_type == "noisy" else settings.LOG_LEVEL


def _extract_access_path(record: logging.LogRecord) -> str | None:
    match = _ACCESS_LOG_PATH_PATTERN.search(record.getMessage())
    if match is not None:
        return match.group("path")

    if isinstance(record.args, tuple) and len(record.args) >= 3 and isinstance(record.args[2], str):
        return record.args[2]

    return None


class _AccessPathFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name not in _ACCESS_LOGGER_NAMES:
            return True

        path = _extract_access_path(record)
        if path is None:
            return True

        return not path.startswith(_MUTED_ACCESS_PATH_PREFIXES)


def configure_logging() -> None:
    """Wire structlog + stdlib logging into a unified JSON pipeline."""
    structlog.configure(
        processors=[
            *_shared_processors,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            _safe_add_logger_name,  # must run before remove_processors_meta (needs _record)
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            *_shared_processors,
            structlog.processors.JSONRenderer(),
        ],
    )

    managed = {
        entry["name"]: {
            "level": _level_for(entry["type"]),
            "handlers": ["access" if entry["name"].endswith(".access") else "default"],
            "propagate": False,
        }
        for entry in _MANAGED_LOGGERS
    }

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "handlers": {
                "default": {"class": "logging.StreamHandler", "formatter": "structlog"},
                "access": {
                    "class": "logging.StreamHandler",
                    "formatter": "structlog",
                    "filters": ["mute_access_paths"],
                },
            },
            "filters": {"mute_access_paths": {"()": _AccessPathFilter}},
            "formatters": {
                "structlog": {"()": lambda: formatter},
            },
            "loggers": managed,
            "root": {"level": settings.LOG_LEVEL, "handlers": ["default"]},
        }
    )

    # Force levels directly on logger objects — some libs (e.g. SQLAlchemy) reset their
    # child loggers at runtime after dictConfig has run.
    for entry in _MANAGED_LOGGERS:
        logging.getLogger(entry["name"]).setLevel(_level_for(entry["type"]))
