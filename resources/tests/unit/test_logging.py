"""Unit tests for log filtering configuration."""

import logging

from src.config.logging import _AccessPathFilter


def _build_record(
    *,
    logger_name: str,
    message: str,
    args: tuple[object, ...] = (),
) -> logging.LogRecord:
    return logging.LogRecord(
        name=logger_name,
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=args,
        exc_info=None,
    )


def test_access_filter_drops_health_requests_from_uvicorn() -> None:
    record = _build_record(
        logger_name="uvicorn.access",
        message='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:12345", "GET", "/health/live", "1.1", 200),
    )

    assert _AccessPathFilter().filter(record) is False


def test_access_filter_drops_metrics_requests_from_gunicorn() -> None:
    record = _build_record(
        logger_name="gunicorn.access",
        message='127.0.0.1 - "GET /metrics HTTP/1.1" 200',
    )

    assert _AccessPathFilter().filter(record) is False


def test_access_filter_keeps_regular_requests() -> None:
    record = _build_record(
        logger_name="uvicorn.access",
        message='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:12345", "POST", "/api/v1/service-clients/token", "1.1", 200),
    )

    assert _AccessPathFilter().filter(record) is True


def test_access_filter_ignores_non_access_loggers() -> None:
    record = _build_record(
        logger_name="uvicorn.error",
        message='127.0.0.1 - "GET /health/live HTTP/1.1" 200',
    )

    assert _AccessPathFilter().filter(record) is True
