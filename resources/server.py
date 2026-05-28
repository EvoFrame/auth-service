import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator
from src.config.settings import settings
from src.events.consumers import start_all_consumers
from src.libs.errors import register_exception_handlers
from src.libs.health import health_router
from src.middlewares.logging import LoggingMiddleware
from src.middlewares.request_id import RequestIdMiddleware
from src.middlewares.service_auth import ServiceAuthMiddleware
from src.redis.client import get_redis
from src.routers import router
from src.tasks.token_cleanup import start_scheduler, stop_scheduler

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.PrintLoggerFactory(),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis = await get_redis()
    app.state.redis = redis
    await start_all_consumers(redis)
    start_scheduler()
    yield
    stop_scheduler()
    await redis.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.SERVICE_NAME,
        version=settings.SERVICE_VERSION,
        docs_url="/docs" if settings.DEBUG else None,
        redoc_url="/redoc" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(ServiceAuthMiddleware)

    register_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(router, prefix="/api/v1")

    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    return app


app = create_app()
