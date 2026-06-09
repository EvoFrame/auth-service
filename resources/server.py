from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from prometheus_fastapi_instrumentator import Instrumentator
from src.config.logging import configure_logging
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

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown lifecycle.

    On startup: initialises Redis, starts event consumers, and starts the
    background scheduler. On shutdown: stops the scheduler and closes Redis.

    Args:
        app: The FastAPI application instance.

    Yields:
        Control to the running application.
    """
    redis = await get_redis()
    app.state.redis = redis
    await start_all_consumers(redis)
    start_scheduler()
    yield
    stop_scheduler()
    await redis.aclose()


def create_app() -> FastAPI:
    """Construct and configure the FastAPI application.

    Registers middlewares, exception handlers, routers, and Prometheus metrics.

    Returns:
        A fully configured FastAPI application instance.
    """
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

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
        schema.setdefault("components", {})["securitySchemes"] = {
            "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        }
        schema["security"] = [{"BearerAuth": []}]
        app.openapi_schema = schema
        return schema

    if settings.DEBUG:
        app.openapi = custom_openapi  # type: ignore[method-assign]

    return app


app = create_app()
