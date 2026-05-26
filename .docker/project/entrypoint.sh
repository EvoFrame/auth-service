#!/bin/sh
set -e

# Run pending migrations before starting the server
alembic -c resources/alembic.ini upgrade head

if [ "${APP_ENV:-production}" = "development" ]; then
    exec uvicorn resources.server:app \
        --reload \
        --host 0.0.0.0 \
        --port 8080
else
    exec gunicorn resources.server:app \
        -k uvicorn.workers.UvicornWorker \
        -w "${WORKERS:-4}" \
        --bind 0.0.0.0:8080 \
        --forwarded-allow-ips="*" \
        --access-logfile - \
        --error-logfile -
fi