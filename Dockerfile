FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CYBER_RISK_PROJECT_ROOT=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md requirements.txt ./
COPY configs ./configs
COPY api ./api
COPY scripts ./scripts
COPY src ./src
COPY data ./data

RUN pip install -U pip && pip install -r requirements.txt && pip install -e .

# Pre-build reference artifacts for faster cold starts (optional; set BUILD_BOOTSTRAP=0 to skip)
ARG BUILD_BOOTSTRAP=1
RUN if [ "$BUILD_BOOTSTRAP" = "1" ]; then python scripts/bootstrap.py; fi

EXPOSE 8000

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
