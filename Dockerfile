FROM ghcr.io/astral-sh/uv:0.13.10 AS uv

FROM python:3.12-slim
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --all-extras --no-cache
COPY . .
ENV PATH="/app/.venv/bin:$PATH"
USER 1000:1000
