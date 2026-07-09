# Builder: install dependencies from the committed lockfile (reproducible),
# then hand only the finished virtualenv to the runtime stage.
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf AS builder

RUN pip install --no-cache-dir uv==0.9.18

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --locked --no-dev --extra telemetry --no-editable

# Runtime: same digest-pinned base, no build tooling, non-root.
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

ENV PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 1000 mcp

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

USER mcp

EXPOSE 8000

# Container-level liveness for docker/compose users (ACA uses its own probes).
# Checks the default port; override/disable if you change MCP_PORT.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"

CMD ["patch-tuesday-mcp"]
