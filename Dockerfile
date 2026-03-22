# -----------------------------------------------------------------------------
# Stage: builder — install Semgrep (pip), Syft & TruffleHog (release binaries)
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Isolated prefix so we can copy only what we need into runtime (no pip/git cache in final image).
RUN pip install --no-cache-dir --prefix=/opt/hexvibe semgrep

RUN mkdir -p /opt/hexvibe/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /opt/hexvibe/bin \
    && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /opt/hexvibe/bin \
    && chmod +x /opt/hexvibe/bin/syft /opt/hexvibe/bin/trufflehog

# -----------------------------------------------------------------------------
# Stage: runtime — minimal app tree + tooling from builder (no git, no pip cache)
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:${PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Binaries produced in builder (semgrep CLI + any semgrep-* helpers, syft, trufflehog).
COPY --from=builder /opt/hexvibe/bin/ /usr/local/bin/

# Semgrep Python stack (and transitive deps) only — no full builder /usr/local.
COPY --from=builder /opt/hexvibe/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/

# Application (MCP server + rules + scripts). Ignore file must live at /app/.hexvibe-ignore.yaml (see server/adapter.py).
COPY core/ /app/core/
COPY server/ /app/server/
COPY scripts/ /app/scripts/
COPY .hexvibe-ignore.yaml /app/.hexvibe-ignore.yaml

# Pre-warm import graph (RAG / compliance loaders) without shipping extra docs.
RUN python -c "import server.adapter"

RUN chmod +x /app/scripts/internal-test.sh

CMD ["python", "server/adapter.py"]
