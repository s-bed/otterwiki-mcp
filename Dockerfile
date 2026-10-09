FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY otterwiki_mcp/ ./otterwiki_mcp/

RUN chmod -R a+rX /app

RUN pip install --no-cache-dir .

RUN useradd --create-home appuser \
    && mkdir -p /app/data \
    && chown appuser:appuser /app/data \
    && chmod 700 /app/data
ENV MCP_OAUTH_DB=/app/data/mcp_oauth.db
USER appuser

EXPOSE 8090

CMD ["python", "-m", "otterwiki_mcp.server"]
