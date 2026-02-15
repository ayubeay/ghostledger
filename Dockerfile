FROM python:3.13-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY ghostledger_intake.py .
COPY ghostledger_docs.py .
COPY GhostLedger.html .
COPY portal.html .

# Create data directory for SQLite persistence
RUN mkdir -p /data/logs

# Environment
ENV GL_DB_PATH=/data/ghostledger.db
ENV PORT=8081
ENV REQUIRE_AUTH=false

EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8081/health')"

CMD ["uvicorn", "ghostledger_intake:app", "--host", "0.0.0.0", "--port", "8081"]
