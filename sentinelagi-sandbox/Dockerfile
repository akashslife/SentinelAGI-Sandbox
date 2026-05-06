# ============================================
# SentinelAGI Sandbox - Main Application Image
# ============================================

FROM python:3.11-slim-bookworm AS base

# Security: Run as non-root
RUN groupadd -r sentinelagi && useradd -r -g sentinelagi sentinelagi

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY deploy/ ./deploy/

# Set Python path
ENV PYTHONPATH=/app/src
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER sentinelagi

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command
CMD ["python", "-m", "sentinelagi.main", "server", "--host", "0.0.0.0", "--port", "8000"]
