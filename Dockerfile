# Cost-Optimized Dockerfile for Correlation Service
FROM python:3.11-slim as builder

# Install only essential system dependencies for sklearn
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage - minimal image
FROM python:3.11-slim

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /app
RUN chown appuser:appuser /app
USER appuser

# Copy application code
COPY clustering_correlation_agent.py .

# Expose port
EXPOSE 8004

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8004/health || exit 1

# Run application
CMD ["uvicorn", "clustering_correlation_agent:app", "--host", "0.0.0.0", "--port", "8004", "--workers", "1"]
