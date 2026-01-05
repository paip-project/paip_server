# PAIP Server Dockerfile
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd --gid 1000 paip && \
    useradd --uid 1000 --gid paip --shell /bin/bash --create-home paip

# Set work directory
WORKDIR /app

# Install dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Install the package
RUN pip install --no-cache-dir -e .

# Create directories for keys (will be mounted)
RUN mkdir -p /app/keys && chown paip:paip /app/keys

# Switch to non-root user
USER paip

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Run the server
CMD ["python", "-m", "paip.main", "serve", "--host", "0.0.0.0", "--port", "8080"]
