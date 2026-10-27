# ==============================================================================
# HawkEye-AI — Production Hardened Dockerfile
# Cloud Computing & Cyber Security SOC Platform
# ==============================================================================
FROM python:3.11-slim as base

# Set environment variables for Python in container
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true

# Install system dependencies (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root SOC analyst user (Cloud Security Best Practice: Principle of Least Privilege)
RUN groupadd -g 10001 socgroup && \
    useradd -u 10001 -g socgroup -s /bin/bash -m socuser

WORKDIR /app

# Copy dependency requirements first to leverage Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY --chown=socuser:socgroup . /app

# Switch to non-root user
USER socuser

# Expose Streamlit SOC dashboard port
EXPOSE 8501

# Container Healthcheck for Kubernetes / Docker Swarm
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command launches the SOC Streamlit intelligence dashboard
CMD ["streamlit", "run", "dashboard/app.py"]
