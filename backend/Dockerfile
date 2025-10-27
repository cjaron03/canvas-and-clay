# Multi-stage build for optimized backend image
# Stage 1: Builder - Install dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

# Avoid flaky http mirror responses that can trigger Hash Sum mismatch errors
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources

# Install system dependencies for psycopg2-binary
# Note: psycopg2-binary includes its own libpq, but we need build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install with BuildKit cache mount
COPY requirements.txt .

# Install Python dependencies with pip cache mount
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --user -r requirements.txt

# Stage 2: Runtime - Minimal production image
FROM python:3.12-slim

WORKDIR /app

# Avoid flaky http mirror responses that can trigger Hash Sum mismatch errors
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources

# Install runtime dependencies only (libpq for psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Set Python environment variables for optimization
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Copy application code
COPY . .

# Copy entrypoint script and make executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5000

# Use entrypoint to handle migrations
ENTRYPOINT ["/entrypoint.sh"]

# Run Flask development server
CMD ["python", "app.py"]
