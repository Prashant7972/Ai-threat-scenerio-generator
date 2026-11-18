FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install runtime utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source, tests, specs, data, scripts, UI, and documentation
COPY src/ /app/src/
COPY specs/ /app/specs/
COPY data/ /app/data/
COPY tests/ /app/tests/
COPY scripts/ /app/scripts/
COPY ui/ /app/ui/
COPY docs/ /app/docs/
COPY pytest.ini ruff.toml PACKAGE_MANIFEST.json DELIVERY_STATUS.md README.md /app/

# Create non-root user for container isolation
RUN useradd -m -u 10001 appuser && \
    mkdir -p /app/reports && \
    chown -R appuser:appuser /app

USER appuser

# Default command: execute the automated unit test suite
CMD ["pytest", "tests/", "-v"]
