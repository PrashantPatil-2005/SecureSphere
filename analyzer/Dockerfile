# =============================================================================
# SecuriSphere Analyzer Service Dockerfile
# Zeek log parsing and anomaly detection
# =============================================================================

FROM python:3.10-slim

WORKDIR /analyzer

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy analyzer code
COPY src/ ./src/

# Set Python path
ENV PYTHONPATH=/analyzer

# Default command - run the analyzer
CMD ["python", "-m", "src.cli", "watch"]
