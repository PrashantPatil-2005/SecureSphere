FROM python:3.10-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /var/log/securisphere

# Copy application files
COPY . .

# Expose port
EXPOSE 8000

# Create upload and sample directories
RUN mkdir -p /app/uploads/pcap /app/samples/pcap

# Run gunicornheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["python", "-u", "app.py"]
