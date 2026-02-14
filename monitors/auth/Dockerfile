FROM python:3.10-slim

# Install curl
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create logs directory
RUN mkdir -p /var/log/securisphere

# Copy application files
COPY . .

# Expose proxy port
EXPOSE 5060

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5060/monitor/health || exit 1

CMD ["python", "-u", "auth_monitor.py"]
