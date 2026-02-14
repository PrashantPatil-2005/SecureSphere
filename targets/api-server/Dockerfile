FROM python:3.10-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/public /app/uploads /var/log/securisphere

# Copy application files
COPY . .

# Create sample files
RUN echo "Welcome to SecuriSphere Demo API Server" > /app/public/readme.txt
RUN echo "db_host=internal-db\ndb_port=5432\napi_key=demo-key-12345" > /app/public/config.txt

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

CMD ["python", "app.py"]
