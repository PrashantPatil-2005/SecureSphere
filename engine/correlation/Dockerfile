FROM python:3.10-slim

WORKDIR /app

# Install curl for health check
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create log directory
RUN mkdir -p /var/log/securisphere

EXPOSE 5070

# Unbuffered output for seeing logs in real-time
CMD ["python", "-u", "correlation_engine.py"]
