FROM python:3.10-slim

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    tcpdump \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create logging directory
RUN mkdir -p /var/log/securisphere

# Copy application files
COPY . .

# Initialize unbuffered output
CMD ["python", "-u", "network_monitor.py"]
