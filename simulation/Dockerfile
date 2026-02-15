FROM python:3.10-slim
RUN apt-get update && apt-get install -y curl iputils-ping net-tools nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python", "-u", "attack_orchestrator.py"]
CMD ["--help"]
