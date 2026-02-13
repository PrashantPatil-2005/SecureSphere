#!/bin/bash

# SecuriSphere Setup Script

echo ""
echo "========================================="
echo "  SecuriSphere Phase 1 Setup"
echo "========================================="
echo ""

# ---- Check Docker ----
echo -n "Checking Docker... "
if ! command -v docker &> /dev/null; then
    echo "FAILED"
    echo "Docker is not installed. Install from https://docker.com"
    exit 1
fi
echo "OK"

# ---- Check Docker Compose ----
echo -n "Checking Docker Compose... "
if ! docker compose version &> /dev/null; then
    echo "FAILED"
    echo "Docker Compose is not available."
    exit 1
fi
echo "OK"

# ---- Create .env if missing ----
if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
fi

# ---- Create directories ----
mkdir -p logs evaluation/results

# ---- Start services ----
echo ""
echo "Starting SecuriSphere services..."
docker compose up -d redis database

# ---- Wait for Redis ----
echo ""
echo -n "Waiting for Redis"
for i in $(seq 1 30); do
    REDIS_OK=$(docker exec securisphere-redis redis-cli ping 2>/dev/null)
    if [ "$REDIS_OK" == "PONG" ]; then
        echo " READY"
        break
    fi
    echo -n "."
    sleep 1
    if [ $i -eq 30 ]; then
        echo " TIMEOUT"
        echo "Redis failed to start. Check: docker logs securisphere-redis"
        exit 1
    fi
done

# ---- Wait for PostgreSQL ----
echo -n "Waiting for PostgreSQL"
for i in $(seq 1 30); do
    PG_OK=$(docker exec securisphere-db pg_isready -U securisphere_user -d securisphere_db 2>/dev/null)
    if echo "$PG_OK" | grep -q "accepting connections"; then
        echo " READY"
        break
    fi
    echo -n "."
    sleep 1
    if [ $i -eq 30 ]; then
        echo " TIMEOUT"
        echo "PostgreSQL failed to start. Check: docker logs securisphere-db"
        exit 1
    fi
done

# ---- Wait extra for init_db.sql to finish ----
echo "Waiting for database initialization..."
sleep 3

# ---- Run health check ----
echo ""
bash scripts/health_check.sh

echo ""
echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "  Redis:      localhost:6379"
echo "  PostgreSQL: localhost:5432"
echo "  Database:   securisphere_db"
echo "  User:       securisphere_user"
echo ""
echo "  Next: Run 'make health' to verify"
echo "========================================="
