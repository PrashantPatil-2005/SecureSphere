#!/bin/bash

echo "Stopping all containers..."
docker compose down 2>/dev/null

echo "Removing volumes..."
docker volume rm securisphere_redis-data 2>/dev/null
docker volume rm securisphere_postgres-data 2>/dev/null

echo "Removing network..."
docker network rm securisphere_securisphere-network 2>/dev/null

echo ""
echo "Reset complete. All data has been cleared."
