#!/bin/bash

# Configuration
API_URL="http://localhost:5000"
AUTH_URL="http://localhost:5001"

echo "========================================="
echo "  Testing SecuriSphere Monitors"
echo "========================================="
echo ""

# 1. Test API Monitor
echo "--- Testing API Monitor Detection ---"
echo "[*] Sending SQL Injection attacks..."
curl -s "${API_URL}/api/products/search?q=' OR '1'='1" > /dev/null
sleep 1
curl -s "${API_URL}/api/products/search?q=' UNION SELECT * FROM users--" > /dev/null
sleep 1

echo "[*] Sending Path Traversal attacks..."
curl -s "${API_URL}/api/files?name=../../../etc/passwd" > /dev/null
sleep 1
curl -s "${API_URL}/api/files?name=..%2f..%2f..%2fetc%2fpasswd" > /dev/null
sleep 1

echo "[*] Accessing sensitive endpoints..."
curl -s "${API_URL}/api/admin/config" > /dev/null
sleep 1
curl -s "${API_URL}/api/admin/users/export" > /dev/null
sleep 1

# 2. Test Auth Monitor
echo ""
echo "--- Testing Auth Monitor Detection ---"
echo "[*] Resetting accounts..."
curl -s -X POST "${AUTH_URL}/auth/reset-all" > /dev/null
sleep 1

echo "[*] Simulating Brute Force (6 failed attempts)..."
for i in {1..6}; do
    curl -s -X POST "${AUTH_URL}/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"wrong${i}\"}" > /dev/null
    sleep 0.5
done
sleep 1

echo "[*] Simulating Credential Stuffing (multiple users)..."
for user in admin john jane bob alice testuser root guest; do
    curl -s -X POST "${AUTH_URL}/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${user}\",\"password\":\"wrongpass\"}" > /dev/null
    sleep 0.3
done
sleep 1

echo "[*] Simulating Suspicious Login (Failure -> Success)..."
curl -s -X POST "${AUTH_URL}/auth/reset-all" > /dev/null
sleep 1
for i in {1..4}; do
    curl -s -X POST "${AUTH_URL}/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"john","password":"wrongpass"}' > /dev/null
    sleep 0.3
done
curl -s -X POST "${AUTH_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"john","password":"password123"}' > /dev/null
sleep 1

# 3. Check Redis
echo ""
echo "--- Checking Redis for Security Events ---"
echo -n "Network Events: "
docker exec securisphere-redis redis-cli LLEN events:network 2>/dev/null || echo "Error connecting to Redis"

echo -n "API Events: "
docker exec securisphere-redis redis-cli LLEN events:api 2>/dev/null || echo "Error"

echo -n "Auth Events: "
docker exec securisphere-redis redis-cli LLEN events:auth 2>/dev/null || echo "Error"

echo ""
echo "Latest API Event:"
docker exec securisphere-redis redis-cli LINDEX events:api 0 2>/dev/null

echo ""
echo "========================================="
echo "  Test Complete. Check logs for details."
echo "========================================="
