#!/bin/bash

echo "Generating test events for Dashboard verification..."

# 1. SQL Injection (API Layer)
echo "  [API] Simulating SQL Injection..."
curl -s "http://localhost:5000/api/products/search?q=' OR '1'='1" > /dev/null
sleep 1

# 2. Path Traversal (API Layer)
echo "  [API] Simulating Path Traversal..."
curl -s "http://localhost:5000/api/files?name=../../../etc/passwd" > /dev/null
sleep 1

# 3. Sensitive Access (API Layer)
echo "  [API] Simulating Sensitive Config Access..."
curl -s "http://localhost:5000/api/admin/config" > /dev/null
sleep 1

# 4. Brute Force (Auth Layer) - 6 attempts to trigger lockout
echo "  [Auth] Simulating Brute Force (6 attempts)..."
for i in {1..6}; do
  curl -s -X POST http://localhost:5001/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong"}' > /dev/null
  sleep 0.2
done
sleep 1

# Reset accounts
echo "  [Auth] Resetting accounts..."
curl -s -X POST http://localhost:5001/auth/reset-all > /dev/null

# 5. Credential Stuffing (Auth Layer) - Multiple users
echo "  [Auth] Simulating Credential Stuffing..."
for user in admin john jane bob alice testuser; do
  curl -s -X POST http://localhost:5001/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$user\",\"password\":\"wrongpass\"}" > /dev/null
  sleep 0.2
done

echo ""
echo "Done! Events generated."
echo "Check http://localhost:3000 to see them appear in real-time."
