#!/bin/bash

echo ""
echo "═══════════════════════════════════════════════"
echo "  Testing SecuriSphere Correlation Engine"
echo "═══════════════════════════════════════════════"
echo ""

# Reset everything first
echo "[*] Clearing all previous events and incidents..."
curl -s -X POST http://localhost:8000/api/events/clear > /dev/null
sleep 2

# Reset auth accounts
echo "[*] Resetting all auth accounts..."
curl -s -X POST http://localhost:5001/auth/reset-all > /dev/null
sleep 2

echo ""
echo "═══════════════════════════════════════════════"
echo "  TEST 1: API + Auth Combined Attack"
echo "  Expected: 'Automated Attack Tool' incident"
echo "═══════════════════════════════════════════════"
echo ""

echo "[*] Sending SQL injection attacks..."
for i in {1..3}; do
  curl -s "http://localhost:5000/api/products/search?q=' OR '1'='1" > /dev/null
  curl -s "http://localhost:5000/api/products/search?q=' UNION SELECT * FROM users--" > /dev/null
  sleep 0.5
done

echo "[*] Sending brute force attacks..."
for i in {1..6}; do
  curl -s -X POST http://localhost:5001/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrong'$i'"}' > /dev/null
  sleep 0.3
done

echo "[*] Waiting for correlation..."
sleep 5

echo "[*] Checking for incidents..."
INCIDENTS=$(curl -s http://localhost:8000/api/incidents)
# Try to pretty print if python is available, else raw
if command -v python3 &> /dev/null; then
    echo "$INCIDENTS" | python3 -m json.tool
else
    echo "$INCIDENTS"
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  TEST 2: Credential Compromise"
echo "  Expected: 'Credential Compromise' incident"
echo "═══════════════════════════════════════════════"
echo ""

# Reset accounts
curl -s -X POST http://localhost:5001/auth/reset-all > /dev/null
sleep 1

echo "[*] Sending failed logins (brute force)..."
for i in {1..5}; do
  curl -s -X POST http://localhost:5001/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"john","password":"wrongpass"}' > /dev/null
  sleep 0.3
done

echo "[*] Resetting john's account for successful login..."
curl -s -X POST http://localhost:5001/auth/reset/john > /dev/null
sleep 1

echo "[*] Sending successful login (triggers suspicious_login)..."
curl -s -X POST http://localhost:5001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john","password":"password123"}' > /dev/null

echo "[*] Waiting for correlation..."
sleep 5

echo "[*] Checking incidents..."
if command -v python3 &> /dev/null; then
    curl -s http://localhost:8000/api/incidents | python3 -m json.tool
else
    curl -s http://localhost:8000/api/incidents
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  TEST 3: Data Exfiltration Pattern"
echo "  Expected: 'Data Exfiltration Risk' incident"
echo "═══════════════════════════════════════════════"
echo ""

echo "[*] Sending exploitation attacks..."
curl -s "http://localhost:5000/api/products/search?q=' OR '1'='1" > /dev/null
curl -s "http://localhost:5000/api/files?name=../../../etc/passwd" > /dev/null
sleep 1

echo "[*] Accessing sensitive endpoints..."
curl -s http://localhost:5000/api/admin/config > /dev/null
curl -s http://localhost:5000/api/admin/users/export > /dev/null

echo "[*] Waiting for correlation..."
sleep 5

echo "[*] Checking incidents..."
if command -v python3 &> /dev/null; then
    curl -s http://localhost:8000/api/incidents | python3 -m json.tool
else
    curl -s http://localhost:8000/api/incidents
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  RESULTS SUMMARY"
echo "═══════════════════════════════════════════════"
echo ""

echo "--- Risk Scores ---"
if command -v python3 &> /dev/null; then
    curl -s http://localhost:8000/api/risk-scores | python3 -m json.tool
else
    curl -s http://localhost:8000/api/risk-scores
fi

echo ""
echo "--- Metrics ---"
if command -v python3 &> /dev/null; then
    curl -s http://localhost:8000/api/metrics | python3 -m json.tool
else
    curl -s http://localhost:8000/api/metrics
fi

echo ""
echo "--- Correlation Engine Stats ---"
if command -v python3 &> /dev/null; then
    curl -s http://localhost:5070/engine/stats | python3 -m json.tool
else
    curl -s http://localhost:5070/engine/stats
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  Open dashboard to see results:"
echo "  http://localhost:3000"
echo "═══════════════════════════════════════════════"
