#!/bin/bash
echo ""
echo "========================================="
echo "  Testing SecuriSphere Backend API"
echo "========================================="
echo ""

BACKEND="http://localhost:8000"
PASS=0
FAIL=0

test_endpoint() {
  local name="$1"
  local url="$2"
  local expected="$3"
  
  echo -n "Testing: $name... "
  response=$(curl -s "$url")
  
  if echo "$response" | grep -q "$expected"; then
    echo "PASS"
    PASS=$((PASS + 1))
  else
    echo "FAIL"
    echo "  Response: $response" | head -c 200
    echo ""
    FAIL=$((FAIL + 1))
  fi
}

# Health check
test_endpoint "Health" "$BACKEND/api/health" '"status":"healthy"'

# Dashboard summary
test_endpoint "Dashboard Summary" "$BACKEND/api/dashboard/summary" '"status":"success"'

# Events - all
test_endpoint "Events (all)" "$BACKEND/api/events" '"status":"success"'

# Events - by layer
test_endpoint "Events (network)" "$BACKEND/api/events?layer=network" '"status":"success"'
test_endpoint "Events (api)" "$BACKEND/api/events?layer=api" '"status":"success"'
test_endpoint "Events (auth)" "$BACKEND/api/events?layer=auth" '"status":"success"'

# Events - by severity
test_endpoint "Events (critical)" "$BACKEND/api/events?severity=critical" '"status":"success"'

# Events latest
test_endpoint "Events Latest" "$BACKEND/api/events/latest" '"status":"success"'

# Incidents
test_endpoint "Incidents" "$BACKEND/api/incidents" '"status":"success"'

# Risk scores
test_endpoint "Risk Scores" "$BACKEND/api/risk-scores" '"status":"success"'

# Metrics
test_endpoint "Metrics" "$BACKEND/api/metrics" '"status":"success"'

# Timeline
test_endpoint "Timeline" "$BACKEND/api/metrics/timeline" '"status":"success"'

# System status
test_endpoint "System Status" "$BACKEND/api/system/status" '"status":"success"'

# 404 handling
test_endpoint "404 Handler" "$BACKEND/api/nonexistent" '"status":"error"'

echo ""
echo "========================================="
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================="

# Test with actual data
echo ""
echo "--- Generating test events ---"
echo "Sending SQL injection to API server..."
curl -s "http://localhost:5000/api/products/search?q=' OR '1'='1" > /dev/null
sleep 2

echo "Sending brute force to Auth service..."
for i in {1..3}; do
  curl -s -X POST http://localhost:5001/auth/login \
    -H "Content-Type: application/json" \
    -d '{ "username":"admin","password":"wrong"}' > /dev/null
  sleep 0.3
done
sleep 2

echo ""
echo "--- Verifying events appear in backend ---"
echo "Events endpoint:"
curl -s "$BACKEND/api/events?limit=5" | python3 -m json.tool
echo ""
echo "Metrics endpoint:"
curl -s "$BACKEND/api/metrics" | python3 -m json.tool
