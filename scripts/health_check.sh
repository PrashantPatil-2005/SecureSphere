#!/bin/bash

# SecuriSphere Health Check Script
# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "========================================="
echo "  SecuriSphere Health Check"
echo "========================================="
echo ""

PASS=0
FAIL=0

# ---- Check Redis ----
echo -n "Checking Redis... "
REDIS_PING=$(docker exec securisphere-redis redis-cli ping 2>/dev/null)

if [ "$REDIS_PING" == "PONG" ]; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  Redis did not respond with PONG"
    FAIL=$((FAIL + 1))
fi

# ---- Check PostgreSQL Connection ----
echo -n "Checking PostgreSQL Connection... "
PG_READY=$(docker exec securisphere-db pg_isready -U securisphere_user -d securisphere_db 2>/dev/null)

if echo "$PG_READY" | grep -q "accepting connections"; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  PostgreSQL is not accepting connections"
    FAIL=$((FAIL + 1))
fi

# ---- Check Database Tables ----
echo -n "Checking Database Tables... "
TABLE_COUNT=$(docker exec securisphere-db psql -U securisphere_user -d securisphere_db -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')

if [ "$TABLE_COUNT" -eq 4 ] 2>/dev/null; then
    echo -e "${GREEN}PASS${NC} (Found $TABLE_COUNT tables)"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  Expected 4 tables, found: $TABLE_COUNT"
    FAIL=$((FAIL + 1))
fi

# ---- List Tables ----
echo ""
echo "Tables in database:"
docker exec securisphere-db psql -U securisphere_user -d securisphere_db -c "\dt" 2>/dev/null

# ---- Check Indexes ----
echo -n "Checking Indexes... "
INDEX_COUNT=$(docker exec securisphere-db psql -U securisphere_user -d securisphere_db -t -c "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public';" 2>/dev/null | tr -d ' ')

if [ "$INDEX_COUNT" -ge 10 ] 2>/dev/null; then
    echo -e "${GREEN}PASS${NC} (Found $INDEX_COUNT indexes)"
    PASS=$((PASS + 1))
else
    echo -e "${YELLOW}WARNING${NC} (Found $INDEX_COUNT indexes, expected 10+)"
fi

# ---- Check API Server ----
echo -n "Checking API Server... "
API_STATUS=$(curl -s http://localhost:5000/api/health | grep -o '"status": "healthy"')

if [ ! -z "$API_STATUS" ]; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  API Server not healthy"
    FAIL=$((FAIL + 1))
fi

# ---- Check Auth Service ----
echo -n "Checking Auth Service... "
AUTH_STATUS=$(curl -s http://localhost:5001/auth/status | grep -o '"status": "running"')

if [ ! -z "$AUTH_STATUS" ]; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  Auth Service not running"
    FAIL=$((FAIL + 1))
fi

# ---- Check API Monitor ----
echo -n "Checking API Monitor... "
APIMON_STATUS=$(curl -s http://localhost:5050/monitor/health | grep -o '"status": "running"')

if [ ! -z "$APIMON_STATUS" ]; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  API Monitor not running"
    FAIL=$((FAIL + 1))
fi

# ---- Check Auth Monitor ----
echo -n "Checking Auth Monitor... "
AUTHMON_STATUS=$(curl -s http://localhost:5060/monitor/health | grep -o '"status": "running"')

if [ ! -z "$AUTHMON_STATUS" ]; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  Auth Monitor not running"
    FAIL=$((FAIL + 1))
fi

# ---- Check Network Monitor ----
echo -n "Checking Network Monitor... "
NETMON_RUNNING=$(docker ps --filter "name=securisphere-netmon" --format "{{.Status}}" | grep "Up")

if [ ! -z "$NETMON_RUNNING" ]; then
    echo -e "${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}"
    echo "  Network Monitor container not running"
    FAIL=$((FAIL + 1))
fi

# ---- Summary ----
echo ""
echo "========================================="
echo "  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "========================================="
echo ""

if [ $FAIL -gt 0 ]; then
    exit 1
else
    exit 0
fi
