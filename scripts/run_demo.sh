#!/bin/bash

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       SecuriSphere Demo Launcher                 ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║                                                  ║"
echo "║  1. Run Full Kill Chain (recommended for demo)   ║"
echo "║  2. Run API Abuse Campaign                       ║"
echo "║  3. Run Credential Attack Campaign               ║"
echo "║  4. Run Benign Traffic (false positive test)     ║"
echo "║  5. Run Stealth Attack                           ║"
echo "║  6. Run ALL Scenarios                            ║"
echo "║  7. Run Full Kill Chain (DEMO MODE - slow)       ║"
echo "║                                                  ║"
echo "║  0. Exit                                         ║"
echo "║                                                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo ""
# Check if argument is provided
if [ -n "$1" ]; then
    choice=$1
else
    echo -n "Select option: "
    read choice
fi

echo ""
echo "----------------------------------------------------------------"

case $choice in
  1)
    echo "This will run the full kill chain scenario."
    echo "Duration: ~30 seconds"
    read -p "Press Enter to launch attack..."
    docker-compose run --rm attack-simulator full_kill_chain
    ;;
  2)
    echo "Running API Abuse Campaign..."
    docker-compose run --rm attack-simulator api_abuse
    ;;
  3)
    echo "Running Credential Attack Campaign..."
    docker-compose run --rm attack-simulator credential_attack
    ;;
  4)
    echo "Running Benign Traffic Simulation."
    echo "Expect: Green events, No Incidents."
    read -p "Press Enter to start..."
    docker-compose run --rm attack-simulator benign
    ;;
  5)
    echo "Running Stealth Attack (Low and Slow)."
    echo "Expect: Single Critical Incident."
    read -p "Press Enter to start..."
    docker-compose run --rm attack-simulator stealth
    ;;
  6)
    echo "Running ALL Scenarios sequentially..."
    docker-compose run --rm attack-simulator all
    ;;
  7)
    echo "Running Full Kill Chain in DEMO MODE (Slow)."
    echo "Events will be spaced out for narration."
    read -p "Press Enter to start..."
    docker-compose run --rm attack-simulator full_kill_chain --delay demo
    ;;
  0)
    echo "Exiting."
    exit 0
    ;;
  *)
    echo "Invalid option."
    exit 1
    ;;
esac
