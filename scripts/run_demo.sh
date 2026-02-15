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
read -p "Select option: " choice

case $choice in
  1)
    docker-compose run --rm attack-simulator full_kill_chain
    ;;
  2)
    docker-compose run --rm attack-simulator api_abuse
    ;;
  3)
    docker-compose run --rm attack-simulator credential_attack
    ;;
  4)
    docker-compose run --rm attack-simulator benign
    ;;
  5)
    docker-compose run --rm attack-simulator stealth
    ;;
  6)
    docker-compose run --rm attack-simulator all
    ;;
  7)
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
