
#!/bin/bash

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     SecuriSphere PCAP Analysis Demo              ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

PCAP_DIR="samples/pcap"
mkdir -p "$PCAP_DIR"

echo "What would you like to do?"
echo ""
echo "  1. Generate sample .pcap files"
echo "  2. Analyze a .pcap file (publish to dashboard)"
echo "  3. Analyze a .pcap file (offline, no Redis)"
echo "  4. Show .pcap file info"
echo "  5. Generate + Analyze (full demo)"
echo "  6. Open Dashboard Analysis"
echo "  0. Exit"
echo ""
read -p "Select option: " choice

case $choice in
  1)
    echo ""
    echo "Generating sample .pcap files..."
    cd simulation && python generate_sample_pcap.py all --output-dir ../samples/pcap
    cd ..
    echo ""
    echo "Files generated in samples/pcap/"
    ls -la samples/pcap/
    ;;
  
  2)
    echo ""
    if [ -z "$(ls samples/pcap/*.pcap 2>/dev/null)" ]; then
      echo "No .pcap files found. Generating samples first..."
      cd simulation && python generate_sample_pcap.py all --output-dir ../samples/pcap
      cd ..
    fi
    echo "Available .pcap files:"
    ls -la samples/pcap/*.pcap
    echo ""
    read -p "Enter file path: " pcap_path
    
    echo ""
    echo "Clearing previous events..."
    curl -s -X POST http://localhost:8000/api/events/clear > /dev/null 2>&1
    sleep 2
    
    echo "Analyzing $pcap_path..."
    echo "(Events will appear on dashboard: http://localhost:3000)"
    echo ""
    
    cd monitors/network && python pcap_analyzer.py "../../$pcap_path" --speed 0
    cd ../..
    
    echo ""
    echo "Check dashboard: http://localhost:3000"
    ;;
  
  3)
    echo ""
    read -p "Enter .pcap file path: " pcap_path
    echo ""
    cd monitors/network && python pcap_analyzer.py "../../$pcap_path" --no-redis --speed 0
    cd ../..
    ;;
  
  4)
    echo ""
    read -p "Enter .pcap file path: " pcap_path
    echo ""
    cd monitors/network && python pcap_analyzer.py "../../$pcap_path" --info-only
    cd ../..
    ;;
  
  5)
    echo ""
    echo "═══ STEP 1: Generate sample .pcap files ═══"
    cd simulation && python generate_sample_pcap.py all --output-dir ../samples/pcap
    cd ..
    echo ""
    
    echo "═══ STEP 2: Clear previous events ═══"
    curl -s -X POST http://localhost:8000/api/events/clear > /dev/null 2>&1
    sleep 2
    echo "Cleared ✅"
    echo ""
    
    echo "═══ STEP 3: Analyze mixed attack pcap ═══"
    echo "(Watch dashboard: http://localhost:3000)"
    echo ""
    cd monitors/network && python pcap_analyzer.py ../../samples/pcap/mixed_attack_sample.pcap --speed 0 --report ../../evaluation/results/pcap_analysis.json
    cd ../..
    echo ""
    
    echo "═══ STEP 4: Wait for correlation ═══"
    echo "Waiting 10 seconds for correlation engine..."
    sleep 10
    
    echo ""
    echo "═══ STEP 5: Check results ═══"
    echo ""
    echo "Events:"
    curl -s http://localhost:8000/api/events?layer=network | python3 -c "
import sys, json
data = json.load(sys.stdin)
events = data.get('data', {}).get('events', [])
print(f'  Network events: {len(events)}')
for e in events[:5]:
    print(f'    [{e.get(\"severity\", {}).get(\"level\", \"unknown\").upper()}] {e.get(\"event_type\")} from {e.get(\"source_entity\", {}).get(\"ip\")}')
" 2>/dev/null || echo "  Could not fetch events"
    
    echo ""
    echo "Incidents:"
    curl -s http://localhost:8000/api/incidents | python3 -c "
import sys, json
data = json.load(sys.stdin)
incidents = data.get('data', {}).get('incidents', [])
print(f'  Correlated incidents: {len(incidents)}')
for i in incidents[:5]:
    print(f'    [{i.get(\"severity\", \"unknown\").upper()}] {i.get(\"title\")}')
" 2>/dev/null || echo "  Could not fetch incidents"
    
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  PCAP Demo Complete!"
    echo "  Dashboard: http://localhost:3000"
    echo "  Report: evaluation/results/pcap_analysis.json"
    echo "═══════════════════════════════════════════"
    ;;
  
  6)
    echo ""
    echo "Opening dashboard PCAP tab..."
    echo "Go to: http://localhost:3000"
    echo "Click the 'PCAP Analysis' tab"
    echo "Upload a file or select a sample"
    (xdg-open "http://localhost:3000" 2>/dev/null || \
     open "http://localhost:3000" 2>/dev/null || \
     start "http://localhost:3000" 2>/dev/null) &
    ;;
  
  0)
    exit 0
    ;;
  
  *)
    echo "Invalid option"
    exit 1
    ;;
esac
