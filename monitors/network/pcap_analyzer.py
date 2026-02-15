
import sys
import os
import json
import time
import argparse
from datetime import datetime
from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, DNS
from collections import defaultdict, Counter

# Ensure we can import network_monitor
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from network_monitor import NetworkMonitor

class PcapAnalyzer:
    def __init__(self, pcap_file, speed=1.0, publish_to_redis=True):
        if not os.path.exists(pcap_file):
            print(f"Error: File not found: {pcap_file}")
            sys.exit(1)
            
        self.pcap_file = pcap_file
        self.speed = speed
        self.publish_to_redis = publish_to_redis
        
        # Initialize Monitor
        self.monitor = NetworkMonitor()
        if not self.publish_to_redis:
            self.monitor.redis_available = False # Disable publishing
            
        self.stats = {
            'total_packets': 0,
            'ip_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'dns_packets': 0,
            'other_packets': 0,
            'unique_source_ips': set(),
            'unique_dest_ips': set(),
            'unique_ports': set(),
            'events_generated': 0,
            'start_time': None,
            'end_time': None,
            'pcap_time_range': {'start': None, 'end': None},
            'file_size_bytes': os.path.getsize(pcap_file)
        }

    def get_pcap_info(self):
        print(f"Reading info from {self.pcap_file}...")
        try:
            # Use PcapReader for large files to avoid memory issues
            count = 0
            start_ts = None
            end_ts = None
            
            with PcapReader(self.pcap_file) as pcap:
                for pkt in pcap:
                    count += 1
                    ts = float(pkt.time)
                    if start_ts is None: start_ts = ts
                    end_ts = ts
                    
            duration = end_ts - start_ts if start_ts and end_ts else 0
            
            info = {
                "file": self.pcap_file,
                "file_size_bytes": self.stats['file_size_bytes'],
                "total_packets": count,
                "duration_seconds": duration,
                "start_timestamp": datetime.fromtimestamp(start_ts).isoformat() if start_ts else "N/A",
                "end_timestamp": datetime.fromtimestamp(end_ts).isoformat() if end_ts else "N/A"
            }
            
            print(json.dumps(info, indent=2))
            return info
        except Exception as e:
            print(f"Error reading pcap info: {e}")
            return {}

    def analyze(self):
        print("\n╔══════════════════════════════════════════════════╗")
        print(f"║  SecuriSphere PCAP Analyzer                      ║")
        print(f"║  File: {os.path.basename(self.pcap_file):<33} ║")
        print(f"║  Size: {self.stats['file_size_bytes'] / 1024:.2f} KB                            ║")
        print("╚══════════════════════════════════════════════════╝\n")

        self.stats['start_time'] = datetime.now()
        
        # Track events before
        events_before = 0
        if self.monitor.redis_available:
            try:
                events_before = self.monitor.redis_client.llen("events:network")
            except: pass

        print("Starting packet analysis...")
        
        try:
            # Load packets (streaming for large files, but rdpcap acceptable for samples)
            # Using rdpcap for simplicity with samples
            packets = rdpcap(self.pcap_file)
            total = len(packets)
            print(f"Processing {total} packets...")
            
            previous_time = None
            
            for i, packet in enumerate(packets):
                self.stats['total_packets'] += 1
                
                # Progress
                if (i + 1) % 50 == 0 or i == total - 1:
                    progress = ((i + 1) / total) * 100
                    print(f"\r  Progress: {progress:.1f}% ({i+1}/{total})", end="", flush=True)

                # Stats
                if IP in packet:
                    self.stats['ip_packets'] += 1
                    self.stats['unique_source_ips'].add(packet[IP].src)
                    self.stats['unique_dest_ips'].add(packet[IP].dst)
                    
                    if TCP in packet:
                        self.stats['tcp_packets'] += 1
                        self.stats['unique_ports'].add(packet[TCP].dport)
                    elif UDP in packet:
                        self.stats['udp_packets'] += 1
                        
                    if DNS in packet:
                        self.stats['dns_packets'] += 1
                else:
                    self.stats['other_packets'] += 1

                # Timing
                pkt_time = float(packet.time)
                if self.stats['pcap_time_range']['start'] is None:
                    self.stats['pcap_time_range']['start'] = pkt_time
                self.stats['pcap_time_range']['end'] = pkt_time

                # Speed Control
                if self.speed > 0 and previous_time is not None:
                    time_diff = pkt_time - previous_time
                    if time_diff > 0:
                        sleep_time = time_diff / self.speed
                        if sleep_time > 0.001:
                            time.sleep(min(sleep_time, 1.0))
                previous_time = pkt_time

                # DETECT
                self.monitor.process_packet(packet)

            print() # Newline

        except Exception as e:
            print(f"\nError analyzing pcap: {e}")
            return

        self.stats['end_time'] = datetime.now()
        
        # Events generated
        events_after = 0
        if self.monitor.redis_available:
            try:
                events_after = self.monitor.redis_client.llen("events:network")
                self.stats['events_generated'] = max(0, events_after - events_before)
            except: pass
            
        self.print_summary()

    def print_summary(self):
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        print("\n╔══════════════════════════════════════════════════╗")
        print("║  Analysis Complete                               ║")
        print("╠══════════════════════════════════════════════════╣")
        print("║  PCAP Statistics:                                ║")
        print(f"║    Total Packets:     {self.stats['total_packets']:<27}║")
        print(f"║    IP Packets:        {self.stats['ip_packets']:<27}║")
        print(f"║    TCP Packets:       {self.stats['tcp_packets']:<27}║")
        print(f"║    UDP Packets:       {self.stats['udp_packets']:<27}║")
        print(f"║    DNS Packets:       {self.stats['dns_packets']:<27}║")
        print(f"║    Unique IPs:        {len(self.stats['unique_source_ips']):<27}║")
        print(f"║                                                  ║")
        print("║  Detection Results:                              ║")
        print(f"║    Events Generated:  {self.stats['events_generated']:<27}║")
        print(f"║    Analysis Time:     {duration:<27.2f}║")
        print(f"║    Published to Redis:{str(self.publish_to_redis):<27}║")
        print("╚══════════════════════════════════════════════════╝")
        
        if self.stats['events_generated'] > 0 and self.publish_to_redis:
            print("\nEvents are visible on the dashboard: http://localhost:3000")

    def generate_report(self, output_file=None):
        if output_file is None:
            output_file = f"pcap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
        report = {
            "file": self.pcap_file,
            "analysis_timestamp": datetime.now().isoformat(),
            "pcap_statistics": {
                "total": self.stats['total_packets'],
                "tcp": self.stats['tcp_packets'],
                "udp": self.stats['udp_packets'],
                "dns": self.stats['dns_packets'],
                "unique_ips": len(self.stats['unique_source_ips']),
                "source_ips": list(self.stats['unique_source_ips'])
            },
            "detection": {
                "events_generated": self.stats['events_generated']
            }
        }
        
        # Convert sets to lists for JSON
        report['pcap_statistics']['source_ips'] = [str(ip) for ip in report['pcap_statistics']['source_ips']]
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved: {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SecuriSphere PCAP Analyzer')
    parser.add_argument('pcap_file', help='Path to .pcap file')
    parser.add_argument('--speed', type=float, default=0, help='Playback speed (0=fast)')
    parser.add_argument('--no-redis', action='store_true', help='Disable Redis publishing')
    parser.add_argument('--info-only', action='store_true', help='Show info only')
    parser.add_argument('--report', type=str, help='Save report to file')

    args = parser.parse_args()

    analyzer = PcapAnalyzer(args.pcap_file, args.speed, not args.no_redis)

    if args.info_only:
        analyzer.get_pcap_info()
    else:
        analyzer.analyze()
        if args.report:
            analyzer.generate_report(args.report)
