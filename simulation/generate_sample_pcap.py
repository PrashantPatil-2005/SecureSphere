
from scapy.all import (
    IP, TCP, UDP, DNS, DNSQR, Ether,
    wrpcap, RandShort, Raw
)
import os
import sys
import random
import string
from datetime import datetime

def generate_port_scan_pcap(output_file, target_ip="192.168.1.100", attacker_ip="10.0.0.50", port_count=50):
    packets = []
    
    # Common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                    143, 443, 445, 993, 995, 1433, 1521, 3306,
                    3389, 5000, 5001, 5432, 5900, 6379, 8000,
                    8080, 8443, 9090, 9200, 27017]
    
    # Fill remaining with random
    while len(common_ports) < port_count:
        common_ports.append(random.randint(1024, 65535))
    
    # Generate SYN packets
    for port in common_ports[:port_count]:
        pkt = IP(src=attacker_ip, dst=target_ip) / \
              TCP(sport=RandShort(), dport=port, flags="S")
        packets.append(pkt)
    
    # Add some SYN-ACK responses (open ports)
    open_ports = [22, 80, 443, 5000, 8000]
    for port in open_ports:
        pkt = IP(src=target_ip, dst=attacker_ip) / \
              TCP(sport=port, dport=RandShort(), flags="SA")
        packets.append(pkt)
    
    wrpcap(output_file, packets)
    print(f"Generated port scan pcap: {output_file}")
    print(f"  Packets: {len(packets)}")
    print(f"  Ports scanned: {port_count}")

def generate_dns_tunneling_pcap(output_file, attacker_ip="10.0.0.50", dns_server="8.8.8.8", query_count=30):
    packets = []
    
    for i in range(query_count):
        # High entropy subdomain
        random_sub = ''.join(random.choices(
            string.ascii_lowercase + string.digits, k=random.randint(20, 40)
        ))
        query_name = f"{random_sub}.exfil.attacker.com"
        
        pkt = IP(src=attacker_ip, dst=dns_server) / \
              UDP(sport=RandShort(), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=query_name))
        packets.append(pkt)
    
    # Normal queries
    normal_domains = ["google.com", "github.com", "stackoverflow.com", "python.org", "docker.com"]
    for domain in normal_domains:
        pkt = IP(src=attacker_ip, dst=dns_server) / \
              UDP(sport=RandShort(), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=domain))
        packets.append(pkt)
    
    wrpcap(output_file, packets)
    print(f"Generated DNS tunneling pcap: {output_file}")
    print(f"  Packets: {len(packets)}")
    print(f"  Tunneling queries: {query_count}")

def generate_mixed_attack_pcap(output_file, attacker_ip="10.0.0.50", target_ip="192.168.1.100"):
    packets = []
    
    # 1. Port Scan
    print("  Generating port scan packets...")
    for port in range(1, 31):
        pkt = IP(src=attacker_ip, dst=target_ip) / \
              TCP(sport=RandShort(), dport=port * 100, flags="S")
        packets.append(pkt)
    
    # 2. Normal Traffic
    print("  Generating normal traffic...")
    for i in range(10):
        pkt = IP(src="192.168.1.10", dst=target_ip) / \
              TCP(sport=RandShort(), dport=80, flags="S")
        packets.append(pkt)
        pkt2 = IP(src=target_ip, dst="192.168.1.10") / \
               TCP(sport=80, dport=RandShort(), flags="SA")
        packets.append(pkt2)
    
    # 3. DNS Tunneling
    print("  Generating DNS tunneling packets...")
    for i in range(20):
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=30))
        pkt = IP(src=attacker_ip, dst="8.8.8.8") / \
              UDP(sport=RandShort(), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=f"{random_sub}.tunnel.evil.com"))
        packets.append(pkt)
        
    # 4. HTTP Suspicious
    print("  Generating HTTP-like packets...")
    for i in range(5):
        payload = f"GET /api/products/search?q=' OR '1'='1 HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
        pkt = IP(src=attacker_ip, dst=target_ip) / \
              TCP(sport=RandShort(), dport=5000, flags="PA") / \
              Raw(load=payload.encode())
        packets.append(pkt)
        
    wrpcap(output_file, packets)
    print(f"\nGenerated mixed attack pcap: {output_file}")
    print(f"  Total packets: {len(packets)}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate sample .pcap files')
    parser.add_argument('type', choices=['port_scan', 'dns_tunnel', 'mixed', 'all'], help='Type of pcap')
    parser.add_argument('--output-dir', '-o', type=str, default='samples/pcap', help='Output directory')
    
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    print("╔══════════════════════════════════════════╗")
    print("║  SecuriSphere Sample PCAP Generator      ║")
    print("╚══════════════════════════════════════════╝\n")
    
    if args.type in ['port_scan', 'all']:
        generate_port_scan_pcap(f"{args.output_dir}/port_scan_sample.pcap")
    
    if args.type in ['dns_tunnel', 'all']:
        generate_dns_tunneling_pcap(f"{args.output_dir}/dns_tunneling_sample.pcap")
        
    if args.type in ['mixed', 'all']:
        generate_mixed_attack_pcap(f"{args.output_dir}/mixed_attack_sample.pcap")
        
    print("\n═══════════════════════════════════════════")
    print(f"  Files saved to: {args.output_dir}/")
