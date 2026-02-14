import os
import time
import json
import logging
import uuid
import math
import statistics
import redis
from datetime import datetime, timedelta
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'  # Simplified format for color output
)
logger = logging.getLogger("NetworkMonitor")

# Colors for console output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class NetworkMonitor:
    def __init__(self):
        # Configuration
        self.redis_host = os.getenv('REDIS_HOST', 'redis')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.monitor_interface = os.getenv('MONITOR_INTERFACE', 'eth0')
        
        # Redis Connection
        self.redis_client = None
        self.redis_available = False
        self._connect_redis()
        
        # Detection State
        
        # 1. Port Scan State
        self.syn_tracker = defaultdict(lambda: {
            'ports': set(),
            'count': 0,
            'first_seen': None,
            'last_seen': None
        })
        self.alerted_scans = set()
        self.scan_alert_cooldown = timedelta(seconds=60)
        self.last_scan_alert = defaultdict(lambda: None)
        
        # 2. Traffic Anomaly State
        self.traffic_counter = defaultdict(int)
        self.traffic_baseline = defaultdict(list)
        self.window_start = datetime.now()
        self.window_duration = timedelta(seconds=10)
        self.baseline_learning = True
        self.learning_start = datetime.now()
        self.learning_duration = timedelta(minutes=5)
        
        # 3. DNS Tunneling State
        self.dns_queries = defaultdict(list)
        
        print(f"{Colors.BLUE}[*] Network Monitor Initialized{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Connected to Redis: {self.redis_available}{Colors.RESET}")

    def _connect_redis(self):
        for i in range(5):
            try:
                self.redis_client = redis.Redis(
                    host=self.redis_host, 
                    port=self.redis_port, 
                    decode_responses=True
                )
                if self.redis_client.ping():
                    self.redis_available = True
                    return
            except redis.ConnectionError:
                print(f"{Colors.YELLOW}[!] Redis connection attempt {i+1} failed. Retrying...{Colors.RESET}")
                time.sleep(3)
        
        print(f"{Colors.RED}[!] WARNING: Redis unavailable. Events will be logged to console only.{Colors.RESET}")
        self.redis_available = False

    def create_event(self, event_type, severity_level, source_ip, target_ip, 
                     description, evidence, confidence, tags, mitre):
        
        severity_map = {
            "low": 20,
            "medium": 50,
            "high": 75,
            "critical": 95
        }
        
        category_map = {
            "port_scan": "reconnaissance",
            "syn_flood": "denial_of_service",
            "traffic_spike": "anomaly",
            "dns_tunneling": "exfiltration",
            "unusual_port": "anomaly"
        }

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_layer": "network",
            "source_monitor": "network_monitor_v1",
            "event_category": category_map.get(event_type, "anomaly"),
            "event_type": event_type,
            "severity": {
                "level": severity_level,
                "score": severity_map.get(severity_level, 50)
            },
            "source_entity": {
                "ip": source_ip,
                "container_id": None,
                "container_name": None
            },
            "target_entity": {
                "ip": target_ip,
                "port": None,
                "service": None,
                "endpoint": None,
                "username": None
            },
            "detection_details": {
                "method": f"detect_{event_type}",
                "confidence": confidence,
                "description": description,
                "evidence": evidence
            },
            "correlation_tags": tags,
            "mitre_technique": mitre
        }
        return event

    def publish_event(self, event):
        # Console Output
        color = Colors.GREEN
        if event['severity']['level'] == 'medium': color = Colors.YELLOW
        if event['severity']['level'] == 'high': color = Colors.YELLOW # Orange/Yellow
        if event['severity']['level'] == 'critical': color = Colors.RED
        
        print(f"{color}[!] [{event['severity']['level'].upper()}] {event['event_type']} from {event['source_entity']['ip']} - {event['detection_details']['description']}{Colors.RESET}")
        
        if not self.redis_available:
            return

        try:
            # 1. Publish to Pub/Sub channel
            self.redis_client.publish('security_events', json.dumps(event))
            
            # 2. Push to storage list
            self.redis_client.lpush('events:network', json.dumps(event))
            self.redis_client.ltrim('events:network', 0, 999)
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to publish event to Redis: {e}{Colors.RESET}")

    def detect_port_scan(self, packet):
        if not packet.haslayer(TCP):
            return

        # Check for SYN only (SYN=0x02, ACK=0x10)
        # flags can be int or str ('S', 'SA', etc)
        flags = packet[TCP].flags
        if flags != 0x02 and flags != 'S':
            return
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        
        tracker = self.syn_tracker[src_ip]
        now = datetime.now()
        
        # Reset tracker if > 30s since first seen
        if tracker['first_seen'] and (now - tracker['first_seen']).total_seconds() > 30:
            tracker['ports'] = set()
            tracker['count'] = 0
            tracker['first_seen'] = now
            
        if not tracker['first_seen']:
            tracker['first_seen'] = now
            
        tracker['ports'].add(dst_port)
        tracker['count'] += 1
        tracker['last_seen'] = now
        
        unique_ports = len(tracker['ports'])
        
        # Check Cooldown
        if self.last_scan_alert[src_ip] and (now - self.last_scan_alert[src_ip] < self.scan_alert_cooldown):
            return

        # Threshold: 15 unique ports
        if unique_ports >= 15:
            time_span = (now - tracker['first_seen']).total_seconds()
            
            severity = "medium"
            if unique_ports > 30: severity = "high"
            if unique_ports > 100: severity = "critical"
            
            confidence = min(0.7 + (unique_ports / 200), 0.99)
            
            event = self.create_event(
                event_type="port_scan",
                severity_level=severity,
                source_ip=src_ip,
                target_ip=dst_ip, # Last target IP
                description=f"Port scan detected: {unique_ports} unique ports probed from {src_ip} in {time_span:.0f} seconds",
                evidence={
                    "unique_ports_count": unique_ports,
                    "total_syn_packets": tracker['count'],
                    "time_window_seconds": round(time_span, 1),
                    "sample_ports": sorted(list(tracker['ports']))[:20],
                    "scan_rate_per_second": round(tracker['count'] / max(time_span, 1), 2)
                },
                confidence=confidence,
                tags=["recon", "port_scan", "pre-exploitation"],
                mitre="T1046"
            )
            
            self.publish_event(event)
            self.last_scan_alert[src_ip] = now
            
            # Reset tracker to continuously detect new waves
            tracker['ports'] = set()
            tracker['count'] = 0
            tracker['first_seen'] = now

    def detect_traffic_anomaly(self, packet):
        src_ip = packet[IP].src
        self.traffic_counter[src_ip] += 1
        
        now = datetime.now()
        if (now - self.window_start) >= self.window_duration:
            
            # Process window statistics
            for ip, count in self.traffic_counter.items():
                self.traffic_baseline[ip].append(count)
                
                # Keep last 30 windows
                if len(self.traffic_baseline[ip]) > 30:
                    self.traffic_baseline[ip].pop(0)
                
                # Skip if learning or insufficient data
                if self.baseline_learning:
                    continue
                if len(self.traffic_baseline[ip]) < 5:
                    continue
                    
                # Calculate Statistics
                # Use previous samples for baseline, not strictly including current spike
                baseline_samples = self.traffic_baseline[ip][:-1]
                if not baseline_samples: continue

                mean = statistics.mean(baseline_samples)
                stdev = statistics.stdev(baseline_samples) if len(baseline_samples) > 1 else mean * 0.3
                threshold = mean + (3 * stdev)
                
                if count > threshold and threshold > 10:
                    deviation_factor = (count - mean) / max(stdev, 1)
                    
                    severity = "medium"
                    if deviation_factor >= 5: severity = "high"
                    
                    confidence = min(0.6 + (deviation_factor * 0.05), 0.95)
                    
                    event = self.create_event(
                        event_type="traffic_spike",
                        severity_level=severity,
                        source_ip=ip,
                        target_ip=None,
                        description=f"Traffic anomaly from {ip}: {count} packets in 10s window (baseline: {mean:.0f} +/- {stdev:.0f})",
                        evidence={
                            "current_packet_count": count,
                            "baseline_mean": round(mean, 2),
                            "baseline_stdev": round(stdev, 2),
                            "threshold": round(threshold, 2),
                            "deviation_factor": round(deviation_factor, 2),
                            "window_seconds": 10,
                            "baseline_samples": len(baseline_samples)
                        },
                        confidence=confidence,
                        tags=["anomaly", "traffic_spike"],
                        mitre="null"
                    )
                    
                    self.publish_event(event)
            
            # Reset counters
            self.traffic_counter = defaultdict(int)
            self.window_start = now
            
            # Check Learning Phase
            if self.baseline_learning and (now - self.learning_start) > self.learning_duration:
                self.baseline_learning = False
                print(f"{Colors.GREEN}[*] Network Monitor: Baseline learning complete. Anomaly detection active.{Colors.RESET}")

    def _calculate_entropy(self, text):
        if not text: return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def detect_dns_tunneling(self, packet):
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return
            
        # Check if query (qr=0)
        if packet[DNS].qr != 0:
            return
            
        src_ip = packet[IP].src
        query_name = packet[DNSQR].qname.decode('utf-8', 'ignore')
        
        # Calculate Entropy
        entropy = self._calculate_entropy(query_name)
        now = datetime.now()
        
        self.dns_queries[src_ip].append({
            "query": query_name,
            "entropy": entropy,
            "time": now
        })
        
        # Cleanup old queries (> 5 mins)
        self.dns_queries[src_ip] = [q for q in self.dns_queries[src_ip] 
                                  if (now - q['time']).total_seconds() < 300]
        
        recent_queries = self.dns_queries[src_ip]
        if len(recent_queries) >= 10:
            avg_entropy = statistics.mean([q['entropy'] for q in recent_queries])
            max_entropy = max([q['entropy'] for q in recent_queries])
            
            if avg_entropy > 3.5:
                # Create Alert
                event = self.create_event(
                    event_type="dns_tunneling",
                    severity_level="high",
                    source_ip=src_ip,
                    target_ip=None,
                    description=f"Possible DNS tunneling detected from {src_ip}: {len(recent_queries)} high-entropy queries (avg: {avg_entropy:.2f})",
                    evidence={
                        "query_count": len(recent_queries),
                        "average_entropy": round(avg_entropy, 3),
                        "max_entropy": round(max_entropy, 3),
                        "sample_queries": [q['query'] for q in recent_queries[:5]],
                        "time_window_minutes": 5,
                        "entropy_threshold": 3.5
                    },
                    confidence=min(0.7 + (avg_entropy - 3.5) * 0.2, 0.95),
                    tags=["exfiltration", "dns_tunneling", "covert_channel"],
                    mitre="T1048"
                )
                
                self.publish_event(event)
                
                # Clear to avoid spam
                self.dns_queries[src_ip] = []

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return
            
        try:
            self.detect_port_scan(packet)
            self.detect_traffic_anomaly(packet)
            self.detect_dns_tunneling(packet)
        except Exception as e:
            print(f"{Colors.RED}[!] Error processing packet: {e}{Colors.RESET}")

    def start_simulated(self):
        print(f"{Colors.YELLOW}[*] Running in SIMULATED mode - generating test events{Colors.RESET}")
        
        last_port_scan = 0
        last_traffic_spike = 0
        last_dns = 0
        
        while True:
            now = time.time()
            
            # Sim Port Scan (every 30s)
            if now - last_port_scan > 30:
                self.create_event(
                    "port_scan", "medium", "172.18.0.100", "172.18.0.5", 
                    "SIMULATED Port Scan", {}, 0.8, ["simulated"], "T1046"
                )
                self.publish_event({
                    "event_type": "port_scan",
                    "severity": {"level": "medium"},
                    "source_entity": {"ip": "172.18.0.100"},
                    "detection_details": {"description": "SIMULATED Port Scan"}
                })
                last_port_scan = now
                
            time.sleep(1)

    def start(self):
        print(f"{Colors.BLUE}[*] Network Monitor starting on interface: {self.monitor_interface}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Detections enabled: port_scan, traffic_anomaly, dns_tunneling{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Baseline learning period: 5 minutes{Colors.RESET}")
        
        try:
            sniff(iface=self.monitor_interface, prn=self.process_packet, store=False, filter="ip")
        except PermissionError:
            print(f"{Colors.RED}[!] ERROR: Packet capture requires NET_RAW capability.{Colors.RESET}")
            print(f"{Colors.RED}[!] Ensure container has cap_add: NET_RAW, NET_ADMIN{Colors.RESET}")
            # In a real scenario we might fall back to simulated, but strict adherence to instructions 
            # implies we should try to run detecting real packets. 
            # The docker-compose settings should fix this.
        except KeyboardInterrupt:
            print(f"{Colors.BLUE}[*] Network Monitor stopped.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")

if __name__ == '__main__':
    monitor = NetworkMonitor()
    monitor.start()
