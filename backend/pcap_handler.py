
import os
import json
import uuid
import time
import threading
import math
from datetime import datetime
from collections import defaultdict, Counter
from werkzeug.utils import secure_filename

# Configuration
UPLOAD_FOLDER = '/app/uploads/pcap'
SAMPLES_FOLDER = '/app/samples/pcap'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

class PcapProcessor:
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.processing_jobs = {}  # job_id → job status
        
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(SAMPLES_FOLDER, exist_ok=True)

    def validate_file(self, filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    def save_uploaded_file(self, file_storage):
        filename = secure_filename(file_storage.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Save file to check size
        file_storage.save(file_path)
        
        # Check size
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            os.remove(file_path)
            raise ValueError("File too large")
            
        return file_path

    def get_sample_files(self):
        samples = []
        if os.path.exists(SAMPLES_FOLDER):
            for f in os.listdir(SAMPLES_FOLDER):
                if self.validate_file(f):
                    path = os.path.join(SAMPLES_FOLDER, f)
                    size = os.path.getsize(path)
                    samples.append({
                        "name": f,
                        "size": size,
                        "size_human": self.human_readable_size(size),
                        "path": path
                    })
        return samples

    def get_pcap_info(self, file_path):
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, ICMP
        
        try:
            # For info, we might want to just read headers or use PcapReader for speed
            # But for simplicity with small files (50MB limit), rdpcap is okay
            packets = rdpcap(file_path)
            
            stats = {
                "total_packets": len(packets),
                "ip_packets": 0,
                "tcp_packets": 0,
                "udp_packets": 0,
                "dns_packets": 0,
                "icmp_packets": 0,
                "other_packets": 0,
                "unique_source_ips": set(),
                "unique_dest_ips": set(),
                "unique_ports": set(),
                "time_range": {"start": None, "end": None, "duration_seconds": 0}
            }
            
            timestamps = []
            
            for pkt in packets:
                ts = float(pkt.time)
                timestamps.append(ts)
                
                if IP in pkt:
                    stats["ip_packets"] += 1
                    stats["unique_source_ips"].add(pkt[IP].src)
                    stats["unique_dest_ips"].add(pkt[IP].dst)
                    
                    if TCP in pkt:
                        stats["tcp_packets"] += 1
                        stats["unique_ports"].add(pkt[TCP].dport)
                    elif UDP in pkt:
                        stats["udp_packets"] += 1
                        if DNS in pkt:
                            stats["dns_packets"] += 1
                    elif ICMP in pkt:
                        stats["icmp_packets"] += 1
                else:
                    stats["other_packets"] += 1
            
            if timestamps:
                stats["time_range"]["start"] = min(timestamps)
                stats["time_range"]["end"] = max(timestamps)
                stats["time_range"]["duration_seconds"] = max(timestamps) - min(timestamps)
            
            # Format for return
            return {
                "file_name": os.path.basename(file_path),
                "file_size": os.path.getsize(file_path),
                "file_size_human": self.human_readable_size(os.path.getsize(file_path)),
                "total_packets": stats["total_packets"],
                "ip_packets": stats["ip_packets"],
                "tcp_packets": stats["tcp_packets"],
                "udp_packets": stats["udp_packets"],
                "dns_packets": stats["dns_packets"],
                "icmp_packets": stats["icmp_packets"],
                "other_packets": stats["other_packets"],
                "unique_source_ips": list(stats["unique_source_ips"]),
                "unique_dest_ips": list(stats["unique_dest_ips"]),
                "unique_ports": sorted(list(stats["unique_ports"]))[:50], # Limit output
                "total_unique_ports": len(stats["unique_ports"]),
                "time_range": stats["time_range"],
                "packet_type_distribution": {
                    "TCP": stats["tcp_packets"],
                    "UDP": stats["udp_packets"],
                    "DNS": stats["dns_packets"],
                    "ICMP": stats["icmp_packets"],
                    "Other": stats["other_packets"]
                }
            }
        except Exception as e:
            print(f"Error getting info: {e}")
            raise

    def process_pcap(self, job_id, file_path):
        # Update status
        self.processing_jobs[job_id]["status"] = "processing"
        
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS
            
            packets = rdpcap(file_path)
            total = len(packets)
            
            # Detection State
            port_scan_state = defaultdict(set) # src_ip -> set(dst_ports)
            traffic_counts = defaultdict(int) # (src_ip, time_window) -> count
            dns_queries = defaultdict(list) # src_ip -> list(query_names)
            
            events = []
            
            # Statistics state for results
            source_ip_counts = Counter()
            
            start_time = time.time()
            
            for i, packet in enumerate(packets):
                # Update progress roughly every 5%
                if total > 0 and i % max(1, int(total * 0.05)) == 0:
                    self.processing_jobs[job_id]["progress"] = int((i / total) * 100)
                
                if IP not in packet:
                    continue
                    
                src_ip = packet[IP].src
                source_ip_counts[src_ip] += 1
                timestamp = float(packet.time)
                
                # --- DETECTION LOGIC (Simplified from NetworkMonitor) ---
                
                # 1. Port Scan Detection
                if TCP in packet and packet[TCP].flags == 'S':
                    port_scan_state[src_ip].add(packet[TCP].dport)
                    if len(port_scan_state[src_ip]) >= 15: # Threshold
                        events.append(self.create_event(
                            "reconnaissance", "port_scan", "medium", src_ip,
                            f"Port scan detected: {len(port_scan_state[src_ip])} ports", 
                            {"ports": list(port_scan_state[src_ip])[:20]},
                            "T1046"
                        ))
                        port_scan_state[src_ip].clear() # Reset to avoid spam
                
                # 2. Traffic Anomaly (Spike)
                window = int(timestamp / 10) # 10s window
                traffic_counts[(src_ip, window)] += 1
                if traffic_counts[(src_ip, window)] > 100: # Threshold: 100 pkts/10s (simplified)
                     # In real monitor this uses baseline, here we use static threshold for demo
                     pass # Skipping event generation for pure volume to reduce noise in demo pcap
                
                # 3. DNS Tunneling
                if DNS in packet and packet.haslayer(DNS) and packet[DNS].qr == 0: # Query
                    qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                    if qname:
                        entropy = self.calculate_entropy(qname)
                        dns_queries[src_ip].append(entropy)
                        
                        # Check last 10 queries
                        if len(dns_queries[src_ip]) >= 10:
                            avg_entropy = sum(dns_queries[src_ip][-10:]) / 10
                            if avg_entropy > 4.0: # Threshold
                                events.append(self.create_event(
                                    "exfiltration", "dns_tunneling", "high", src_ip,
                                    f"High entropy DNS queries detected (avg: {avg_entropy:.2f})",
                                    {"last_query": qname, "entropy": entropy},
                                    "T1048"
                                ))
                                dns_queries[src_ip].clear() # Reset
            
            # Final stats
            file_info = self.get_pcap_info(file_path)
            
            # Deduplicate events (simple)
            unique_events = []
            seen_events = set()
            for e in events:
                key = (e['event_type'], e['source_entity']['ip'])
                if key not in seen_events:
                    unique_events.append(e)
                    seen_events.add(key)
                    # Publish to Redis
                    self.publish_event(e)
            
            results = {
                "file_info": file_info,
                "events_detected": len(unique_events),
                "detected_events": unique_events,
                "source_ip_distribution": [{"ip": k, "count": v} for k, v in source_ip_counts.most_common(10)],
                "analysis_duration": time.time() - start_time
            }
            
            self.processing_jobs[job_id]["results"] = results
            self.processing_jobs[job_id]["status"] = "complete"
            self.processing_jobs[job_id]["progress"] = 100
            self.processing_jobs[job_id]["completed_at"] = datetime.now().isoformat()
            
        except Exception as e:
            print(f"PCAP Processing Error: {e}")
            self.processing_jobs[job_id]["status"] = "error"
            self.processing_jobs[job_id]["error"] = str(e)

    def create_event(self, category, type_, severity, src_ip, desc, evidence, mitre):
        scores = {"low": 20, "medium": 50, "high": 75, "critical": 95}
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_layer": "network",
            "source_monitor": "pcap_analyzer_v1",
            "event_category": category,
            "event_type": type_,
            "severity": {"level": severity, "score": scores.get(severity, 20)},
            "source_entity": {"ip": src_ip},
            "target_entity": {"ip": "unknown"}, # Pcap specific
            "detection_details": {
                "method": "pcap_analysis", 
                "confidence": 0.9, 
                "description": desc,
                "evidence": evidence
            },
            "correlation_tags": ["pcap_analysis", type_],
            "mitre_technique": mitre
        }

    def publish_event(self, event):
        try:
            # Publish to Pub/Sub
            self.redis_client.publish('security_events', json.dumps(event))
            
            # Push to List
            self.redis_client.lpush('events:network', json.dumps(event))
            self.redis_client.ltrim('events:network', 0, 999)
        except Exception as e:
            print(f"Failed to publish pcap event: {e}")

    def start_processing(self, file_path):
        job_id = str(uuid.uuid4())
        self.processing_jobs[job_id] = {
            "job_id": job_id,
            "file": os.path.basename(file_path),
            "file_path": file_path,
            "status": "queued",
            "progress": 0,
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "results": None,
            "error": None
        }
        
        thread = threading.Thread(target=self.process_pcap, args=(job_id, file_path))
        thread.daemon = True
        thread.start()
        
        return job_id

    def get_job_status(self, job_id):
        return self.processing_jobs.get(job_id)

    def get_all_jobs(self):
        # Return list of jobs sorted by started_at desc
        return sorted(
            self.processing_jobs.values(), 
            key=lambda x: x['started_at'], 
            reverse=True
        )

    def human_readable_size(self, size_bytes):
        if size_bytes == 0: return "0 B"
        size_name = ("B", "KB", "MB", "GB", "TB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"

    def calculate_entropy(self, text):
        if not text: return 0
        freq = Counter(text)
        length = len(text)
        return -sum((count/length) * math.log2(count/length) for count in freq.values())
