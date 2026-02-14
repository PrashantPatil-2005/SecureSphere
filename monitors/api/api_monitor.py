import os
import time
import json
import logging
import uuid
import re
import threading
import redis
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("APIMonitor")

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class APIMonitor:
    def __init__(self):
        self.redis_host = os.getenv('REDIS_HOST', 'redis')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.target_api = os.getenv('TARGET_API', 'http://api-server:5000')
        
        self.redis_client = None
        self.redis_available = False
        self._connect_redis()
        
        # Detection Patterns
        self.sql_injection_patterns = [
            re.compile(p, re.IGNORECASE) for p in [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b)",
                r"(\b(UNION)\s+(ALL\s+)?SELECT\b)",
                r"(\b(OR|AND)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)",
                r"(\b(OR|AND)\s+[\'\"]?[a-zA-Z]+[\'\"]?\s*=\s*[\'\"]?[a-zA-Z]+)",
                r"([\'\"];?\s*--)",
                r"([\'\"];\s*(DROP|DELETE|INSERT|UPDATE))",
                r"(/\*.*\*/)",
                r"(\bEXEC\s+)",
                r"(\bxp_cmdshell\b)",
                r"(\bWAITFOR\s+DELAY\b)",
                r"(\bBENCHMARK\s*\()",
                r"(\bSLEEP\s*\()"
            ]
        ]
        
        self.path_traversal_patterns = [
            re.compile(p, re.IGNORECASE) for p in [
                r"(\.\.\/)", r"(\.\.\\)",
                r"(%2e%2e%2f)", r"(%2e%2e\/)",
                r"(\.\.%2f)", r"(%2e%2e%5c)",
                r"(\/etc\/passwd)", r"(\/etc\/shadow)",
                r"(\/proc\/self)", r"(C:\\Windows)",
                r"(\/var\/log)", r"(\.\.%252f)"
            ]
        ]
        
        # Rate Tracking
        self.request_tracker = defaultdict(lambda: {
            'count': 0, 'first_request': None, 
            'endpoints': set(), 'window_start': None
        })
        self.rate_window = timedelta(seconds=60)
        self.rate_threshold = 100
        self.enum_threshold = 20
        
        # Request History
        self.request_history = defaultdict(list)
        
        print(f"{Colors.BLUE}[*] API Monitor Initialized{Colors.RESET}")

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
                print(f"{Colors.YELLOW}[!] Redis connection failed. Retrying...{Colors.RESET}")
                time.sleep(3)
        print(f"{Colors.RED}[!] WARNING: Redis unavailable.{Colors.RESET}")
        self.redis_available = False

    def create_event(self, event_type, severity_level, source_ip, 
                     target_endpoint, description, evidence, confidence, tags, mitre):
        
        severity_map = {"low": 20, "medium": 50, "high": 75, "critical": 95}
        category_map = {
            "sql_injection": "exploitation",
            "path_traversal": "exploitation",
            "rate_abuse": "abuse",
            "endpoint_enumeration": "reconnaissance",
            "parameter_tampering": "exploitation",
            "sensitive_access": "abuse"
        }
        
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_layer": "api",
            "source_monitor": "api_monitor_v1",
            "event_category": category_map.get(event_type, "abuse"),
            "event_type": event_type,
            "severity": {"level": severity_level, "score": severity_map.get(severity_level, 50)},
            "source_entity": {"ip": source_ip, "container_id": None, "container_name": None},
            "target_entity": {"ip": self.target_api, "port": 5000, "service": "api-server", "endpoint": target_endpoint, "username": None},
            "detection_details": {
                "method": f"check_{event_type}",
                "confidence": confidence,
                "description": description,
                "evidence": evidence
            },
            "correlation_tags": tags,
            "mitre_technique": mitre
        }
        return event

    def publish_event(self, event):
        color = Colors.GREEN
        if event['severity']['level'] == 'medium': color = Colors.YELLOW
        if event['severity']['level'] == 'high': color = Colors.YELLOW
        if event['severity']['level'] == 'critical': color = Colors.RED
        
        print(f"{color}[!] [{event['severity']['level'].upper()}] {event['event_type']} from {event['source_entity']['ip']} - {event['detection_details']['description']}{Colors.RESET}")
        
        if self.redis_available:
            try:
                self.redis_client.publish('security_events', json.dumps(event))
                self.redis_client.lpush('events:api', json.dumps(event))
                self.redis_client.ltrim('events:api', 0, 999)
            except Exception as e:
                print(f"{Colors.RED}[!] Redis publish failed: {e}{Colors.RESET}")

    def check_sql_injection(self, source_ip, endpoint, params):
        if not params: return False
        
        for param_name, param_value in params.items():
            if not param_value: continue
            
            for pattern in self.sql_injection_patterns:
                if pattern.search(str(param_value)):
                    severity = "high"
                    if "DROP" in str(param_value).upper() or "UNION" in str(param_value).upper():
                        severity = "critical"
                        
                    event = self.create_event(
                        "sql_injection", severity, source_ip, endpoint,
                        f"SQL injection attempt in parameter '{param_name}'",
                        {
                            "parameter": param_name,
                            "payload": str(param_value)[:500],
                            "matched_pattern": pattern.pattern,
                            "endpoint": endpoint,
                            "http_method": "GET"
                        },
                        0.92, ["exploitation", "sqli", "owasp_top10"], "T1190"
                    )
                    self.publish_event(event)
                    return True
        return False

    def check_path_traversal(self, source_ip, endpoint, params):
        values = list(params.values()) if params else []
        values.append(endpoint)
        
        for value in values:
            if not value: continue
            
            for pattern in self.path_traversal_patterns:
                if pattern.search(str(value)):
                    severity = "high"
                    if "/etc/passwd" in str(value) or "/etc/shadow" in str(value):
                        severity = "critical"
                        
                    event = self.create_event(
                        "path_traversal", severity, source_ip, endpoint,
                        f"Path traversal attempt targeting {endpoint}",
                        {
                            "payload": str(value)[:500],
                            "matched_pattern": pattern.pattern,
                            "endpoint": endpoint,
                            "http_method": "GET"
                        },
                        0.88, ["exploitation", "path_traversal", "file_access"], "T1083"
                    )
                    self.publish_event(event)
                    return True
        return False

    def check_rate_abuse(self, source_ip, endpoint):
        now = datetime.now()
        tracker = self.request_tracker[source_ip]
        
        if tracker['window_start'] is None or (now - tracker['window_start']) > self.rate_window:
            # Check threshold before processing new window
            if tracker['count'] > self.rate_threshold:
                severity = "medium" if tracker['count'] < 200 else "high"
                event = self.create_event(
                    "rate_abuse", severity, source_ip, endpoint,
                    f"{tracker['count']} requests from {source_ip} in 1 minute",
                    {
                        "request_count": tracker['count'],
                        "time_window_seconds": 60,
                        "unique_endpoints": len(tracker['endpoints'])
                    }, 0.80, ["abuse", "rate_limit"], None
                )
                self.publish_event(event)
                
            elif len(tracker['endpoints']) > self.enum_threshold:
                 event = self.create_event(
                    "endpoint_enumeration", "medium", source_ip, endpoint,
                    f"API enumeration: {len(tracker['endpoints'])} unique endpoints",
                    {
                        "unique_endpoints": len(tracker['endpoints']),
                        "total_requests": tracker['count']
                    }, 0.75, ["reconnaissance", "api_enumeration"], "T1595"
                )
                 self.publish_event(event)
                 
            # Reset
            tracker['count'] = 0
            tracker['endpoints'] = set()
            tracker['window_start'] = now
            tracker['first_request'] = now
            
        if tracker['first_request'] is None:
            tracker['first_request'] = now
            tracker['window_start'] = now
            
        tracker['count'] += 1
        tracker['endpoints'].add(endpoint)

    def check_sensitive_access(self, source_ip, endpoint, params, status_code):
        sensitive_endpoints = ["/api/admin/config", "/api/admin/users/export"]
        if endpoint in sensitive_endpoints:
            event = self.create_event(
                "sensitive_access", "high", source_ip, endpoint,
                f"Sensitive endpoint {endpoint} accessed by {source_ip}",
                {"endpoint": endpoint, "status_code": status_code, "params": params},
                0.85, ["abuse", "sensitive_data"], "T1530"
            )
            self.publish_event(event)
            return True
        return False

    def process_api_log(self, log_data):
        try:
            data = json.loads(log_data)
            source_ip = data.get('source_ip', 'unknown')
            endpoint = data.get('endpoint', '/')
            params = data.get('params', {})
            status_code = data.get('status_code', 0)
            
            self.check_sql_injection(source_ip, endpoint, params)
            self.check_path_traversal(source_ip, endpoint, params)
            self.check_rate_abuse(source_ip, endpoint)
            self.check_sensitive_access(source_ip, endpoint, params, status_code)
            
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"{Colors.RED}[!] Error processing log: {e}{Colors.RESET}")

    def run_monitor(self):
        print(f"{Colors.BLUE}[*] Subscribing to Redis channel: api_logs{Colors.RESET}")
        
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('api_logs')
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                self.process_api_log(message['data'])

# Flask Health App
app = Flask(__name__)
monitor = APIMonitor()

@app.route('/monitor/health')
def health():
    return jsonify({
        "status": "running", 
        "service": "api-monitor",
        "redis_connected": monitor.redis_available,
        "timestamp": datetime.utcnow().isoformat()
    })

def start_flask():
    app.run(host='0.0.0.0', port=5050, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Start Flask in background thread
    t = threading.Thread(target=start_flask)
    t.daemon = True
    t.start()
    
    # Run Monitor
    monitor.run_monitor()
