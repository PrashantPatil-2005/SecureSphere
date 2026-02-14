import os
import time
import json
import logging
import uuid
import threading
import redis
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("AuthMonitor")

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class AuthMonitor:
    def __init__(self):
        self.redis_host = os.getenv('REDIS_HOST', 'redis')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        
        self.redis_client = None
        self.redis_available = False
        self._connect_redis()
        
        # Detection State
        self.ip_failures = defaultdict(lambda: {
            'count': 0, 'usernames': set(), 
            'first_attempt': None, 'last_attempt': None
        })
        
        self.user_failures = defaultdict(lambda: {
            'count': 0, 'source_ips': set(), 'first_attempt': None
        })
        
        self.success_after_failure = defaultdict(lambda: {
            'previous_failures': 0, 'failure_ips': set()
        })
        
        self.lockout_tracker = defaultdict(lambda: {
            'count': 0, 'first_lockout': None, 'usernames': set()
        })
        
        self.alert_cooldowns = defaultdict(lambda: None)
        
        print(f"{Colors.BLUE}[*] Auth Monitor Initialized{Colors.RESET}")

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
                     username, description, evidence, confidence, tags, mitre):
        
        severity_map = {"low": 20, "medium": 50, "high": 75, "critical": 95}
        
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_layer": "auth",
            "source_monitor": "auth_monitor_v1",
            "event_category": "credential_attack",
            "event_type": event_type,
            "severity": {"level": severity_level, "score": severity_map.get(severity_level, 50)},
            "source_entity": {"ip": source_ip, "container_id": None, "container_name": None},
            "target_entity": {"ip": None, "port": 5001, "service": "auth-service", "endpoint": "/auth/login", "username": username},
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
        color = Colors.GREEN
        if event['severity']['level'] == 'medium': color = Colors.YELLOW
        if event['severity']['level'] == 'high': color = Colors.YELLOW
        if event['severity']['level'] == 'critical': color = Colors.RED
        
        print(f"{color}[!] [{event['severity']['level'].upper()}] {event['event_type']} for user {event['target_entity']['username']} - {event['detection_details']['description']}{Colors.RESET}")
        
        if self.redis_available:
            try:
                self.redis_client.publish('security_events', json.dumps(event))
                self.redis_client.lpush('events:auth', json.dumps(event))
                self.redis_client.ltrim('events:auth', 0, 999)
            except Exception as e:
                print(f"{Colors.RED}[!] Redis publish failed: {e}{Colors.RESET}")

    def detect_brute_force(self, source_ip, username):
        now = datetime.now()
        tracker = self.ip_failures[source_ip]
        
        if tracker['first_attempt'] and (now - tracker['first_attempt']).total_seconds() > 120:
             # Reset after 2 mins
             tracker['count'] = 0
             tracker['usernames'] = set()
             tracker['first_attempt'] = now
             
        if not tracker['first_attempt']:
            tracker['first_attempt'] = now
            
        tracker['count'] += 1
        tracker['usernames'].add(username)
        tracker['last_attempt'] = now
        
        # Threshold: 5 failures
        if tracker['count'] >= 5:
            # Check cooldown
            cooldown_key = f"{source_ip}_brute_force"
            if self.alert_cooldowns[cooldown_key] and (now - self.alert_cooldowns[cooldown_key]).total_seconds() < 60:
                return
                
            time_span = (now - tracker['first_attempt']).total_seconds()
            severity = "high" if tracker['count'] < 10 else "critical"
            
            event = self.create_event(
                "brute_force", severity, source_ip, username,
                f"Brute force: {tracker['count']} failed attempts from {source_ip}",
                {
                    "failed_attempts": tracker['count'],
                    "time_window_seconds": round(time_span, 1),
                    "targeted_usernames": list(tracker['usernames'])
                }, min(0.7 + (tracker['count'] * 0.03), 0.98),
                ["credential_attack", "brute_force"], "T1110"
            )
            self.publish_event(event)
            self.alert_cooldowns[cooldown_key] = now

    def detect_credential_stuffing(self, source_ip, username):
        tracker = self.ip_failures[source_ip]
        now = datetime.now()
        
        if len(tracker['usernames']) >= 5:
            cooldown_key = f"{source_ip}_cred_stuffing"
            if self.alert_cooldowns[cooldown_key] and (now - self.alert_cooldowns[cooldown_key]).total_seconds() < 300:
                return

            time_span = (now - tracker['first_attempt']).total_seconds()
            if time_span <= 300: # 5 mins
                event = self.create_event(
                    "credential_stuffing", "high", source_ip, username,
                    f"Credential stuffing: {len(tracker['usernames'])} users tried from {source_ip}",
                    {
                        "unique_usernames": len(tracker['usernames']),
                        "usernames": sorted(list(tracker['usernames'])),
                        "total_attempts": tracker['count']
                    }, 0.88, ["credential_attack", "credential_stuffing", "automated"], "T1110.004"
                )
                self.publish_event(event)
                self.alert_cooldowns[cooldown_key] = now

    def detect_suspicious_login(self, source_ip, username):
        saf = self.success_after_failure[username]
        if saf['previous_failures'] >= 3:
            event = self.create_event(
                "suspicious_login", "critical", source_ip, username,
                f"Suspicious login for '{username}' after {saf['previous_failures']} failures",
                {
                    "previous_failures": saf['previous_failures'],
                    "failure_ips": sorted(list(saf['failure_ips'])),
                    "success_ip": source_ip,
                    "possible_compromise": True
                }, 0.95, ["credential_attack", "account_takeover"], "T1078"
            )
            self.publish_event(event)
        
        # Reset
        self.success_after_failure[username]['previous_failures'] = 0
        self.success_after_failure[username]['failure_ips'] = set()

    def detect_lockout_storm(self, source_ip, username):
        now = datetime.now()
        tracker = self.lockout_tracker[source_ip]
        
        if tracker['first_lockout'] and (now - tracker['first_lockout']).total_seconds() > 300:
            tracker['count'] = 0
            tracker['usernames'] = set()
            tracker['first_lockout'] = now
            
        if not tracker['first_lockout']:
            tracker['first_lockout'] = now
            
        tracker['count'] += 1
        tracker['usernames'].add(username)
        
        if tracker['count'] >= 3:
            event = self.create_event(
                "lockout_storm", "critical", source_ip, username,
                f"Lockout storm: {tracker['count']} accounts locked by {source_ip}",
                {
                    "lockout_count": tracker['count'],
                    "locked_accounts": sorted(list(tracker['usernames']))
                }, 0.93, ["credential_attack", "lockout_storm", "denial_of_service"], "T1110"
            )
            self.publish_event(event)
            tracker['count'] = 0 # Reset to alert again on next batch

    def process_event(self, event_data):
        try:
            data = json.loads(event_data)
            source_ip = data.get('source_ip', 'unknown')
            username = data.get('username', 'unknown')
            event_type = data.get('event_type')
            
            if event_type == 'login_failure':
                self.success_after_failure[username]['previous_failures'] += 1
                self.success_after_failure[username]['failure_ips'].add(source_ip)
                self.detect_brute_force(source_ip, username)
                self.detect_credential_stuffing(source_ip, username)
                
            elif event_type == 'login_success':
                self.detect_suspicious_login(source_ip, username)
                
            elif event_type == 'account_lockout':
                self.detect_lockout_storm(source_ip, username)
                
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"{Colors.RED}[!] Error processing event: {e}{Colors.RESET}")

    def run_monitor(self):
        print(f"{Colors.BLUE}[*] Subscribing to Redis channel: auth_events{Colors.RESET}")
        
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('auth_events')
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                self.process_event(message['data'])

# Flask Health App
app = Flask(__name__)
monitor = AuthMonitor()

@app.route('/monitor/health')
def health():
    return jsonify({
        "status": "running", 
        "service": "auth-monitor",
        "redis_connected": monitor.redis_available,
        "timestamp": datetime.utcnow().isoformat()
    })

def start_flask():
    app.run(host='0.0.0.0', port=5060, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Start Flask
    t = threading.Thread(target=start_flask)
    t.daemon = True
    t.start()
    
    # Run Monitor
    monitor.run_monitor()
