import os
import time
import json
import redis
import threading
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from uuid import uuid4
from flask import Flask, jsonify

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("CorrelationEngine")

# Constants
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
CORRELATION_WINDOW = int(os.getenv('CORRELATION_WINDOW', 900))  # 15 minutes
RISK_DECAY_RATE = int(os.getenv('RISK_DECAY_RATE', 5))
RISK_DECAY_INTERVAL = int(os.getenv('RISK_DECAY_INTERVAL', 60))

class CorrelationEngine:
    def __init__(self):
        self.connect_redis()
        
        # State
        self.event_buffer = []
        self.buffer_lock = threading.Lock()
        
        self.risk_scores = defaultdict(lambda: {
            'score': 0,
            'events': [],
            'layers_involved': set(),
            'last_update': None,
            'peak_score': 0,
            'event_count': 0,
            'last_event_type': None,
            'threat_level': 'normal'
        })
        
        self.recent_incidents = []
        self.incident_cooldowns = {}
        self.cooldown_duration = timedelta(minutes=5)
        
        self.rules = [
            self.rule_recon_to_exploit,
            self.rule_credential_compromise,
            self.rule_full_kill_chain,
            self.rule_api_auth_combined,
            self.rule_distributed_attack,
            self.rule_data_exfiltration,
            self.rule_persistent_threat
        ]
        
        self.stats = {
            'events_processed': 0,
            'incidents_created': 0,
            'rules_triggered': defaultdict(int),
            'start_time': datetime.now()
        }
        
        # Flask for Health Check
        self.app = Flask(__name__)
        self.setup_routes()

    def connect_redis(self):
        retries = 5
        while retries > 0:
            try:
                self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
                self.redis.ping()
                logger.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
                
                self.pubsub = self.redis.pubsub()
                self.pubsub.subscribe('security_events')
                return
            except redis.ConnectionError:
                retries -= 1
                logger.warning(f"Redis connection failed. Retries left: {retries}")
                time.sleep(3)
        
        logger.error("Could not connect to Redis. Exiting.")
        exit(1)

    # --- RISK SCORING ---

    def update_risk_score(self, entity_ip, event):
        if not entity_ip:
            return

        severity_points = {
            'low': 10,
            'medium': 25,
            'high': 50,
            'critical': 100
        }
        
        severity = event.get('severity', {}).get('level', 'low')
        points = severity_points.get(severity, 10)
        
        score_data = self.risk_scores[entity_ip]
        
        # Cross-layer bonus check
        current_layer = event.get('source_layer')
        if current_layer:
            score_data['layers_involved'].add(current_layer)
        
        if len(score_data['layers_involved']) > 1:
            points = int(points * 1.5)
            
        score_data['score'] += points
        score_data['peak_score'] = max(score_data['peak_score'], score_data['score'])
        score_data['event_count'] += 1
        score_data['last_event_type'] = event.get('event_type')
        score_data['last_update'] = datetime.now().isoformat()
        score_data['threat_level'] = self.get_threat_level(score_data['score'])
        
        # Keep last 50 events for history
        score_data['events'].append({
            'event_id': event.get('event_id'),
            'type': event.get('event_type'),
            'layer': current_layer,
            'severity': severity,
            'points': points,
            'timestamp': event.get('timestamp')
        })
        score_data['events'] = score_data['events'][-50:]
        
        self.publish_risk_score(entity_ip, score_data, points)

    def get_threat_level(self, score):
        if score > 150: return 'critical'
        if score > 70: return 'threatening'
        if score > 30: return 'suspicious'
        return 'normal'

    def publish_risk_score(self, ip, data, points_added):
        payload = {
            "entity_ip": ip,
            "current_score": data['score'],
            "peak_score": data['peak_score'],
            "threat_level": data['threat_level'],
            "layers_involved": list(data['layers_involved']),
            "event_count": data['event_count'],
            "last_event_type": data['last_event_type'],
            "last_update": data['last_update'],
            "points_added": points_added
        }
        
        # To Channel
        self.redis.publish("risk_scores", json.dumps(payload))
        
        # To Hash (Persistent)
        self.redis.hset("risk_scores_current", ip, json.dumps(payload))
        
        colors = {
            'normal': '\033[92m',       # Green
            'suspicious': '\033[93m',   # Yellow
            'threatening': '\033[91m',  # Red
            'critical': '\033[95m'      # Magenta/Purple
        }
        reset = '\033[0m'
        c = colors.get(data['threat_level'], reset)
        
        logger.info(f"{c}[RISK] {ip}: {data['score']} ({data['threat_level']}) | +{points_added} pts{reset}")

    def decay_risk_scores_loop(self):
        while True:
            time.sleep(RISK_DECAY_INTERVAL)
            try:
                ips_to_remove = []
                for ip, data in self.risk_scores.items():
                    if data['score'] > 0:
                        data['score'] = max(0, data['score'] - RISK_DECAY_RATE)
                        data['threat_level'] = self.get_threat_level(data['score'])
                        
                        # Update Redis
                        self.publish_risk_score(ip, data, -RISK_DECAY_RATE)
                    
                    # Cleanup old zero-score entries (older than 30m)
                    if data['score'] == 0:
                        last_up = datetime.fromisoformat(data['last_update']) if data['last_update'] else datetime.min
                        if (datetime.now() - last_up).total_seconds() > 1800:
                            ips_to_remove.append(ip)

                for ip in ips_to_remove:
                    del self.risk_scores[ip]
                    self.redis.hdel("risk_scores_current", ip)
                                    
            except Exception as e:
                logger.error(f"Error in decay loop: {e}")

    # --- CORRELATION HELPERS ---

    def check_cooldown(self, rule_name, key):
        cooldown_key = f"{rule_name}:{key}"
        if cooldown_key in self.incident_cooldowns:
            if datetime.now() < self.incident_cooldowns[cooldown_key] + self.cooldown_duration:
                return True
        return False

    def set_cooldown(self, rule_name, key):
        cooldown_key = f"{rule_name}:{key}"
        self.incident_cooldowns[cooldown_key] = datetime.now()

    def create_incident(self, incident_type, title, description, severity, confidence, source_ip, correlated_events, layers, mitre, actions, extra=None):
        timestamps = [e.get('timestamp') for e in correlated_events if e.get('timestamp')]
        time_span = 0
        if timestamps:
            times = [datetime.fromisoformat(t.replace('Z', '')) for t in timestamps]
            time_span = (max(times) - min(times)).total_seconds()

        current_risk = self.risk_scores[source_ip]['score'] if source_ip else 0

        incident = {
            "incident_id": str(uuid4()),
            "incident_type": incident_type,
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "source_ip": source_ip,
            "correlated_events": [e.get('event_id') for e in correlated_events],
            "correlated_event_count": len(correlated_events),
            "layers_involved": list(set(layers)),
            "mitre_techniques": mitre,
            "recommended_actions": actions,
            "risk_score_at_time": current_risk,
            "time_span_seconds": int(time_span),
            "timestamp": datetime.now().isoformat()
        }
        
        if extra:
            incident.update(extra)
            
        return incident

    def publish_incident(self, incident):
        json_str = json.dumps(incident)
        
        # Publish
        self.redis.publish("correlated_incidents", json_str)
        self.redis.lpush("incidents", json_str)
        self.redis.ltrim("incidents", 0, 99)
        
        self.recent_incidents.append(incident)
        if len(self.recent_incidents) > 50:
            self.recent_incidents.pop(0)
            
        self.stats['incidents_created'] += 1
        self.stats['rules_triggered'][incident['incident_type']] += 1
        
        # Banner
        print("\033[91m")  # Red
        print("════════════════════════════════════════════")
        print(f"[INCIDENT] [{incident['severity'].upper()}] {incident['title']}")
        print(f"[INCIDENT] Type: {incident['incident_type']}")
        print(f"[INCIDENT] Source: {incident['source_ip']}")
        print(f"[INCIDENT] Layers: {incident['layers_involved']}")
        print(f"[INCIDENT] Events: {incident['correlated_event_count']}")
        print("════════════════════════════════════════════")
        print("\033[0m") # Reset

    # --- RULES ---

    def rule_recon_to_exploit(self, new_event, buffer):
        if new_event.get('event_type') not in ['sql_injection', 'path_traversal']:
            return None
            
        source_ip = new_event.get('source_entity', {}).get('ip')
        if not source_ip or self.check_cooldown('recon_to_exploit', source_ip):
            return None

        # Look for past port scans
        scans = [e for e in buffer 
                 if e.get('source_entity', {}).get('ip') == source_ip 
                 and e.get('event_type') == 'port_scan']
                 
        if scans:
            latest_scan = scans[-1]
            try:
                t1 = datetime.fromisoformat(latest_scan['timestamp'].replace('Z', ''))
                t2 = datetime.fromisoformat(new_event['timestamp'].replace('Z', ''))
                if (t2 - t1).total_seconds() <= 600:
                    self.set_cooldown('recon_to_exploit', source_ip)
                    return self.create_incident(
                        "recon_to_exploitation",
                        "Reconnaissance → Exploitation Chain Detected",
                        f"Source {source_ip} performed network reconnaissance followed by {new_event['event_type']} attack.",
                        "critical", 0.92, source_ip, [latest_scan, new_event], ["network", "api"],
                        ["T1046", "T1190"], ["Block IP", "Audit Logs"]
                    )
            except: pass
        return None

    def rule_credential_compromise(self, new_event, buffer):
        if new_event.get('event_type') != 'suspicious_login':
            return None
            
        source_ip = new_event.get('source_entity', {}).get('ip')
        username = new_event.get('target_entity', {}).get('username')
        if not source_ip or self.check_cooldown('credential_compromise', source_ip):
            return None
            
        # Look for previous brute force/stuffing from same IP
        attacks = [e for e in buffer
                   if e.get('source_entity', {}).get('ip') == source_ip
                   and e.get('event_type') in ['brute_force', 'credential_stuffing']]
                   
        if attacks:
            self.set_cooldown('credential_compromise', source_ip)
            return self.create_incident(
                "credential_compromise",
                "🔓 Credential Compromise Detected",
                f"Account '{username}' accessed from {source_ip} after failed attempts.",
                "critical", 0.95, source_ip, [attacks[-1], new_event], ["auth"],
                ["T1110", "T1078"], ["Reset Password", "Block IP", "Check MFA"],
                {'target_username': username}
            )
        return None

    def rule_full_kill_chain(self, new_event, buffer):
        source_ip = new_event.get('source_entity', {}).get('ip')
        if not source_ip or self.check_cooldown('full_kill_chain', source_ip):
            return None
            
        ip_events = [e for e in buffer if e.get('source_entity', {}).get('ip') == source_ip]
        layers = set(e.get('source_layer') for e in ip_events)
        
        if {'network', 'api', 'auth'}.issubset(layers):
            self.set_cooldown('full_kill_chain', source_ip)
            return self.create_incident(
                "full_kill_chain",
                "🚨 MULTI-VECTOR ATTACK CAMPAIGN",
                f"Source {source_ip} attacking across Network, API, and Auth layers.",
                "critical", 0.97, source_ip, ip_events, list(layers),
                ["T1046", "T1190", "T1110"], ["ISOLATE HOST", "Incident Response"]
            )
        return None

    def rule_api_auth_combined(self, new_event, buffer):
        relevant_types = ['rate_abuse', 'sql_injection', 'credential_stuffing', 'brute_force']
        if new_event.get('event_type') not in relevant_types:
            return None
            
        source_ip = new_event.get('source_entity', {}).get('ip')
        if not source_ip or self.check_cooldown('api_auth_combined', source_ip):
            return None
            
        ip_events = [e for e in buffer if e.get('source_entity', {}).get('ip') == source_ip]
        
        has_api = any(e for e in ip_events if e.get('source_layer') == 'api')
        has_auth = any(e for e in ip_events if e.get('source_layer') == 'auth')
        
        if has_api and has_auth:
            self.set_cooldown('api_auth_combined', source_ip)
            return self.create_incident(
                "automated_attack_tool",
                "🤖 Automated Attack Tool Detected",
                f"Source {source_ip} targeting both API and Auth endpoints simultaneously.",
                "high", 0.88, source_ip, ip_events, ["api", "auth"],
                ["T1110", "T1190"], ["Rate Limit", "CAPTCHA", "Block IP"]
            )
        return None

    def rule_distributed_attack(self, new_event, buffer):
        if new_event.get('event_type') not in ['brute_force', 'credential_stuffing']:
            return None
            
        username = new_event.get('target_entity', {}).get('username')
        if not username or self.check_cooldown('distributed_attack', username):
            return None
            
        targeting_events = [e for e in buffer if e.get('target_entity', {}).get('username') == username]
        unique_ips = set(e.get('source_entity', {}).get('ip') for e in targeting_events if e.get('source_entity', {}).get('ip'))
        
        if len(unique_ips) >= 3:
            self.set_cooldown('distributed_attack', username)
            return self.create_incident(
                "distributed_credential_attack",
                "🌐 Distributed Credential Attack",
                f"Account '{username}' targeted by {len(unique_ips)} IPs.",
                "critical", 0.90, list(unique_ips)[0], targeting_events, ["auth"],
                ["T1110.004"], ["Lock Account", "Block IPs"],
                {'target_username': username, 'attacking_ips': list(unique_ips)}
            )
        return None

    def rule_data_exfiltration(self, new_event, buffer):
        if new_event.get('event_type') != 'sensitive_access':
            return None
            
        source_ip = new_event.get('source_entity', {}).get('ip')
        if not source_ip or self.check_cooldown('data_exfiltration', source_ip):
            return None
            
        # Check for prior exploitation
        exploits = [e for e in buffer 
                    if e.get('source_entity', {}).get('ip') == source_ip
                    and e.get('event_type') in ['sql_injection', 'path_traversal']]
                    
        if exploits:
            self.set_cooldown('data_exfiltration', source_ip)
            return self.create_incident(
                "data_exfiltration_risk",
                "📤 Data Exfiltration Risk Detected",
                f"Source {source_ip} accessed sensitive endpoints after exploitation attempt.",
                "high", 0.85, source_ip, [exploits[-1], new_event], ["api"],
                ["T1530", "T1190"], ["Audit Access", "Restrict Permissions"]
            )
        return None

    def rule_persistent_threat(self, new_event, buffer):
        source_ip = new_event.get('source_entity', {}).get('ip')
        if not source_ip or self.check_cooldown('persistent_threat', source_ip):
            return None
            
        ip_events = [e for e in buffer if e.get('source_entity', {}).get('ip') == source_ip]
        if len(ip_events) >= 10:
            timestamps = [datetime.fromisoformat(e['timestamp'].replace('Z','')) for e in ip_events]
            duration = (max(timestamps) - min(timestamps)).total_seconds()
            
            if duration >= 300: # 5 mins
                unique_types = len(set(e.get('event_type') for e in ip_events))
                if unique_types >= 3:
                    self.set_cooldown('persistent_threat', source_ip)
                    return self.create_incident(
                        "persistent_threat",
                        "⏱️ Persistent Threat Actor",
                        f"Source {source_ip} generated {len(ip_events)} events over {duration/60:.1f} mins.",
                        "high", 0.82, source_ip, ip_events, list(set(e.get('source_layer') for e in ip_events)),
                        ["T1595"], ["Block IP", "Threat Intel"]
                    )
        return None

    # --- PROCESSING ---

    def process_event(self, event_data):
        try:
            if isinstance(event_data, str):
                event = json.loads(event_data)
            else:
                event = event_data
        except:
            logger.error("Failed to parse event data")
            return

        self.stats['events_processed'] += 1
        source_ip = event.get('source_entity', {}).get('ip')
        
        # Add to buffer
        with self.buffer_lock:
            self.event_buffer.append(event)
            # Cleanup old events
            cutoff = datetime.now() - timedelta(seconds=CORRELATION_WINDOW)
            self.event_buffer = [e for e in self.event_buffer 
                                 if datetime.fromisoformat(e['timestamp'].replace('Z','')) > cutoff]
            
            # Make copy for rules
            buffer_copy = list(self.event_buffer)

        # Update Risk
        if source_ip:
            self.update_risk_score(source_ip, event)

        # Run Rules
        for rule in self.rules:
            try:
                incident = rule(event, buffer_copy)
                if incident:
                    self.publish_incident(incident)
            except Exception as e:
                logger.error(f"Error in rule {rule.__name__}: {e}")

        logger.info(f"[EVENT] {event.get('source_layer')} | {event.get('event_type')} | {source_ip}")

    def publish_summary_loop(self):
        while True:
            time.sleep(30)
            try:
                with self.buffer_lock:
                    count = len(self.event_buffer)
                    layers = Counter(e.get('source_layer') for e in self.event_buffer)
                    types = Counter(e.get('event_type') for e in self.event_buffer)
                    
                risk_summary = {ip: {'score': d['score'], 'level': d['threat_level']} 
                               for ip, d in self.risk_scores.items() if d['score'] > 0}
                
                summary = {
                    "total_events_in_window": count,
                    "events_by_layer": dict(layers),
                    "events_by_type": dict(types),
                    "active_incidents": len(self.recent_incidents),
                    "total_incidents": self.stats['incidents_created'],
                    "risk_scores": risk_summary,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.redis.publish("correlation_summary", json.dumps(summary))
                self.redis.set("latest_summary", json.dumps(summary))
                
            except Exception as e:
                logger.error(f"Summary loop error: {e}")

    # --- FLASK SETUP ---

    def setup_routes(self):
        @self.app.route('/engine/health')
        def health():
            return jsonify({
                "status": "running",
                "events_processed": self.stats['events_processed'],
                "incidents_created": self.stats['incidents_created'],
                "active_risks": len(self.risk_scores),
                "uptime": (datetime.now() - self.stats['start_time']).total_seconds()
            })
            
        @self.app.route('/engine/stats')
        def stats():
            return jsonify({
                "status": "success",
                "data": self.stats
            })
            
        @self.app.route('/engine/risk-scores')
        def risks():
            return jsonify({
                "status": "success", 
                "data": {k: v for k, v in self.risk_scores.items()}
            })

    def run_flask(self):
        self.app.run(host='0.0.0.0', port=5070, use_reloader=False)

    def start(self):
        logger.info("Starting SecuriSphere Correlation Engine...")
        
        # Start Threads
        threading.Thread(target=self.run_flask, daemon=True).start()
        threading.Thread(target=self.decay_risk_scores_loop, daemon=True).start()
        threading.Thread(target=self.publish_summary_loop, daemon=True).start()
        
        # Redis Loop
        while True:
            try:
                for message in self.pubsub.listen():
                    if message['type'] == 'message':
                        self.process_event(message['data'])
            except Exception as e:
                logger.error(f"Redis loop error: {e}")
                time.sleep(1)
                self.connect_redis()

if __name__ == '__main__':
    engine = CorrelationEngine()
    engine.start()
