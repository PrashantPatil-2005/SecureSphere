import requests
import time
import sys
import json
import socket
import random
import string
import argparse
from datetime import datetime
from colorama import init, Fore, Back, Style

init(autoreset=True)  # Initialize colorama

# --- CONFIGURATION ---

class Config:
    API_URL = "http://api-server:5000"
    AUTH_URL = "http://auth-service:5001"
    BACKEND_URL = "http://backend:8000"
    ENGINE_URL = "http://correlation-engine:5070"
    
    # Delays between stages (seconds)
    DEMO_DELAY = 8      # For live demo (slow, audience can watch)
    NORMAL_DELAY = 3     # Normal testing
    FAST_DELAY = 1       # Fast testing
    
    # Attack timing
    REQUEST_DELAY = 0.3  # Delay between individual requests

# --- UTILITY FUNCTIONS ---

def banner(title, subtitle=""):
    print(Fore.CYAN + "╔══════════════════════════════════════════════════╗")
    print(Fore.CYAN + f"║  🎯 SecuriSphere Attack Simulator               ║")
    print(Fore.CYAN + f"║  Scenario: {title.ljust(29)}       ║")
    print(Fore.CYAN + f"║  Time: {datetime.now().strftime('%H:%M:%S').ljust(33)}   ║")
    if subtitle:
        print(Fore.CYAN + f"║  {subtitle.ljust(46)}  ║")
    print(Fore.CYAN + "╚══════════════════════════════════════════════════╝")
    print("")

def stage_header(stage_num, stage_name, icon):
    print(Fore.YELLOW + f"┌──────────────────────────────────────────────┐")
    print(Fore.YELLOW + f"│  {icon} STAGE {stage_num}: {stage_name.ljust(33)}   │")
    print(Fore.YELLOW + f"└──────────────────────────────────────────────┘")

def log(stage_num, action, detail="", status="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    color = Fore.CYAN
    if status == "attack": color = Fore.RED
    elif status == "success": color = Fore.GREEN
    elif status == "fail": color = Fore.YELLOW
    elif status == "detect": color = Fore.MAGENTA
    
    stage_str = f"[Stage {stage_num}]" if stage_num else "[Setup]"
    print(f"{Fore.WHITE}[{timestamp}] {color}{stage_str.ljust(10)} {action.ljust(25)} {Style.RESET_ALL}{detail}")

def wait(seconds, reason=""):
    print(f"{Fore.YELLOW}⏳ Waiting {seconds}s {reason}...", end="", flush=True)
    for _ in range(seconds):
        time.sleep(1)
        print(".", end="", flush=True)
    print(" Done.")

def check_service(url, name):
    try:
        requests.get(url, timeout=2)
        print(f"{Fore.GREEN}{name}: Ready ✅")
        return True
    except:
        print(f"{Fore.RED}{name}: Not reachable ❌")
        return False

def reset_auth_accounts():
    try:
        requests.post(f"{Config.AUTH_URL}/auth/reset-all", timeout=5)
        print(f"{Fore.GREEN}All auth accounts reset ✅")
    except:
        print(f"{Fore.RED}Failed to reset auth accounts ❌")

def clear_all_events():
    try:
        requests.post(f"{Config.BACKEND_URL}/api/events/clear", timeout=5)
        print(f"{Fore.GREEN}All events and incidents cleared ✅")
    except:
        print(f"{Fore.RED}Failed to clear events ❌")

def get_incidents():
    try:
        resp = requests.get(f"{Config.BACKEND_URL}/api/incidents", timeout=5)
        return resp.json().get('data', {}).get('incidents', [])
    except:
        return []

def get_risk_scores():
    try:
        resp = requests.get(f"{Config.BACKEND_URL}/api/risk-scores", timeout=5)
        return resp.json().get('data', {})
    except:
        return {}

def get_metrics():
    try:
        resp = requests.get(f"{Config.BACKEND_URL}/api/metrics", timeout=5)
        return resp.json()
    except:
        return {}

# --- ATTACK SIMULATOR CLASS ---

class AttackSimulator:
    def __init__(self, delay_mode="normal", verify=True):
        self.delay = Config.NORMAL_DELAY
        if delay_mode == "demo": self.delay = Config.DEMO_DELAY
        elif delay_mode == "fast": self.delay = Config.FAST_DELAY
        self.verify = verify
        self.results = []
        self.start_time = datetime.now()

    def record_result(self, scenario, stage, action, success, detail=""):
        self.results.append({
            "scenario": scenario, "stage": stage, "action": action,
            "success": success, "detail": detail, "timestamp": datetime.now().isoformat()
        })

    # === SCENARIO 1: Full Kill Chain ===
    def scenario_full_kill_chain(self):
        banner("Full Kill Chain Attack", "Recon → Exploit → Credential → Exfil")
        
        check_service(f"{Config.API_URL}/api/health", "API Server")
        clear_all_events()
        reset_auth_accounts()
        wait(3, "for clean state")

        # Stage 1: Recon
        stage_header(1, "Network Reconnaissance", "📡")
        log(1, "Scanning common ports...")
        
        target_host = "api-server"
        ports = [22, 80, 443, 5000, 5001, 8000, 6379, 5432]
        open_ports = []
        
        try:
            target_ip = socket.gethostbyname(target_host)
            for port in ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    log(1, f"Port {port} OPEN", "api-server", "success")
                    open_ports.append(port)
                s.close()
        except:
             # Fallback if hostname resolution fails in some envs
             log(1, "Hostname resolution failed", "Using simulated scan", "fail")
             open_ports = [5000, 5001]
             
        log(1, f"Scan complete: {len(open_ports)} open ports", str(open_ports))
        self.record_result("full_kill_chain", 1, "port_scan", True, f"{len(open_ports)} ports")
        wait(self.delay, "Analyzing scan results")

        # Stage 2: Discovery
        stage_header(2, "API Endpoint Discovery", "🔍")
        log(2, "Enumerating endpoints...")
        
        endpoints = ['/api/health', '/api/products', '/api/users', '/api/admin/config', 
                     '/api/files', '/api/login', '/api/v1/users', '/dashboard']
        
        discovered = []
        for ep in endpoints:
            try:
                r = requests.get(f"{Config.API_URL}{ep}", timeout=1)
                status = r.status_code
                log(2, f"GET {ep}", f"Status: {status}", "success" if status < 400 else "fail")
                if status < 400: discovered.append(ep)
            except: pass
            time.sleep(0.1)
            
        wait(self.delay, "Selecting vectors")

        # Stage 3: SQL Injection
        stage_header(3, "SQL Injection Exploitation", "💉")
        payloads = [
            ("' OR '1'='1", "Basic OR bypass"),
            ("' UNION SELECT 1,2,3--", "Data Extraction"),
            ("'; DROP TABLE users--", "Destructive")
        ]
        
        for payload, name in payloads:
            try:
                requests.get(f"{Config.API_URL}/api/products/search", params={'q': payload})
                log(3, f"SQLi: {name}", f"Payload: {payload}", "attack")
            except: pass
            time.sleep(Config.REQUEST_DELAY)
            
        wait(self.delay // 2, "Preparing traversal")

        # Stage 4: Path Traversal
        stage_header(4, "Path Traversal Attack", "📂")
        payloads = ["../../../etc/passwd", "..%2f..%2fetc%2fpasswd"]
        
        for p in payloads:
            try:
                requests.get(f"{Config.API_URL}/api/files", params={'name': p})
                log(4, "Traversal Attempt", f"Path: {p}", "attack")
            except: pass
            time.sleep(Config.REQUEST_DELAY)
            
        wait(self.delay, "Pivoting to auth")

        # Stage 5: Brute Force
        stage_header(5, "Credential Brute Force", "🔐")
        passwords = ['123456', 'password', 'admin', 'welcome', 'admin123']
        
        success = False
        for p in passwords:
            try:
                r = requests.post(f"{Config.AUTH_URL}/auth/login", json={"username":"admin", "password":p})
                if r.json().get('status') == 'success':
                    log(5, f"admin:{p}", "🚨 LOGIN SUCCESS!", "success")
                    success = True
                    break
                else:
                    log(5, f"admin:{p}", "❌ Failed", "fail")
                    if "locked" in r.text:
                        requests.post(f"{Config.AUTH_URL}/auth/reset/admin")
            except: pass
            time.sleep(Config.REQUEST_DELAY)
            
        wait(self.delay, "Using credentials")

        # Stage 6: Exfiltration
        stage_header(6, "Data Exfiltration", "🏴")
        targets = ["/api/admin/config", "/api/admin/users/export"]
        
        for t in targets:
            try:
                requests.get(f"{Config.API_URL}{t}")
                log(6, f"Accessing {t}", "Data Extracted", "attack")
            except: pass
            time.sleep(0.5)

        # Verification
        if self.verify:
            wait(5, "for correlation")
            stage_header(7, "Verification", "🔍")
            incidents = get_incidents()
            log(7, f"Incidents Detected: {len(incidents)}", "", "detect")
            for i in incidents:
                log(7, f"[{i['severity'].upper()}] {i['title']}", f"Layers: {i['layers_involved']}", "detect")

    # === SCENARIO 2: API Abuse ===
    def scenario_api_abuse(self):
        banner("API Abuse Campaign", "Fuzzing & Injection")
        clear_all_events()
        reset_auth_accounts()
        
        stage_header(1, "Parameter Fuzzing", "🔧")
        payloads = ["<script>alert(1)</script>", "{{7*7}}", "' OR '1'='1", "../../../etc/passwd"]
        
        for p in payloads:
            requests.get(f"{Config.API_URL}/api/products/search", params={'q': p})
            log(1, "Fuzzing", f"Payload: {p}", "attack")
            time.sleep(0.2)
            
        wait(self.delay, "Switching to injection")
        
        stage_header(2, "Targeted Injection", "💉")
        for _ in range(5):
             requests.get(f"{Config.API_URL}/api/products/search", params={'q': "' UNION SELECT user,pass FROM users--"})
             log(2, "SQLi Attempt", "Extracting Users", "attack")
             time.sleep(0.5)

        if self.verify:
            wait(5, "for correlation")
            incidents = get_incidents()
            log(3, f"Incidents: {len(incidents)}", "", "detect")

    # === SCENARIO 3: Credential Attack ===
    def scenario_credential_attack(self):
        banner("Credential Attack", "Brute Force & Stuffing")
        clear_all_events()
        reset_auth_accounts()
        
        stage_header(1, "Brute Force", "🔐")
        for i in range(6):
            requests.post(f"{Config.AUTH_URL}/auth/login", json={"username":"john", "password":f"wrong{i}"})
            log(1, "Login Attempt", f"john:wrong{i}", "fail")
            time.sleep(0.2)
            
        wait(self.delay, "Resetting targets")
        reset_auth_accounts()
        
        stage_header(2, "Credential Stuffing", "📋")
        users = [('jane','123'), ('bob','pass'), ('alice','qwerty'), ('john','password123')]
        for u,p in users:
            r = requests.post(f"{Config.AUTH_URL}/auth/login", json={"username":u, "password":p})
            status = "✅ Success" if r.json().get('status')=='success' else "❌ Fail"
            log(2, f"Stuffing", f"{u}:{p} -> {status}", "info")
            time.sleep(0.3)
            
        if self.verify:
            wait(5, "for correlation")
            incidents = get_incidents()
            log(3, f"Incidents: {len(incidents)}", "", "detect")

    # === SCENARIO 4: Benign Traffic ===
    def scenario_benign_traffic(self):
        banner("Benign Traffic", "False Positive Test")
        clear_all_events()
        reset_auth_accounts()
        
        stage_header(1, "Normal Activity", "🛒")
        searches = ['laptop', 'phone', 'camera']
        for s in searches:
            requests.get(f"{Config.API_URL}/api/products/search", params={'q': s})
            log(1, "Search", s, "success")
            time.sleep(1)
            
        stage_header(2, "Valid Login", "👤")
        requests.post(f"{Config.AUTH_URL}/auth/login", json={"username":"john","password":"password123"})
        log(2, "Login", "john:password123", "success")
        
        if self.verify:
            wait(5, "Checking for False Positives")
            incidents = get_incidents()
            crit = [i for i in incidents if i['severity']=='critical']
            if not crit:
                log(3, "Result", "✅ Zero critical incidents (Pass)", "success")
            else:
                log(3, "Result", f"❌ {len(crit)} False Positives!", "fail")

    # === SCENARIO 5: Stealth Attack ===
    def scenario_stealth_attack(self):
        banner("Stealth Attack", "Low & Slow")
        clear_all_events()
        
        stage_header(1, "Slow Probing", "🐌")
        for i in range(3):
            requests.get(f"{Config.API_URL}/api/products/search", params={'q': "' OR '1'='1"})
            log(1, "Probe", f"Attempt {i+1}", "attack")
            wait(5, "to evade detection")
            
        if self.verify:
             incidents = get_incidents()
             log(2, f"Incidents: {len(incidents)} (May be 0 if too slow)", "", "info")

    def run_all(self):
        self.scenario_benign_traffic()
        wait(5)
        self.scenario_full_kill_chain()
        wait(5)
        self.scenario_api_abuse()
        wait(5)
        self.scenario_credential_attack()
        wait(5)
        self.scenario_stealth_attack()

# --- MAIN ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SecuriSphere Attack Simulator')
    parser.add_argument('scenario', nargs='?', default='help', 
                        choices=['full_kill_chain', 'api_abuse', 'credential_attack', 
                                 'benign', 'stealth', 'all', 'help'])
    parser.add_argument('--delay', default='normal', choices=['fast', 'normal', 'demo'])
    parser.add_argument('--no-verify', action='store_true')
    
    args = parser.parse_args()
    
    if args.scenario == 'help':
        parser.print_help()
        sys.exit(0)
        
    sim = AttackSimulator(delay_mode=args.delay, verify=not args.no_verify)
    
    print(Fore.WHITE + "Waiting for services...")
    time.sleep(2)
    
    if args.scenario == 'full_kill_chain': sim.scenario_full_kill_chain()
    elif args.scenario == 'api_abuse': sim.scenario_api_abuse()
    elif args.scenario == 'credential_attack': sim.scenario_credential_attack()
    elif args.scenario == 'benign': sim.scenario_benign_traffic()
    elif args.scenario == 'stealth': sim.scenario_stealth_attack()
    elif args.scenario == 'all': sim.run_all()
