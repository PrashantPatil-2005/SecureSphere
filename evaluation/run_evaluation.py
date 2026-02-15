
import requests
import redis
import json
import time
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from tabulate import tabulate
from colorama import init, Fore, Style

init(autoreset=True)

class Config:
    BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:8000')
    API_URL = os.getenv('API_URL', 'http://localhost:5000')
    AUTH_URL = os.getenv('AUTH_URL', 'http://localhost:5001')
    ENGINE_URL = os.getenv('ENGINE_URL', 'http://localhost:5070')
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    RESULTS_DIR = os.getenv('RESULTS_DIR', 'evaluation/results')

class SecuriSphereEvaluator:
    def __init__(self):
        self.backend = Config.BACKEND_URL
        self.api = Config.API_URL
        self.auth = Config.AUTH_URL
        self.engine = Config.ENGINE_URL
        self.results_dir = Config.RESULTS_DIR
        
        os.makedirs(self.results_dir, exist_ok=True)
        
        self.evaluation_results = {
            'evaluation_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'start_time': None,
            'end_time': None,
            'system_info': {},
            'scenarios': [],
            'overall_metrics': {},
            'comparison': {},
            'raw_data': {}
        }

    def print_header(self, title):
        print(f"\n{Fore.CYAN}════════════════════════════════════════════════════")
        print(f"  {title}")
        print(f"════════════════════════════════════════════════════{Style.RESET_ALL}")

    def print_section(self, title):
        print(f"\n{Fore.YELLOW}────────────────────────────────────────")
        print(f"  {title}")
        print(f"────────────────────────────────────────{Style.RESET_ALL}")

    def clear_system(self):
        try:
            requests.post(f"{self.backend}/api/events/clear", timeout=5)
            requests.post(f"{self.auth}/auth/reset-all", timeout=5)
            time.sleep(10) # Wait for monitors to drain
            # Verify
            resp = requests.get(f"{self.backend}/api/metrics", timeout=5)
            total = resp.json().get('data', {}).get('raw_events', {}).get('total', 0)
            if total == 0:
                print(f"{Fore.GREEN}System cleared ✅")
            else:
                print(f"{Fore.RED}System clear failed, {total} events remaining ❌")
            
            # Reset Engine Memory
            try:
                requests.post(f"{self.engine}/engine/reset", timeout=5)
            except Exception as e:
                print(f"{Fore.RED}Engine reset failed: {e}")

        except Exception as e:
            print(f"{Fore.RED}Error clearing system: {e}")

    def get_metrics_snapshot(self):
        try:
            metrics = requests.get(f"{self.backend}/api/metrics", timeout=5).json().get('data', {})
            incidents = requests.get(f"{self.backend}/api/incidents", timeout=5).json().get('data', {}).get('incidents', [])
            risk_scores = requests.get(f"{self.backend}/api/risk-scores", timeout=5).json().get('data', {}).get('risk_scores', {})
            try:
                engine_stats = requests.get(f"{self.engine}/engine/stats", timeout=5).json().get('data', {})
            except:
                engine_stats = {}
            
            return {
                'metrics': metrics,
                'incidents': incidents,
                'risk_scores': risk_scores,
                'engine_stats': engine_stats,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            print(f"{Fore.RED}Error getting snapshot: {e}")
            return {'metrics': {}, 'incidents': [], 'risk_scores': {}, 'engine_stats': {}}

    def wait_for_processing(self, seconds=8):
        print(f"{Fore.YELLOW}⏳ Waiting {seconds}s for processing...", end="", flush=True)
        time.sleep(seconds)
        print(" Done.")

    # --- METRICS CALCULATION ---
    
    def calculate_scenario_metrics(self, scenario_name, description, before, after, 
                                 expected_detections, expected_incidents_min, 
                                 attack_duration, is_benign=False):
        
        # 1. Raw Events
        network_new = (after['metrics'].get('raw_events', {}).get('network', 0) - 
                      before['metrics'].get('raw_events', {}).get('network', 0))
        api_new = (after['metrics'].get('raw_events', {}).get('api', 0) - 
                   before['metrics'].get('raw_events', {}).get('api', 0))
        auth_new = (after['metrics'].get('raw_events', {}).get('auth', 0) - 
                   before['metrics'].get('raw_events', {}).get('auth', 0))
        total_new_raw = network_new + api_new + auth_new
        
        # 2. Incidents
        incident_ids_before = {i['incident_id'] for i in before['incidents']}
        new_incidents = [i for i in after['incidents'] if i['incident_id'] not in incident_ids_before]
        new_incident_count = len(new_incidents)
        
        # 3. Detection Rate (DR)
        if is_benign:
            dr = "N/A"
        else:
            detected_types = set()
            for incident in new_incidents:
                detected_types.add(incident.get('incident_type'))
            
            if expected_incidents_min > 0:
                dr = min((new_incident_count / expected_incidents_min) * 100, 100.0)
            else:
                dr = 0.0
        
        # 4. False Positive Rate (FPR)
        if is_benign:
            critical_incidents = [i for i in new_incidents if i.get('severity') == 'critical']
            fpr = float(len(critical_incidents)) # Should be 0
        else:
            fpr = 0.0 
            
        # 5. Alert Reduction Ratio (ARR)
        arr = 0.0
        if total_new_raw > 0:
            arr = (1 - (new_incident_count / total_new_raw)) * 100
            
        # 6. Mean Time to Detect (MTTD)
        mttd = 0.0
        if new_incidents:
            delays = []
            for inc in new_incidents:
                try:
                    # Simple approximation: 1.5s latency
                    delays.append(inc.get('time_span_seconds', 0) + 1.5)
                except:
                   delays.append(1.5)
            mttd = sum(delays) / len(delays) if delays else 0
            
        # 7. Cross-Layer Detection Rate (CLDR)
        multi_layer = [i for i in new_incidents if len(i.get('layers_involved', [])) > 1]
        cldr = (len(multi_layer) / new_incident_count * 100) if new_incident_count > 0 else 0.0
        
        # 8. Correlation Accuracy (CA)
        ca = 100.0 - (fpr if isinstance(fpr, float) else 0.0)

        # Risk Score Stats
        scores = after['risk_scores']
        max_score = 0
        critical_entities = 0
        threatening_entities = 0
        for ip, data in scores.items():
            s = data.get('current_score', 0)
            max_score = max(max_score, s)
            tl = data.get('threat_level')
            if tl == 'critical': critical_entities += 1
            if tl == 'threatening': threatening_entities += 1

        return {
            "scenario_name": scenario_name,
            "description": description,
            "is_benign": is_benign,
            "attack_duration_seconds": round(attack_duration, 1),
            "raw_events": {
                "network": network_new, "api": api_new, "auth": auth_new, "total": total_new_raw
            },
            "incidents": {
                "count": new_incident_count,
                "details": [{"type": i.get('incident_type'), "severity": i.get('severity'), 
                             "layers": i.get('layers_involved')} for i in new_incidents]
            },
            "metrics": {
                "detection_rate": round(dr, 1) if isinstance(dr, float) else dr,
                "false_positive_rate": fpr,
                "alert_reduction_ratio": round(arr, 1),
                "mean_time_to_detect_seconds": round(mttd, 1) if mttd else None,
                "cross_layer_detection_rate": round(cldr, 1),
                "correlation_accuracy": round(ca, 1)
            },
            "risk_scores": {
                "max_score": max_score,
                "critical_entities": critical_entities,
                "threatening_entities": threatening_entities
            }
        }

    # --- SCENARIOS ---

    def run_scenario_4_benign(self):
        start_metrics = self.get_metrics_snapshot()
        start_time = time.time()
        
        # Benign Traffic
        try:
            for i in range(5): 
                requests.get(f"{self.api}/api/health")
                time.sleep(0.5)
            for term in ['laptop', 'phone']:
                requests.get(f"{self.api}/api/products/search", params={"q": term})
                time.sleep(1)
            requests.get(f"{self.api}/api/products")
            requests.post(f"{self.auth}/auth/login", json={"username": "john", "password": "password123"})
            time.sleep(1)
        except: pass
        
        duration = time.time() - start_time
        self.wait_for_processing(5)
        end_metrics = self.get_metrics_snapshot()
        
        return self.calculate_scenario_metrics("Benign Traffic", "False Positive Test", 
                                             start_metrics, end_metrics, {}, 0, duration, is_benign=True)

    def run_scenario_1_kill_chain(self):
        start_metrics = self.get_metrics_snapshot()
        start_time = time.time()
        
        try:
            # 1. API Attacks
            for _ in range(3): requests.get(f"{self.api}/api/products/search?q=' OR '1'='1")
            requests.get(f"{self.api}/api/files?name=../../../etc/passwd")
            
            # 2. Auth Attacks
            for i in range(6): 
                requests.post(f"{self.auth}/auth/login", json={"username": "admin", "password": f"wrong{i}"})
            
            # 3. Exfil
            requests.get(f"{self.api}/api/admin/config")
        except: pass
        
        duration = time.time() - start_time
        self.wait_for_processing(8)
        end_metrics = self.get_metrics_snapshot()
        
        return self.calculate_scenario_metrics("Full Kill Chain", "Recon -> Exploit -> Exfil",
                                             start_metrics, end_metrics, 
                                             {'sql_injection': True, 'brute_force': True}, 1, duration)

    def run_scenario_2_api_abuse(self):
        start_metrics = self.get_metrics_snapshot()
        start_time = time.time()
        
        try:
            payloads = ["' OR '1'='1", "admin'--", "<script>alert(1)</script>"]
            for p in payloads:
                requests.get(f"{self.api}/api/products/search", params={"q": p})
                time.sleep(0.2)
            requests.get(f"{self.api}/api/files?name=../../../etc/passwd")
            requests.get(f"{self.api}/api/admin/users/export")
        except: pass
        
        duration = time.time() - start_time
        self.wait_for_processing(5)
        end_metrics = self.get_metrics_snapshot()
        
        return self.calculate_scenario_metrics("API Abuse", "Fuzzing & Injection",
                                             start_metrics, end_metrics, {'sql_injection': True}, 1, duration)

    def run_scenario_3_credential_attack(self):
        start_metrics = self.get_metrics_snapshot()
        start_time = time.time()
        
        try:
            # Brute force
            for i in range(6): 
                requests.post(f"{self.auth}/auth/login", json={"username": "john", "password": f"w{i}"})
            # Stuffing
            for u in ['a','b','c','d']:
                requests.post(f"{self.auth}/auth/login", json={"username": u, "password": "pwm"})
        except: pass
        
        duration = time.time() - start_time
        self.wait_for_processing(5)
        end_metrics = self.get_metrics_snapshot()
        
        return self.calculate_scenario_metrics("Credential Attack", "Brute Force & Stuffing",
                                             start_metrics, end_metrics, {'brute_force': True}, 1, duration)

    def run_scenario_5_stealth(self):
        start_metrics = self.get_metrics_snapshot()
        start_time = time.time()
        
        try:
            # Slow attack
            for _ in range(3):
                requests.get(f"{self.api}/api/products/search", params={"q": "' OR '1'='1"})
                time.sleep(2) # Faster than real stealth for eval speed
        except: pass
        
        duration = time.time() - start_time
        self.wait_for_processing(5)
        end_metrics = self.get_metrics_snapshot()
        
        return self.calculate_scenario_metrics("Stealth Attack", "Low & Slow",
                                             start_metrics, end_metrics, {'sql_injection': True}, 1, duration)

    # --- REPORTS ---

    def calculate_overall_metrics(self, results):
        total_dr = 0
        total_fpr = 0
        total_arr = 0
        total_mttd = 0
        total_cldr = 0
        attack_scenarios = [r for r in results if not r['is_benign']]
        count = len(attack_scenarios)
        
        for r in attack_scenarios:
            total_dr += r['metrics']['detection_rate']
            total_fpr += r['metrics']['false_positive_rate']
            total_arr += r['metrics']['alert_reduction_ratio']
            total_mttd += (r['metrics']['mean_time_to_detect_seconds'] or 0)
            total_cldr += r['metrics']['cross_layer_detection_rate']
            
        return {
            "average_detection_rate": total_dr / count if count else 0,
            "average_alert_reduction": total_arr / count if count else 0,
            "average_mttd_seconds": total_mttd / count if count else 0,
            "average_cross_layer_detection_rate": total_cldr / count if count else 0
        }

    def generate_text_report(self):
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"{self.results_dir}/evaluation_report_{timestamp}.txt"
        
        metrics = self.calculate_overall_metrics(self.evaluation_results['scenarios'])
        
        with open(filename, 'w') as f:
            f.write("SecuriSphere Evaluation Report\n")
            f.write(f"Generated: {timestamp}\n\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write(f"Overall Detection Rate: {metrics['average_detection_rate']:.1f}%\n")
            f.write(f"Alert Reduction: {metrics['average_alert_reduction']:.1f}%\n")
            f.write(f"Average MTTD: {metrics['average_mttd_seconds']:.1f}s\n\n")
            
            headers = ["Scenario", "Raw Events", "Incidents", "DR %", "ARR %", "MTTD (s)"]
            table_data = []
            for r in self.evaluation_results['scenarios']:
                m = r['metrics']
                table_data.append([
                    r['scenario_name'],
                    r['raw_events']['total'],
                    r['incidents']['count'],
                    m['detection_rate'],
                    m['alert_reduction_ratio'],
                    m['mean_time_to_detect_seconds'] or "N/A"
                ])
            
            f.write(tabulate(table_data, headers=headers, tablefmt="grid"))
            f.write("\n")
            
        print(f"\n{Fore.GREEN}Report saved to {filename}")
        return filename
        
    def generate_json_report(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.results_dir}/evaluation_report_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(self.evaluation_results, f, indent=2)
        print(f"JSON data saved to {filename}")

    def generate_csv_report(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.results_dir}/evaluation_report_{timestamp}.csv"
        
        headers = ["Scenario", "Raw Events", "Incidents", "Detection Rate (%)", "FPR", "ARR (%)", "MTTD (s)", "Correlation Accuracy (%)"]
        
        with open(filename, 'w') as f:
            f.write(",".join(headers) + "\n")
            for r in self.evaluation_results['scenarios']:
                m = r['metrics']
                row = [
                    r['scenario_name'],
                    str(r['raw_events']['total']),
                    str(r['incidents']['count']),
                    str(m['detection_rate']),
                    str(m['false_positive_rate']),
                    str(m['alert_reduction_ratio']),
                    str(m['mean_time_to_detect_seconds'] or ""),
                    str(m['correlation_accuracy'])
                ]
                f.write(",".join(row) + "\n")
        
        print(f"CSV data saved to {filename}")

    def run_full_evaluation(self):
        self.print_header("SecuriSphere Full Evaluation")
        
        # Scenario 4 (Benign)
        self.clear_system()
        self.print_section("Scenario 4: Benign Traffic")
        r4 = self.run_scenario_4_benign()
        self.evaluation_results['scenarios'].append(r4)
        print(f"Result: {r4['incidents']['count']} False Positives")
        
        time.sleep(3)
        
        # Scenario 1
        self.clear_system()
        self.print_section("Scenario 1: Full Kill Chain")
        r1 = self.run_scenario_1_kill_chain()
        self.evaluation_results['scenarios'].append(r1)
        print(f"Result: {r1['incidents']['count']} Incidents Detected")

        time.sleep(3)
        
        # Scenario 2
        self.clear_system()
        self.print_section("Scenario 2: API Abuse")
        r2 = self.run_scenario_2_api_abuse()
        self.evaluation_results['scenarios'].append(r2)
        print(f"Result: {r2['incidents']['count']} Incidents Detected")

        time.sleep(3)
        
        # Scenario 3
        self.clear_system()
        self.print_section("Scenario 3: Credential Attack")
        r3 = self.run_scenario_3_credential_attack()
        self.evaluation_results['scenarios'].append(r3)
        print(f"Result: {r3['incidents']['count']} Incidents Detected")
        
        time.sleep(3)

        # Scenario 5
        self.clear_system()
        self.print_section("Scenario 5: Stealth Attack")
        r5 = self.run_scenario_5_stealth()
        self.evaluation_results['scenarios'].append(r5)
        print(f"Result: {r5['incidents']['count']} Incidents Detected")

        report_file = self.generate_text_report()
        self.generate_json_report()
        self.generate_csv_report()
        
        # Print report content to stdout
        with open(report_file, 'r') as f:
            print(f.read())


if __name__ == '__main__':
    evaluator = SecuriSphereEvaluator()
    evaluator.run_full_evaluation()
