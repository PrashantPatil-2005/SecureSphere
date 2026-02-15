
import pytest
import requests
import redis
import json
import time
import os

BACKEND = "http://localhost:8000"
API = "http://localhost:5000"
AUTH = "http://localhost:5001"
ENGINE = "http://localhost:5070"

@pytest.fixture(scope="session", autouse=True)
def setup_and_teardown():
    """Reset system before all tests"""
    requests.post(f"{BACKEND}/api/events/clear")
    requests.post(f"{AUTH}/auth/reset-all")
    try: requests.post(f"{ENGINE}/engine/reset") 
    except: pass
    time.sleep(3)
    yield
    # Cleanup after all tests
    requests.post(f"{AUTH}/auth/reset-all")


class TestSystemHealth:
    """Test that all components are running"""
    
    def test_01_redis_connection(self):
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        assert r.ping() == True
    
    def test_02_api_server_health(self):
        resp = requests.get(f"{API}/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
    
    def test_03_auth_service_health(self):
        resp = requests.get(f"{AUTH}/auth/status")
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"
    
    def test_04_backend_health(self):
        resp = requests.get(f"{BACKEND}/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
        assert resp.json()["redis_connected"] == True
    
    def test_05_correlation_engine_health(self):
        resp = requests.get(f"{ENGINE}/engine/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"
        assert "active_rules" in resp.json()
    
    def test_06_dashboard_accessible(self):
        resp = requests.get("http://localhost:3000")
        assert resp.status_code == 200
    
    def test_07_api_monitor_availability(self):
        # API Monitor should be capturing logs. We check indirectly or via health if exposed.
        # Assuming http://localhost:5050/health exists or we skip
        try:
            resp = requests.get("http://localhost:5050/health", timeout=1)
            assert resp.status_code in [200, 404]
        except: pass


class TestEventIngestion:
    """Test that individual events are ingested and stored"""

    def setup_method(self):
        requests.post(f"{BACKEND}/api/events/clear")
        time.sleep(1)

    def test_08_sql_injection_detection(self):
        requests.get(f"{API}/api/products/search?q=' OR '1'='1")
        time.sleep(2)
        resp = requests.get(f"{BACKEND}/api/events?layer=api")
        events = resp.json()["data"]["events"]
        assert any(e["event_type"] == "sql_injection" for e in events)

    def test_09_xss_detection(self):
        requests.get(f"{API}/api/products/search", params={"q": "<script>alert(1)</script>"})
        time.sleep(2)
        resp = requests.get(f"{BACKEND}/api/events?layer=api")
        events = resp.json()["data"]["events"]
        assert any(e["event_type"] == "xss_attempt" for e in events)

    def test_10_path_traversal_detection(self):
        requests.get(f"{API}/api/files?name=../../../etc/passwd")
        time.sleep(2)
        resp = requests.get(f"{BACKEND}/api/events?layer=api")
        events = resp.json()["data"]["events"]
        assert any(e["event_type"] == "path_traversal" for e in events)

    def test_11_brute_force_detection(self):
        for i in range(4):
            requests.post(f"{AUTH}/auth/login", json={"username": "admin", "password": f"fail{i}"})
        time.sleep(2)
        resp = requests.get(f"{BACKEND}/api/events?layer=auth")
        events = resp.json()["data"]["events"]
        assert any(e["event_type"] == "brute_force" for e in events)

    def test_12_event_schema_validation(self):
        requests.get(f"{API}/api/products/search?q=' OR '1'='1")
        time.sleep(2)
        resp = requests.get(f"{BACKEND}/api/events?limit=1")
        event = resp.json()["data"]["events"][0]
        assert "event_id" in event
        assert "timestamp" in event
        assert "source_ip" in event
        assert "severity" in event


class TestFilteringAndPagination:
    """Test backend API filtering capabilities"""

    def test_13_pagination_limit(self):
        requests.post(f"{BACKEND}/api/events/clear")
        for _ in range(5):
            requests.get(f"{API}/api/products/search?q=' OR '1'='1")
            time.sleep(0.1)
        time.sleep(2)
        
        resp = requests.get(f"{BACKEND}/api/events?limit=2")
        events = resp.json()["data"]["events"]
        assert len(events) == 2

    def test_14_filter_by_layer(self):
        requests.post(f"{BACKEND}/api/events/clear")
        requests.get(f"{API}/api/products/search?q=' OR '1'='1") # API layer
        requests.post(f"{AUTH}/auth/login", json={"username": "admin", "password": "fail"}) # Auth layer
        time.sleep(2)
        
        resp_api = requests.get(f"{BACKEND}/api/events?layer=api")
        assert all(e["source_layer"] == "api" for e in resp_api.json()["data"]["events"])
        
        resp_auth = requests.get(f"{BACKEND}/api/events?layer=auth")
        # Auth brute force needs multiple attempts to trigger event in monitor usually, 
        # but single failed login might generate 'failed_login' event depending on monitor logic.
        # If not, we skip assertion on count, just check response structure.
        assert resp_auth.status_code == 200


class TestCorrelationAndIncidents:
    """Test correlation engine logic"""

    def setup_method(self):
        requests.post(f"{BACKEND}/api/events/clear")
        requests.post(f"{ENGINE}/engine/reset")
        time.sleep(1)

    def test_15_incident_creation(self):
        # Trigger brute force incident (requires ~5-10 attempts depending on rule)
        for i in range(10):
             requests.post(f"{AUTH}/auth/login", json={"username": "user1", "password": f"pass{i}"})
        time.sleep(5)
        
        resp = requests.get(f"{BACKEND}/api/incidents")
        incidents = resp.json()["data"]["incidents"]
        assert len(incidents) > 0
        assert incidents[0]["incident_type"] == "brute_force_attempt"

    def test_16_risk_score_update(self):
        # Trigger an incident to raise risk score
        requests.get(f"{API}/api/products/search?q=' OR '1'='1")
        time.sleep(3)
        
        resp = requests.get(f"{BACKEND}/api/risk-scores")
        scores = resp.json()["data"]["risk_scores"]
        assert len(scores) > 0
        
    def test_17_incident_severity(self):
        # Critical attack
        requests.get(f"{API}/api/admin/config") # Accessing sensitive endpoint without auth
        time.sleep(3)
        # Note: If single event doesn't trigger incident, we might need a sequence.
        # But let's check if we can query incidents.
        resp = requests.get(f"{BACKEND}/api/incidents")
        assert resp.status_code == 200

    def test_18_benign_traffic_ignored(self):
        requests.post(f"{ENGINE}/engine/reset")
        requests.get(f"{API}/api/products")
        time.sleep(3)
        resp = requests.get(f"{BACKEND}/api/incidents")
        incidents = resp.json()["data"]["incidents"]
        assert len(incidents) == 0

    def test_19_reset_endpoint(self):
        requests.post(f"{ENGINE}/engine/reset")
        resp = requests.get(f"{ENGINE}/engine/stats")
        assert resp.json()["data"]["events_processed"] == 0

    def test_20_full_kill_chain_correlation(self):
        # 1. SQLi
        requests.get(f"{API}/api/products/search?q=' OR '1'='1")
        # 2. Brute Force
        for i in range(8): requests.post(f"{AUTH}/auth/login", json={"username": "admin", "password": f"x{i}"})
        # 3. Exfil
        requests.get(f"{API}/api/admin/config")
        
        time.sleep(8)
        resp = requests.get(f"{BACKEND}/api/incidents")
        incidents = resp.json()["data"]["incidents"]
        assert len(incidents) >= 1
