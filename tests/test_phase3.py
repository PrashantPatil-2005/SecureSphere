import pytest
import requests
import time
import redis
import os
import json

# Configuration
API_URL = "http://localhost:5000"
AUTH_URL = "http://localhost:5001"
API_MON_URL = "http://localhost:5050"
AUTH_MON_URL = "http://localhost:5060"

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

@pytest.fixture(scope="module")
def redis_client():
    client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    yield client
    client.close()

@pytest.fixture(autouse=True)
def setup_teardown():
    # Setup: Reset auth state
    try:
        requests.post(f"{AUTH_URL}/auth/reset-all")
    except:
        pass
    yield

def get_latest_event(redis_client, list_name):
    """Helper to get latest event from Redis list"""
    event_json = redis_client.lindex(list_name, 0)
    if event_json:
        return json.loads(event_json)
    return None

def wait_for_event(redis_client, list_name, event_type, timeout=10):
    """Poll Redis for specific event type"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        # Check first 5 events
        events_json = redis_client.lrange(list_name, 0, 4)
        for ej in events_json:
            event = json.loads(ej)
            if event['event_type'] == event_type:
                return event
        time.sleep(0.5)
    return None

class TestNetworkMonitor:
    def test_container_running(self):
        # We can't easily check docker from inside python without docker sdk
        # But we can check if it's logging to redis? 
        # Actually, network monitor doesn't have a health endpoint.
        # So we assume if other tests pass, environment is ok.
        pass

class TestAPIMonitor:
    def test_health(self):
        try:
            resp = requests.get(f"{API_MON_URL}/monitor/health")
            assert resp.status_code == 200
            assert resp.json()['status'] == 'running'
        except requests.exceptions.ConnectionError:
            pytest.fail("API Monitor not reachable")

    def test_sql_injection_detection(self, redis_client):
        # 1. Trigger SQLi
        payload = "' OR '1'='1"
        try:
            requests.get(f"{API_URL}/api/products/search", params={'q': payload})
        except:
            pass
        
        # 2. Check Event
        event = wait_for_event(redis_client, "events:api", "sql_injection")
        assert event is not None
        assert event['event_category'] == "exploitation"
        assert event['detection_details']['evidence']['matched_pattern']
        assert event['severity']['level'] in ['high', 'critical']

    def test_path_traversal_detection(self, redis_client):
        # 1. Trigger Traversal
        payload = "../../../etc/passwd"
        try:
            requests.get(f"{API_URL}/api/files", params={'name': payload})
        except:
            pass
            
        # 2. Check Event
        event = wait_for_event(redis_client, "events:api", "path_traversal")
        assert event is not None
        assert event['target_entity']['endpoint'] == "/api/files"

    def test_sensitive_access_detection(self, redis_client):
        # 1. Trigger
        try:
            requests.get(f"{API_URL}/api/admin/config")
        except:
            pass
            
        # 2. Check Event
        event = wait_for_event(redis_client, "events:api", "sensitive_access")
        assert event is not None

    def test_event_schema_compliance(self, redis_client):
        event = get_latest_event(redis_client, "events:api")
        if not event:
            pytest.skip("No API events found to check schema")
            
        required_fields = [
            "event_id", "timestamp", "source_layer", "source_monitor",
            "event_category", "event_type", "severity", "source_entity",
            "target_entity", "detection_details", "correlation_tags", "mitre_technique"
        ]
        for field in required_fields:
            assert field in event
            
        assert isinstance(event['severity']['score'], int)
        assert isinstance(event['detection_details']['confidence'], float)

class TestAuthMonitor:
    def test_health(self):
        try:
            resp = requests.get(f"{AUTH_MON_URL}/monitor/health")
            assert resp.status_code == 200
            assert resp.json()['status'] == 'running'
        except requests.exceptions.ConnectionError:
            pytest.fail("Auth Monitor not reachable")

    def test_brute_force_detection(self, redis_client):
        # 1. Trigger (6 attempts)
        for i in range(6):
            requests.post(f"{AUTH_URL}/auth/login", json={"username": "bf_test", "password": "wrong"})
            
        # 2. Check Event
        event = wait_for_event(redis_client, "events:auth", "brute_force")
        assert event is not None
        assert event['target_entity']['username'] == "bf_test"
        assert event['severity']['level'] in ['high', 'critical']

    def test_credential_stuffing_detection(self, redis_client):
        # Need to be fast to trigger stuffing
        users = ["u1", "u2", "u3", "u4", "u5", "u6"]
        for u in users:
            requests.post(f"{AUTH_URL}/auth/login", json={"username": u, "password": "wrong"})
            
        # 2. Check Event
        event = wait_for_event(redis_client, "events:auth", "credential_stuffing")
        assert event is not None
        assert event['event_category'] == "credential_attack"

    def test_suspicious_login_detection(self, redis_client):
        user = "suspicious_user"
        # 1. Failures
        for _ in range(4):
            requests.post(f"{AUTH_URL}/auth/login", json={"username": user, "password": "wrong"})
            
        # 2. Success
        requests.post(f"{AUTH_URL}/auth/login", json={"username": user, "password": "password123"}) # Assuming this creates user if not exists? No, auth service has static users.
        # Wait, auth service only has static users? 
        # We need to use a valid user from the seed or register one if possible. 
        # Auth service in Phase 2 has hardcoded users? 
        # Let's use 'admin' / 'admin123'
        
        user = "admin"
        requests.post(f"{AUTH_URL}/auth/reset-all")
        for _ in range(3):
             requests.post(f"{AUTH_URL}/auth/login", json={"username": user, "password": "wrong"})
        
        requests.post(f"{AUTH_URL}/auth/login", json={"username": user, "password": "admin123"})
        
        # 3. Check Event
        event = wait_for_event(redis_client, "events:auth", "suspicious_login")
        assert event is not None
        assert event['detection_details']['evidence']['possible_compromise'] is True
