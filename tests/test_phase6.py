import pytest
import requests
import json
import time
import os

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
API_URL = os.getenv("API_URL", "http://localhost:5000")
AUTH_URL = os.getenv("AUTH_URL", "http://localhost:5001")
ENGINE_URL = os.getenv("ENGINE_URL", "http://localhost:5070")

class TestCorrelationEngineHealth:
    def test_engine_health(self):
        resp = requests.get(f"{ENGINE_URL}/engine/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert "events_processed" in data

    def test_engine_stats(self):
        resp = requests.get(f"{ENGINE_URL}/engine/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "events_processed" in data["data"]

class TestRiskScoring:
    @classmethod
    def setup_class(cls):
        requests.post(f"{BACKEND_URL}/api/events/clear")
        requests.post(f"{AUTH_URL}/auth/reset-all")
        time.sleep(2)

    def test_risk_score_increases_on_attack(self):
        # Send an attack
        requests.get(f"{API_URL}/api/products/search?q=' OR '1'='1")
        time.sleep(3)
        
        # Check risk scores
        resp = requests.get(f"{BACKEND_URL}/api/risk-scores")
        data = resp.json()
        
        risk_data = data["data"]["risk_scores"]
        if risk_data:
            scores = [v.get("current_score", 0) for v in risk_data.values()]
            assert max(scores) > 0

class TestCorrelationRules:
    @classmethod
    def setup_class(cls):
        requests.post(f"{BACKEND_URL}/api/events/clear")
        requests.post(f"{AUTH_URL}/auth/reset-all")
        time.sleep(3)

    def test_api_auth_combined_incident(self):
        # Send SQL injection
        for i in range(3):
            requests.get(f"{API_URL}/api/products/search?q=' OR '1'='1")
            time.sleep(0.3)
        
        # Send brute force
        for i in range(6):
            requests.post(f"{AUTH_URL}/auth/login",
                          json={"username": "admin", "password": f"wrong{i}"})
            time.sleep(0.3)
        
        time.sleep(10)
        
        # Check for incidents
        resp = requests.get(f"{BACKEND_URL}/api/incidents")
        data = resp.json()
        incidents = data["data"]["incidents"]
        
        assert len(incidents) >= 1
        incident = incidents[0]
        assert "incident_id" in incident
        assert "title" in incident
        assert "severity" in incident
        assert "layers_involved" in incident

    def test_data_exfiltration_incident(self):
        # Exploitation first
        requests.get(f"{API_URL}/api/products/search?q=' OR '1'='1")
        requests.get(f"{API_URL}/api/files?name=../../../etc/passwd")
        time.sleep(1)
        
        # Then sensitive access
        requests.get(f"{API_URL}/api/admin/config")
        requests.get(f"{API_URL}/api/admin/users/export")
        time.sleep(5)
        
        # Check incidents
        resp = requests.get(f"{BACKEND_URL}/api/incidents")
        incidents = resp.json()["data"]["incidents"]
        
        # Look for data exfil incident
        found = False
        for inc in incidents:
            if inc.get("incident_type") == "data_exfiltration_risk":
                found = True
                break
        assert found

class TestIncidentsOnDashboard:
    def test_incidents_internal_api(self):
        resp = requests.get(f"{BACKEND_URL}/api/incidents")
        data = resp.json()
        assert data["status"] == "success"
        assert isinstance(data["data"]["incidents"], list)

    def test_dashboard_summary_has_incidents(self):
        resp = requests.get(f"{BACKEND_URL}/api/dashboard/summary")
        data = resp.json()
        assert "metrics" in data["data"]
        # Note: correlated_incidents might count incidents, not be the list itself
        assert "correlated_incidents" in data["data"]["metrics"]
