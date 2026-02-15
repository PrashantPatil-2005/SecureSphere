import pytest
import requests
import json
import time

BACKEND_URL = "http://localhost:8000"
API_URL = "http://localhost:5000"
AUTH_URL = "http://localhost:5001"

class TestBackendHealth:
    def test_health_endpoint(self):
        try:
            resp = requests.get(f"{BACKEND_URL}/api/health")
        except requests.exceptions.ConnectionError:
            pytest.fail("Backend not reachable")
            
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "securisphere-backend"
        assert "timestamp" in data
        assert "redis_connected" in data

    def test_health_redis_status(self):
        resp = requests.get(f"{BACKEND_URL}/api/health")
        data = resp.json()
        assert data["redis_connected"] == True

class TestDashboardSummary:
    def test_summary_endpoint(self):
        resp = requests.get(f"{BACKEND_URL}/api/dashboard/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "data" in data
        assert "metrics" in data["data"]
        assert "events_by_layer" in data["data"]

    def test_summary_has_metrics(self):
        resp = requests.get(f"{BACKEND_URL}/api/dashboard/summary")
        metrics = resp.json()["data"]["metrics"]
        assert "raw_events" in metrics
        assert "network" in metrics["raw_events"]
        assert "api" in metrics["raw_events"]
        assert "auth" in metrics["raw_events"]
        assert "total" in metrics["raw_events"]

class TestEventsEndpoint:
    @classmethod
    def setup_class(cls):
        # Generate some events first
        try:
            requests.get(f"{API_URL}/api/products/search?q=' OR '1'='1")
            requests.get(f"{API_URL}/api/files?name=../../../etc/passwd")
            time.sleep(3)
        except:
            pass

    def test_get_all_events(self):
        resp = requests.get(f"{BACKEND_URL}/api/events")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "events" in data["data"]
        assert "count" in data["data"]

    def test_filter_by_layer(self):
        resp = requests.get(f"{BACKEND_URL}/api/events?layer=api")
        assert resp.status_code == 200
        data = resp.json()
        for event in data["data"]["events"]:
            assert event["source_layer"] == "api"

    def test_filter_by_severity(self):
        resp = requests.get(f"{BACKEND_URL}/api/events?severity=critical")
        assert resp.status_code == 200
        data = resp.json()
        for event in data["data"]["events"]:
            assert event["severity"]["level"] == "critical"

    def test_limit_parameter(self):
        resp = requests.get(f"{BACKEND_URL}/api/events?limit=5")
        data = resp.json()
        assert len(data["data"]["events"]) <= 5

    def test_events_have_correct_schema(self):
        resp = requests.get(f"{BACKEND_URL}/api/events?limit=1")
        data = resp.json()
        if data["data"]["events"]:
            event = data["data"]["events"][0]
            assert "event_id" in event
            assert "timestamp" in event
            assert "source_layer" in event
            assert "event_type" in event
            assert "severity" in event
            assert "level" in event["severity"]
            assert "score" in event["severity"]
            assert "source_entity" in event
            assert "detection_details" in event

    def test_events_latest(self):
        resp = requests.get(f"{BACKEND_URL}/api/events/latest")
        assert resp.status_code == 200
        data = resp.json()
        assert "latest" in data["data"]
        assert "network" in data["data"]["latest"]
        assert "api" in data["data"]["latest"]
        assert "auth" in data["data"]["latest"]

class TestIncidentsEndpoint:
    def test_get_incidents(self):
        resp = requests.get(f"{BACKEND_URL}/api/incidents")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "incidents" in data["data"]

    def test_incidents_empty_is_ok(self):
        # Before correlation engine runs, incidents should be empty
        resp = requests.get(f"{BACKEND_URL}/api/incidents")
        data = resp.json()
        assert isinstance(data["data"]["incidents"], list)

class TestRiskScoresEndpoint:
    def test_get_risk_scores(self):
        resp = requests.get(f"{BACKEND_URL}/api/risk-scores")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "risk_scores" in data["data"]
        assert "summary" in data["data"]

class TestMetricsEndpoint:
    def test_get_metrics(self):
        resp = requests.get(f"{BACKEND_URL}/api/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "raw_events" in data["data"]
        assert "events_by_severity" in data["data"]

    def test_timeline(self):
        resp = requests.get(f"{BACKEND_URL}/api/metrics/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert "timeline" in data["data"]
        assert isinstance(data["data"]["timeline"], list)

class TestSystemStatus:
    def test_system_status(self):
        resp = requests.get(f"{BACKEND_URL}/api/system/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "redis" in data["data"]
        assert "monitors" in data["data"]
        assert data["data"]["redis"]["connected"] == True

class TestErrorHandling:
    def test_404(self):
        resp = requests.get(f"{BACKEND_URL}/api/nonexistent")
        assert resp.status_code == 404
        data = resp.json()
        assert data["status"] == "error"

    def test_invalid_layer_filter(self):
        resp = requests.get(f"{BACKEND_URL}/api/events?layer=invalid")
        # Should either ignore it (200) or error (400) depending on impl. 
        # Our impl ignores it, but returns empty list because it tries to fetch 'events:invalid' which is empty
        assert resp.status_code in [200, 400]

class TestClearEndpoint:
    def test_clear_events(self):
        resp = requests.post(f"{BACKEND_URL}/api/events/clear")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"

    def test_events_empty_after_clear(self):
        requests.post(f"{BACKEND_URL}/api/events/clear")
        resp = requests.get(f"{BACKEND_URL}/api/events")
        data = resp.json()
        assert data["data"]["count"] == 0
