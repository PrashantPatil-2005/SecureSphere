import pytest
import requests
import json
import time

# Configuration
API_URL = "http://localhost:5000"
AUTH_URL = "http://localhost:5001"

def wait_for_service(url, timeout=30):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    return False

def test_api_server_health():
    """Verify API Server is reachable"""
    assert wait_for_service(API_URL), "API Server is not reachable"
    response = requests.get(API_URL)
    assert response.status_code == 200
    assert response.json()["service"] == "api-server"

def test_auth_service_health():
    """Verify Auth Service is reachable"""
    assert wait_for_service(AUTH_URL), "Auth Service is not reachable"
    response = requests.get(AUTH_URL)
    assert response.status_code == 200
    assert response.json()["service"] == "auth-service"

def test_auth_flow():
    """Test Registration and Login"""
    # Register
    username = f"testuser_{int(time.time())}"
    password = "password123"
    
    reg_response = requests.post(f"{AUTH_URL}/register", json={
        "username": username,
        "password": password
    })
    assert reg_response.status_code == 201
    
    # Login
    login_response = requests.post(f"{AUTH_URL}/login", json={
        "username": username,
        "password": password
    })
    assert login_response.status_code == 200
    token = login_response.json().get("token")
    assert token is not None

def test_api_db_connection():
    """Verify API Server can connect to DB (via users endpoint)"""
    # Note: DB might be empty, but endpoint should return 200 (empty list) or data
    # It shouldn't return 500 error if DB connection is working
    try:
        response = requests.get(f"{API_URL}/users")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    except Exception as e:
        pytest.fail(f"API Server DB check failed: {e}")
