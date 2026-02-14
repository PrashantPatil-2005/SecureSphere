# SecuriSphere: Phase 1 & 2 - Project Status & Documentation

## 🚀 Project Overview

**SecuriSphere** is a cybersecurity monitoring and threat correlation framework designed to detect, analyze, and correlate security events across multiple layers (Network, Password, API).

**Current Status:**
- **Phase 1 (Foundation):** Completed. Docker infrastructure, environment setup, and Git initialization.
- **Phase 2 (Target Services):** Completed. Development of vulnerable target services (`api-server`, `auth-service`) and integration with Redis event bus.

---

## 🛠️ Setup & Installation

Follow these steps to get the project running on your local machine.

### Prerequisites
- **Docker Desktop** (Running and up-to-date)
- **Git** (Installed and configured)
- **Python 3.10+** (For local testing scripts)

### Quick Start
We have updated the `Makefile` to simplify management.

1.  **Build and Start the Environment:**
    ```bash
    make build
    make start
    ```
    This builds the Docker images and starts all services (Redis, Database, API Server, Auth Service).

2.  **Check Health:**
    ```bash
    make health
    ```
    Verifies that all services including api-server and auth-service are healthy.

3.  **View Logs:**
    ```bash
    make logs
    ```
    Streams logs from all running containers.

4.  **Stop the Environment:**
    ```bash
    make stop
    ```

---

## 🏗️ Technical Architecture

The system is containerized using Docker Compose and consists of the following components connected via a user-defined bridge network (`securisphere-network`).

### 1. Infrastructure Services
- **Database (`securisphere-db`)**: 
    - **Image**: `postgres:15-alpine`
    - **Port**: 5432
    - **Role**: Primary data store for the security platform (correlated incidents, user data).
- **Redis (`securisphere-redis`)**:
    - **Image**: `redis:7.2-alpine`
    - **Port**: 6379
    - **Role**: Event bus for real-time log publishing from target services to monitors.

### 2. Target Services (Vulnerable)
These services are intentionally vulnerable to allow the security modules (Phase 3) to detect attacks. They run in their own containers.

#### A. API Server (`securisphere-api`)
- **Path**: `targets/api-server/`
- **Port**: 5000
- **Internal DB**: SQLite (simulating product/user DB)
- **Tech Stack**: Python 3.10, Flask, Redis Client
- **Vulnerabilities**:
    - **SQL Injection**: `GET /api/products/search?q=` (Unsanitized query injection)
    - **Path Traversal**: `GET /api/files?name=` (Access to system files)
    - **Broken Access Control**: `GET /api/admin/config` (Sensitive config exposed without auth)
    - **Sensitive Data Exposure**: `GET /api/admin/users/export` (Full user dump)
- **Logging**: Publishes request logs to Redis channel `api_logs`.

#### B. Auth Service (`securisphere-auth`)
- **Path**: `targets/auth-service/`
- **Port**: 5001
- **Internal DB**: SQLite (simulating auth DB)
- **Tech Stack**: Python 3.10, Flask, Redis Client
- **Features**:
    - **Brute Force Detection**: Locks account after 5 failed attempts.
    - **Event Publishing**: Publishes `login_success`, `login_failure`, and `account_lockout` events to Redis channel `auth_events`.
- **Endpoints**:
    - `POST /auth/login`: Authenticate user.
    - `POST /auth/reset/<username>`: Reset locked account.
    - `GET /auth/status`: Service health and stats.

---

## 🔍 Verification & Testing

We have successfully verified the implementation using automated tests.

### Automated Tests
Run the comprehensive test suite using `pytest`:
```bash
make test-phase2
```
This runs `tests/test_phase2.py` which verifies:
- API endpoint functionality and health.
- Exploitability of SQL Injection and Path Traversal.
- Brute force lockout mechanism (5 failed attempts -> Lockout).
- Redis event publishing.

### Manual Verification
You can manually test the endpoints using correct `curl` commands:

1.  **Test API Health:**
    ```bash
    make test-api
    ```
    
2.  **Test SQL Injection:**
    ```bash
    curl "http://localhost:5000/api/products/search?q=' OR '1'='1"
    ```
    *Expected Output:* Returns ALL products (bypassing search filter).

3.  **Test Path Traversal:**
    ```bash
    curl "http://localhost:5000/api/files?name=../../../etc/passwd"
    ```
    *Expected Output:* Content of /etc/passwd file (or similar system file).

4.  **Test Auth Service:**
    ```bash
    make test-auth
    ```

---

## 🔜 Next Steps (Phase 3)
With the foundation and target services in place, the next phase will focus on building the **Security Analysis Modules**:
1.  **Network Monitor**: To detect anomalies in traffic.
2.  **API Monitor**: To consume `api_logs` from Redis and detect SQLi/Traversals.
3.  **Auth Monitor**: To consume `auth_events` from Redis and detect brute-force attacks.
