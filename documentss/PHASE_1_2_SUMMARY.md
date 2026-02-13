# SecuriSphere: Phase 1 & 2 - Project Status & Documentation

## 🚀 Project Overview

**SecuriSphere** is a cybersecurity monitoring and threat correlation framework designed to detect, analyze, and correlate security events across multiple layers (Network, Password, API).

**Current Status:**
- **Phase 1 (Foundation):** Completed. Docker infrastructure, environment setup, and Git initialization.
- **Phase 2 (Target Services):** Completed. Development of vulnerable target services (`api-server`, `auth-service`) and database integration.

---

## 🛠️ Setup & Installation

Follow these steps to get the project running on your local machine.

### Prerequisites
- **Docker Desktop** (Running and up-to-date)
- **Git** (Installed and configured)
- **Python 3.10+** (For local testing scripts)

### Quick Start (Windows)
We have created a `run.bat` script to simplify management on Windows.

1.  **Start the Environment:**
    ```powershell
    .\run.bat start
    ```
    This builds the Docker images and starts all services in the background.

2.  **Check Health:**
    ```powershell
    .\run.bat health
    ```
    Verifies that Redis and PostgreSQL are healthy and ready.

3.  **View Logs:**
    ```powershell
    .\run.bat logs
    ```
    Streams logs from all running containers.

4.  **Stop the Environment:**
    ```powershell
    .\run.bat stop
    ```

---

## 🏗️ Technical Architecture

The system is containerized using Docker Compose and consists of the following components connected via a user-defined bridge network (`securisphere-network`).

### 1. Infrastructure Services
- **Database (`securisphere-db`)**: 
    - **Image**: `postgres:15-alpine`
    - **Port**: 5432
    - **Role**: Stores application data (users) and future security alerts.
    - **Schema**: Initialized with `users` table and seed data (`admin`, `user1`, `user2`).
- **Redis (`securisphere-redis`)**:
    - **Image**: `redis:7.2-alpine`
    - **Port**: 6379
    - **Role**: Message broker for real-time alert processing (Pub/Sub).

### 2. Target Services (Vulnerable)
These services are intentionally vulnerable to allow the security modules (Phase 3) to detect attacks.

#### A. API Server (`securisphere-api`)
- **Path**: `targets/api-server/`
- **Port**: 5000
- **Tech Stack**: Python, Flask, Psycopg2
- **Vulnerabilities**:
    - **SQL Injection**: The `/users?id=` endpoint directly concatenates user input into SQL queries.
    - **IDOR (Insecure Direct Object Reference)**: The `/data/<id>` endpoint accesses files without verifying ownership.
- **Endpoints**:
    - `GET /` : Health check.
    - `GET /users`: List users (Vulnerable to SQLi).
    - `GET /data/<id>`: Retrieve data (Vulnerable to IDOR).

#### B. Auth Service (`securisphere-auth`)
- **Path**: `targets/auth-service/`
- **Port**: 5001
- **Tech Stack**: Python, Flask, PyJWT
- **Vulnerabilities**:
    - **Weak Password Policy**: No complexity requirements for registration.
    - **Hardcoded Secrets**: Uses a weak secret key for JWT signing.
- **Endpoints**:
    - `POST /register`: Create a new user.
    - `POST /login`: Authenticate and receive a JWT.
    - `POST /verify`: Verify a JWT token.

---

## 🔍 Verification & Testing

We have successfully verified the implementation using both automated tests and manual checks.

### Automated Tests
Run the improved test suite using `pytest`:
```bash
python -m pytest tests/test_phase2.py
```
**Coverage:**
- Service reachability (HTTP 200 OK on home endpoints).
- Authentication flow (Register -> Login -> Token generation).
- Database connectivity (API Server correctly querying PostgreSQL).

### Manual Verification
You can manually test the endpoints using `curl` or a browser:

1.  **Test API Server:**
    ```bash
    curl http://localhost:5000/users
    ```
    *Expected Output:* A JSON list of users from the database.

2.  **Test Auth Service:**
    ```bash
    curl -X POST http://localhost:5001/login -H "Content-Type: application/json" -d "{\"username\":\"admin\", \"password\":\"password123\"}"
    ```
    *Expected Output:* A JSON object containing a `token`.

---

## 🔜 Next Steps (Phase 3)
With the foundation and target services in place, the next phase will focus on building the **Security Analysis Modules**:
1.  **Network Monitor**: To detect anomalies in traffic.
2.  **API Monitor**: To detect the SQLi and IDOR attacks we implemented.
3.  **Auth Monitor**: To detect brute-force attacks and weak passwords.
