# 📖 SecuriSphere — Technical Documentation

> Comprehensive technical reference for all phases of the SecuriSphere Multi-Layer Integrated Cybersecurity Monitoring System.

---

## Table of Contents

1. [Phase 1: Docker Lab Environment](#phase-1-docker-lab-environment)
2. [Phase 2: Security Modules](#phase-2-security-modules)
3. [Phase 3: Integration & Correlation Backend](#phase-3-integration--correlation-backend)
4. [Data Flow & Architecture](#data-flow--architecture)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Changelog](#changelog)

---

## Phase 1: Docker Lab Environment

### Docker Services

| Service | Image | IP Address | Port | Purpose |
|---------|-------|------------|------|---------|
| victim | Custom FastAPI | 10.0.0.10 | 8000 | Vulnerable test API |
| attacker | Kali Linux | 10.0.0.50 | — | Attack simulation |
| zeek | zeek/zeek | 10.0.0.20 | — | Network traffic capture |
| analyzer | Python | — | — | Legacy anomaly detection |

### Network Configuration

```yaml
networks:
  labnet:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.0.0/24
          gateway: 10.0.0.1
```

### Victim App Vulnerabilities

| Vulnerability | Endpoint | OWASP Category |
|---------------|----------|----------------|
| Broken Authentication | `/users/{username}` | API2:2023 |
| Weak Password Policy | `/login` | N/A |
| IDOR | `/api/user/{id}/profile` | API1:2023 |
| Sensitive Data Exposure | `/debug/config` | API8:2023 |
| No Rate Limiting | `/login`, `/` | API4:2023 |
| SQL Injection (simulated) | `/search?q=` | API8:2023 |

---

## Phase 2: Security Modules

### Network Anomaly Detector

**Location:** `modules/network/anomaly_detector.py`

Detects network traffic anomalies using IsolationForest ML and Z-score statistics.

#### Classes

| Class | Purpose |
|-------|---------|
| `NetworkAnomalyDetector` | Main detection engine |

#### Detection Methods

| Method | Technique | When Used |
|--------|-----------|-----------|
| IsolationForest | Unsupervised ML | Trained model available |
| Z-score | Statistical | Fallback (model unavailable) |

#### Alert Format

```json
{
  "module": "network",
  "type": "connection_anomaly",
  "severity": "high",
  "timestamp": "2026-02-10T07:00:00",
  "connection": {
    "src_ip": "10.0.0.50",
    "dst_ip": "10.0.0.10",
    "dst_port": 8000,
    "protocol": "tcp"
  },
  "features": {
    "duration": 0.5,
    "total_bytes": 50000
  },
  "analysis": {
    "z_score": 4.2,
    "baseline_mean": 1200.0,
    "baseline_std": 800.0
  }
}
```

#### CLI

```bash
python modules/network/anomaly_detector.py --log-path /logs/conn.log --mode collect  # Baseline
python modules/network/anomaly_detector.py --log-path /logs/conn.log --mode detect   # Detect
python modules/network/anomaly_detector.py --log-path /logs/conn.log --output alerts.json
```

---

### Password Policy Auditor

**Location:** `modules/password/auditor.py`

Audits password policies against NIST SP 800-63B and industry standards.

#### Classes

| Class | Purpose |
|-------|---------|
| `PasswordPolicyAuditor` | Main audit engine |
| `AuditResult` | Stores audit score, grade, issues |
| `ComplianceIssue` | Individual policy violation |

#### Standards Supported

| Standard | Min Length | Complexity | Max Age | MFA |
|----------|-----------|------------|---------|-----|
| `nist` | 8 | No | No rotation | Yes |
| `nist-strict` | 12 | No | No rotation | Yes |
| `industry` | 12 | Yes | 90 days | Yes |

#### Alert Format

```json
{
  "module": "password",
  "type": "policy_audit",
  "severity": "high",
  "timestamp": "2026-02-10T07:02:00",
  "summary": {
    "score": 35,
    "grade": "D",
    "compliant": false,
    "standard": "nist",
    "issues_count": 5
  },
  "issues_by_severity": { "critical": [...], "high": [...] },
  "recommendations": ["Enforce minimum 12-char passwords", ...]
}
```

#### CLI

```bash
python modules/password/auditor.py --config /etc/security/pwquality.conf
python modules/password/auditor.py --config policy.conf --standard industry
python modules/password/auditor.py --ldap-uri ldap://localhost --base-dn "dc=example,dc=com"
```

---

### API Security Scanner

**Location:** `modules/api/scanner.py`

Scans API endpoints for OWASP API Security Top 10 (2023) vulnerabilities.

#### OWASP Mapping

| OWASP ID | Name | Test Performed |
|----------|------|----------------|
| API1:2023 | Broken Object Level Authorization | BOLA/IDOR via ID manipulation |
| API2:2023 | Broken Authentication | Unauthenticated access, weak creds |
| API4:2023 | Unrestricted Resource Consumption | 20 rapid requests (rate limiting) |
| API8:2023 | Security Misconfiguration | Missing headers, SQL injection |

#### Alert Format

```json
{
  "module": "api",
  "type": "security_scan",
  "severity": "critical",
  "timestamp": "2026-02-10T07:05:00",
  "target": "http://victim-app:8000",
  "summary": {
    "total_vulnerabilities": 5,
    "by_severity": { "critical": 2, "high": 1, "medium": 1, "low": 1 }
  },
  "vulnerabilities": [
    {
      "owasp_id": "API2:2023",
      "severity": "critical",
      "title": "Unauthenticated Access to Sensitive Endpoint",
      "endpoint": "/users/admin",
      "remediation": "Implement proper authentication..."
    }
  ]
}
```

#### CLI

```bash
python modules/api/scanner.py --target http://victim-app:8000
python modules/api/scanner.py --target http://localhost:8000 --endpoints /api/users,/api/admin
python modules/api/scanner.py --target http://localhost:8000 --output vulns.json
```

---

## Phase 3: Integration & Correlation Backend

### Overview

Phase 3 introduces a **FastAPI backend** that serves as the central integration hub. It receives alerts from all Phase 2 modules via REST API, stores them in **SQLite**, and runs a **correlation engine** with 5 rules that automatically group related alerts into escalated incidents.

### Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| API Framework | FastAPI + Uvicorn | REST API + ASGI server |
| Database | SQLite + SQLAlchemy ORM | Alert/incident storage |
| Schemas | Pydantic v2 | Request/response validation |
| Scheduler | APScheduler | Periodic correlation fallback |
| Testing | requests + custom script | Sample alert submission |

### Files

| File | Lines | Purpose |
|------|-------|---------|
| `backend/main.py` | ~370 | FastAPI app — all endpoints, CORS, startup |
| `backend/models.py` | ~150 | Pydantic schemas + severity helper functions |
| `backend/database.py` | ~170 | SQLAlchemy engine, ORM models, session factory |
| `backend/correlation_engine.py` | ~490 | 5-rule correlation engine with stories |
| `backend/scheduler.py` | ~100 | APScheduler integration (every 60s) |
| `scripts/submit_sample_alerts.py` | ~280 | 8 sample alerts designed to trigger all rules |

---

### Database Schema

Three tables in SQLite (`backend/securisphere.db`):

```
┌──────────────────┐       ┌─────────────────────┐       ┌──────────────────┐
│     alerts       │       │  incident_alerts     │       │   incidents      │
├──────────────────┤       │  (join table)        │       ├──────────────────┤
│ id (PK, auto)    │←──────│  alert_id (FK)       │       │ incident_id (PK) │
│ module           │       │  incident_id (FK)    │──────→│ rule_name        │
│ type             │       └─────────────────────┘       │ severity         │
│ severity         │                                      │ story            │
│ timestamp        │                                      │ created_at       │
│ asset            │                                      └──────────────────┘
│ details (JSON)   │
│ created_at       │
└──────────────────┘
```

- **SQLite WAL mode** enabled for better concurrent read performance
- **Foreign keys** enforced via PRAGMA
- **Many-to-many** relationship: one incident can reference multiple alerts

---

### Correlation Engine Deep Dive

**Location:** `backend/correlation_engine.py`

The engine pulls alerts from the **last 30 minutes** and applies 5 rules using pure Python loops. Each rule uses a **"best match" strategy** — every alert is paired with its closest partner (by time), preventing N×M explosion.

#### Rule 1: Credential Abuse Likely

```
TRIGGER:    Password alert (severity ≥ medium)
          + Network anomaly
          → Same asset, within 10 minutes

SEVERITY:   Critical

STORY:      "A weak password policy was flagged alongside abnormal
             network traffic. An attacker likely obtained valid
             credentials and is conducting unauthorized access."
```

#### Rule 2: Recon + Active Exploitation

```
TRIGGER:    Network anomaly (scanning/probing)
          + API vulnerability (exploitable weakness)
          → Same asset

SEVERITY:   Critical

STORY:      "The attacker first scanned the network to discover
             services, then exploited a known API vulnerability.
             This is a targeted, multi-stage intrusion."
```

#### Rule 3: Multi-Signal Attack in Progress

```
TRIGGER:    3+ alerts with severity ≥ medium
          → Same asset, within 15 minutes

SEVERITY:   max(all severities), minimum High

SPECIAL:    Only ONE incident per asset (largest group).
            Old subsets are automatically replaced.

STORY:      "Multiple security signals converging on the same
             asset indicates a coordinated multi-vector attack."
```

#### Rule 4: API Takeover Attempt

```
TRIGGER:    API authentication vulnerability
          + Network brute-force traffic (severity ≥ medium)
          → Same asset

SEVERITY:   Critical

STORY:      "An attacker is exploiting weak authentication while
             running credential stuffing against the API endpoints."
```

#### Rule 5: Identity Compromise Risk

```
TRIGGER:    Any password policy alert
          + Network alert of type "new_ip_login" or "unusual_access"
          → Same asset

SEVERITY:   High

STORY:      "Weak password + login from unrecognised IP suggests
             the user's identity has been compromised."
```

#### Anti-Duplication Strategy

1. **Exact-set dedup** — Before creating an incident, the engine checks if the same set of alert IDs already exists
2. **Best-match pairing** — Each alert participates in at most one incident per rule (closest time match wins)
3. **Superset replacement** — For Rule 3, if a new group is a strict superset of an existing incident, the old one is deleted and replaced

---

### API Endpoint Reference

#### `POST /alerts` — Submit Alert

Receives a JSON alert and triggers correlation automatically.

**Request:**
```json
{
  "module": "network",
  "type": "connection_anomaly",
  "severity": "high",
  "timestamp": "2026-02-10T07:00:00",
  "asset": "victim-app:8000",
  "details": { "src_ip": "10.0.0.50", "dst_port": 8000 }
}
```

**Response (201):**
```json
{
  "id": 1,
  "module": "network",
  "type": "connection_anomaly",
  "severity": "high",
  "timestamp": "2026-02-10T07:00:00",
  "asset": "victim-app:8000",
  "details": { "src_ip": "10.0.0.50", "dst_port": 8000 },
  "created_at": "2026-02-10T07:00:01"
}
```

#### `GET /alerts` — List Alerts

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `module` | string | Filter: `network`, `password`, `api` |
| `severity` | string | Filter: `info`, `low`, `medium`, `high`, `critical` |
| `asset` | string | Filter by asset name |
| `limit` | int | Max results (default 100, max 1000) |

#### `GET /incidents` — List Incidents

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Filter by escalated severity |
| `limit` | int | Max results (default 50, max 500) |

**Response:**
```json
[
  {
    "incident_id": "a8f2c3c5-...",
    "rule_name": "Credential Abuse Likely",
    "severity": "critical",
    "story": "🔴 CRITICAL — Credential Abuse Likely\n\nWhat happened:\n  ...",
    "alert_ids": [1, 2],
    "created_at": "2026-02-10T07:00:05"
  }
]
```

#### `GET /stats` — Dashboard Statistics

**Response:**
```json
{
  "total_alerts": 8,
  "total_incidents": 8,
  "alerts_by_module": { "network": 4, "password": 2, "api": 2 },
  "alerts_by_severity": { "info": 0, "low": 0, "medium": 4, "high": 3, "critical": 1 },
  "incidents_by_severity": { "high": 1, "critical": 7 }
}
```

#### `POST /correlate` — Manual Correlation Trigger

Force the engine to run against all recent alerts.

#### `GET /health` — Health Check

Returns `{"status": "healthy", "version": "3.0.0"}`.

---

## Data Flow & Architecture

```
1. TRAFFIC GENERATION
   ┌──────────┐         ┌──────────┐
   │ Attacker │───HTTP──│  Victim  │
   └──────────┘         └──────────┘
         │                    │
         └────────┬───────────┘
                  │
2. TRAFFIC CAPTURE
                  ▼
           ┌──────────┐
           │   Zeek   │
           └────┬─────┘
                ▼
         ┌────────────┐
         │  Log Files  │ (conn.log, http.log)
         └─────┬──────┘
               │
3. ANALYSIS    ▼
        ┌────────────────────────────────────────┐
        │         Phase 2: Security Modules      │
        │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
        │  │ Network  │ │ Password │ │  API   │ │
        │  │ Detector │ │ Auditor  │ │ Scanner│ │
        │  └────┬─────┘ └────┬─────┘ └───┬────┘ │
        └───────┼────────────┼───────────┼──────┘
                │            │           │
                └────────────┼───────────┘
                             │
4. INTEGRATION               ▼
               ┌──────────────────────────┐
               │  Phase 3: FastAPI Backend │
               │  POST /alerts            │
               │         │                │
               │         ▼                │
               │  ┌──────────────────┐    │
               │  │ Correlation      │    │
               │  │ Engine (5 rules) │    │
               │  └────────┬─────────┘    │
               │           │              │
               │           ▼              │
               │  ┌──────────────────┐    │
               │  │ SQLite Database  │    │
               │  │ Alerts+Incidents │    │
               │  └──────────────────┘    │
               └──────────────────────────┘
                             │
5. OUTPUT                    ▼
               ┌──────────────────────────┐
               │  Escalated Incidents     │
               │  with Stories &          │
               │  Grouped Alert IDs      │
               └──────────────────────────┘
                             │
6. DASHBOARD (Phase 4)       ▼
               ┌──────────────────────────┐
               │  Streamlit Dashboard     │
               │  (Coming Soon)           │
               └──────────────────────────┘
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | true | Enable debug mode |
| `PYTHONUNBUFFERED` | 1 | Unbuffered output |
| `LOG_DIR` | /logs | Zeek log directory |

### Dependencies

**Phase 2 Modules:**
```
pandas>=1.5.0
numpy>=1.21.0
scikit-learn>=1.0.0
requests>=2.28.0
ldap3>=2.9.0        # Optional for LDAP
```

**Phase 3 Backend (`backend/requirements.txt`):**
```
fastapi>=0.104.0
uvicorn>=0.24.0
sqlalchemy>=2.0.0
pydantic>=2.0.0
apscheduler>=3.10.0
requests>=2.31.0
```

---

## Changelog

### [3.0.0] - 2026-02-10

#### Added — Phase 3: Integration & Correlation

**Backend API** (`backend/main.py`)
- FastAPI application with 7 REST endpoints
- CORS middleware for future dashboard integration
- Auto-correlation on every incoming alert
- Root URL redirect to Swagger docs

**Database** (`backend/database.py`)
- SQLite with SQLAlchemy ORM
- 3 tables: `alerts`, `incidents`, `incident_alerts` (many-to-many)
- WAL mode and foreign key enforcement

**Correlation Engine** (`backend/correlation_engine.py`)
- 5 correlation rules with student-friendly comments
- 30-minute alert window for recent-only analysis
- Best-match pairing strategy (prevents N×M explosion)
- Superset deduplication for multi-signal rule
- Natural-language story generation (What/Why/Action format)

**Background Scheduler** (`backend/scheduler.py`)
- APScheduler running correlation every 60 seconds as fallback

**Testing Script** (`scripts/submit_sample_alerts.py`)
- 8 sample alerts designed to trigger all 5 correlation rules
- Automatic incident and stats display after submission

### [2.0.0] - 2026-02-09

#### Added — Phase 2: Security Modules

- Network Anomaly Detector (IsolationForest + Z-score)
- Password Policy Auditor (NIST SP 800-63B compliance)
- API Security Scanner (OWASP Top 10)
- Unified JSON alert format
- CLI interfaces for all modules

### [1.0.0] - 2026-02-08

#### Added — Phase 1: Docker Lab

- Victim FastAPI with 6 vulnerabilities
- Attacker Kali Linux container
- Zeek network capture
- Docker Compose orchestration

---

## 📞 Support

For issues or questions, contact the SecuriSphere development team.

---

*SecuriSphere — BTech Final Year Project*
