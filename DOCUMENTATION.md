# 📘 SecuriSphere - Technical Documentation

> **Last Updated:** 2026-02-08  
> **Version:** 1.0.0  
> **Status:** Phase 2 Complete

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Components](#components)
4. [Phase Progress](#phase-progress)
5. [API Reference](#api-reference)
6. [Data Flow](#data-flow)
7. [Configuration](#configuration)
8. [Changelog](#changelog)

---

## 🎯 Project Overview

**SecuriSphere** is a Multi-Layer Integrated Cybersecurity Monitoring System designed for enterprise security teams. It correlates multiple security signals into a unified platform with prioritized alerts.

### Core Capabilities

| Layer | Function | Status |
|-------|----------|--------|
| Network Monitoring | Zeek-based traffic analysis & anomaly detection | ✅ Complete |
| Password Auditing | Policy compliance checking | 🔲 Planned |
| API Security | Vulnerability scanning | 🔲 Planned |
| Correlation Engine | Cross-layer alert correlation | 🔲 Planned |
| Dashboard | Real-time visualization | 🔲 Planned |

### Tech Stack

- **Backend:** Python 3.10+, FastAPI
- **Analysis:** pandas, scikit-learn, numpy
- **Network:** Zeek (traffic metadata capture)
- **Dashboard:** Streamlit (planned)
- **Database:** SQLite/PostgreSQL + TimescaleDB (planned)
- **Infrastructure:** Docker Compose

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network (labnet)                   │
│                         172.28.0.0/16                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   VICTIM     │    │   ATTACKER   │    │     ZEEK     │       │
│  │  172.28.0.10 │◄───│  172.28.0.20 │    │  172.28.0.30 │       │
│  │              │    │              │    │              │       │
│  │  FastAPI     │    │  Kali Linux  │    │  Traffic     │       │
│  │  Port 8000   │    │  nmap/hydra  │    │  Capture     │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
│         │                                        │               │
│         │              HTTP Traffic              │               │
│         └────────────────────────────────────────┘               │
│                              │                                   │
│                              ▼                                   │
│                    ┌──────────────────┐                         │
│                    │    ANALYZER      │                         │
│                    │   172.28.0.40    │                         │
│                    │                  │                         │
│                    │  Log Parsing     │                         │
│                    │  Baseline Build  │                         │
│                    │  Anomaly Detect  │                         │
│                    └──────────────────┘                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Container Details

| Service | IP Address | Port | Image | Purpose |
|---------|------------|------|-------|---------|
| victim | 172.28.0.10 | 8000 | Custom (Python 3.10) | Vulnerable API |
| attacker | 172.28.0.20 | - | kalilinux/kali-rolling | Attack simulation |
| zeek | 172.28.0.30 | - | blacktop/zeek | Traffic capture |
| analyzer | 172.28.0.40 | - | Custom (Python 3.10) | Anomaly detection |

---

## 🧩 Components

### 1. Victim Service (`/victim`)

An intentionally vulnerable FastAPI application for security testing.

#### Vulnerabilities Implemented

| ID | Vulnerability | Endpoint | OWASP Category |
|----|--------------|----------|----------------|
| V1 | Broken Authentication | `/users/{username}` | A01:2021 |
| V2 | Weak Password Policy | `/login` | A07:2021 |
| V3 | Hardcoded Credentials | `/login` (backdoor) | A07:2021 |
| V4 | IDOR | `/api/user/{id}/profile` | A01:2021 |
| V5 | Sensitive Data Exposure | `/debug/config` | A02:2021 |
| V6 | SQL Injection (simulated) | `/search?q=` | A03:2021 |

#### Files
```
victim/
├── Dockerfile           # Python 3.10-slim base
├── requirements.txt     # FastAPI, uvicorn, passlib
└── app/
    └── main.py          # Vulnerable API endpoints
```

#### Test Credentials
| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| john_doe | password | user |
| jane_smith | 123456 | user |
| guest | guest | guest |
| backdoor | letmein | superadmin |

---

### 2. Attacker Service (`/attacker`)

Kali Linux container with pre-installed security tools.

#### Available Tools
- **nmap** - Network scanning
- **hydra** - Brute force attacks
- **nikto** - Web vulnerability scanner
- **dirb** - Directory enumeration
- **curl/wget** - HTTP testing

#### Scripts
```
attacker/
├── scripts/
│   ├── scan_victim.sh    # Reconnaissance script
│   └── brute_force.sh    # Password attack simulation
└── wordlists/
    └── common_passwords.txt
```

---

### 3. Zeek Service (`/zeek`)

Network traffic analyzer capturing metadata in JSON format.

#### Log Files Generated
| Log | Description | Key Fields |
|-----|-------------|------------|
| `conn.log` | All connections | ts, src/dst IP, port, duration, bytes |
| `http.log` | HTTP requests | method, URI, status_code, user_agent |
| `dns.log` | DNS queries | query, qtype, answers |
| `ssl.log` | TLS connections | cert info, cipher |

#### Configuration
```
zeek/
└── config/
    └── local.zeek    # JSON logging, custom event handlers
```

---

### 4. Analyzer Service (`/analyzer`)

Python-based anomaly detection engine.

#### Module Structure
```
analyzer/
├── Dockerfile
├── requirements.txt
└── src/
    ├── __init__.py
    ├── zeek_parser.py   # Log file parsing
    ├── baseline.py      # Traffic baseline builder
    ├── detector.py      # Anomaly detection engine
    └── cli.py           # Command-line interface
```

#### Detection Algorithms

##### Statistical (Z-Score) Detection
```python
z_score = (observed_value - baseline_mean) / baseline_std

# Thresholds:
# z >= 3.0 → Anomaly detected
# z >= 4.0 → High severity
# z >= 5.0 → Critical severity
```

##### Anomaly Types Detected

| Type | Detection Method | Severity |
|------|-----------------|----------|
| `high_connection_rate` | Z-score on conn/min | Based on z-score |
| `port_scan` | Unique ports per IP ≥ 10 | HIGH |
| `brute_force` | Failed logins ≥ 5 | HIGH |
| `endpoint_scan` | Unique URIs per IP ≥ 10 | MEDIUM |
| `sql_injection_attempt` | Pattern matching | CRITICAL |
| `long_duration` | Duration > p99 | Based on z-score |
| `high_bytes_transfer` | Bytes > p99 | Based on z-score |
| `error_spike` | Error rate > 30% | MEDIUM |

#### CLI Commands

```bash
# Build network baseline
python -m src.cli baseline

# Run anomaly detection
python -m src.cli detect

# Real-time monitoring
python -m src.cli watch --interval 30

# View report
python -m src.cli report
```

---

## 📊 Phase Progress

### Phase 1: Docker Lab Environment ✅
- [x] docker-compose.yml with 4 services
- [x] Victim FastAPI with 6 vulnerabilities
- [x] Attacker Kali container with tools
- [x] Zeek network capture
- [x] README documentation

### Phase 2: Zeek Anomaly Detection ✅
- [x] Zeek log parser (JSON/TSV)
- [x] Baseline statistics builder
- [x] Z-score anomaly detection
- [x] Port/endpoint scan detection
- [x] Brute force detection
- [x] SQL injection pattern detection
- [x] Rich CLI interface
- [x] Analyzer Docker service

### Phase 3: Password Policy Auditor 🔲
- [ ] Password policy rules engine
- [ ] LDAP/AD integration (optional)
- [ ] Compliance report generator

### Phase 4: API Security Scanner 🔲
- [ ] Endpoint discovery
- [ ] OWASP Top 10 vulnerability checks
- [ ] Scan report generator

### Phase 5: Correlation Engine 🔲
- [ ] Cross-layer correlation rules
- [ ] Alert prioritization algorithm
- [ ] Unified alert storage (PostgreSQL)

### Phase 6: Streamlit Dashboard 🔲
- [ ] Real-time metrics display
- [ ] Alert visualization
- [ ] Historical analysis

---

## 🔌 API Reference

### Victim API Endpoints

#### Authentication
```http
POST /login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

#### User Operations
```http
GET /users                    # List all users
GET /users/{username}         # Get user details (IDOR!)
GET /api/user/{id}/profile    # Get by ID (IDOR!)
POST /change-password         # Change password (no auth!)
```

#### Debug/Admin (Should be protected!)
```http
GET /debug/config             # Exposes secrets
GET /admin/users              # All user data + hashes
```

#### Search
```http
GET /search?q=admin           # Normal search
GET /search?q=admin' OR '1'='1  # SQL injection test
```

---

## 🔄 Data Flow

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
                │
                ▼
         ┌────────────┐
         │  Log Files │
         │ (conn.log) │
         │ (http.log) │
         └─────┬──────┘
               │
3. ANALYSIS    ▼
        ┌────────────┐
        │  Analyzer  │
        ├────────────┤
        │ 1. Parse   │
        │ 2. Baseline│
        │ 3. Detect  │
        └─────┬──────┘
              │
              ▼
4. OUTPUT  ┌────────────┐
           │  Anomaly   │
           │   Report   │
           │  (JSON)    │
           └────────────┘
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | true | Enable debug mode |
| `PYTHONUNBUFFERED` | 1 | Unbuffered Python output |
| `LOG_DIR` | /logs | Zeek log directory |
| `OUTPUT_DIR` | /analyzer/output | Analyzer output directory |

### Docker Volumes

| Volume | Mount Point | Purpose |
|--------|-------------|---------|
| `zeek_logs` | /logs | Zeek log file storage |
| `victim_data` | /data | Victim app data |
| `analyzer_output` | /analyzer/output | Reports and baselines |

---

## 📝 Changelog

### [1.0.0] - 2026-02-08

#### Added
- **Phase 1:** Complete Docker lab environment
  - Victim FastAPI with 6 intentional vulnerabilities
  - Attacker Kali Linux container
  - Zeek network traffic capture
  - Bridge network (labnet) with static IPs

- **Phase 2:** Zeek Anomaly Detection Module
  - `zeek_parser.py` - JSON/TSV log parsing
  - `baseline.py` - Traffic baseline statistics
  - `detector.py` - Multi-method anomaly detection
  - `cli.py` - Rich command-line interface
  - Analyzer Docker service with auto-watch mode

#### Detection Features
- Z-score statistical analysis
- Port scan detection (≥10 ports)
- Brute force detection (≥5 failed logins)
- Endpoint enumeration detection
- SQL injection pattern matching
- Connection rate anomalies
- Data transfer anomalies

---

## 🔗 Quick Links

- [README.md](./README.md) - Getting started guide
- [docker-compose.yml](./docker-compose.yml) - Container orchestration
- [victim/app/main.py](./victim/app/main.py) - Vulnerable API code
- [analyzer/src/detector.py](./analyzer/src/detector.py) - Detection engine

---

## 📞 Support

For issues or questions, contact the SecuriSphere development team.

---

*This documentation is maintained as part of the SecuriSphere BTech Final Year Project.*
