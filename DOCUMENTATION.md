# 📚 SecuriSphere Technical Documentation

## Multi-Layer Integrated Cybersecurity Monitoring System

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Security Modules](#security-modules)
   - [Network Anomaly Detector](#network-anomaly-detector)
   - [Password Policy Auditor](#password-policy-auditor)
   - [API Security Scanner](#api-security-scanner)
3. [Docker Services](#docker-services)
4. [Data Flow](#data-flow)
5. [API Reference](#api-reference)
6. [Configuration](#configuration)
7. [Changelog](#changelog)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SecuriSphere                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Victim  │    │ Attacker │    │   Zeek   │    │ Analyzer │  │
│  │   App    │◄───│  (Kali)  │    │ (Capture)│    │ (Legacy) │  │
│  └────┬─────┘    └──────────┘    └────┬─────┘    └──────────┘  │
│       │                               │                          │
│       └───────────────┬───────────────┘                          │
│                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  Security Modules                           ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         ││
│  │  │   Network   │  │  Password   │  │     API     │         ││
│  │  │  Anomaly    │  │   Policy    │  │  Security   │         ││
│  │  │  Detector   │  │   Auditor   │  │   Scanner   │         ││
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         ││
│  └─────────┼────────────────┼────────────────┼─────────────────┘│
│            │                │                │                   │
│            └────────────────┼────────────────┘                   │
│                             ▼                                    │
│                    ┌─────────────────┐                          │
│                    │   JSON Alerts   │                          │
│                    └─────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Modules

### Network Anomaly Detector

**Location:** `modules/network/anomaly_detector.py`

#### Overview

Detects network traffic anomalies using machine learning (IsolationForest) with a statistical fallback (Z-score).

#### Classes

| Class | Purpose |
|-------|---------|
| `ZeekConnLogParser` | Parses Zeek conn.log TSV files |
| `FeatureExtractor` | Extracts/transforms features for ML |
| `NetworkAnomalyDetector` | Main detection engine |

#### Detection Methods

##### 1. IsolationForest (Primary)

```python
# Training: Learns "normal" traffic patterns
model = IsolationForest(
    n_estimators=100,
    contamination=0.01,  # 1% expected outliers
    random_state=42
)
model.fit(baseline_features)

# Detection: Identifies outliers
predictions = model.predict(new_features)  # -1 = anomaly
```

##### 2. Z-Score Fallback

```python
z_score = abs((total_bytes - baseline_mean) / baseline_std)

# Thresholds:
# z >= 3.0 → Anomaly (medium)
# z >= 4.0 → High severity
# z >= 5.0 → Critical severity
```

#### Features Extracted

| Feature | Description | Source |
|---------|-------------|--------|
| `duration` | Connection duration (seconds) | conn.log |
| `orig_bytes` | Bytes from originator | conn.log |
| `resp_bytes` | Bytes from responder | conn.log |
| `proto_encoded` | Protocol (tcp=0, udp=1, icmp=2) | conn.log |
| `conn_state_encoded` | Connection state (S0-OTH) | conn.log |
| `total_bytes` | orig_bytes + resp_bytes | Derived |

#### CLI Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--log-path` | Yes | - | Path to Zeek conn.log |
| `--mode` | Yes | - | `collect` or `detect` |
| `--baseline` | No | `network_baseline.pkl` | Baseline file path |
| `--output` | No | stdout | Output JSON file |
| `--contamination` | No | 0.01 | Expected outlier ratio |
| `--verbose` | No | False | Debug logging |

#### Output Alert Format

```json
{
  "module": "network",
  "type": "connection_anomaly",
  "severity": "high",
  "timestamp": "2026-02-09T16:00:00Z",
  "detection_method": "isolation_forest",
  "connection": {
    "src_ip": "10.0.0.50",
    "dst_ip": "10.0.0.10",
    "dst_port": 8000,
    "protocol": "tcp"
  },
  "features": {
    "duration": 0.5,
    "total_bytes": 1500000
  },
  "analysis": {
    "z_score": 4.2,
    "isolation_forest_score": -0.15
  }
}
```

---

### Password Policy Auditor

**Location:** `modules/password/auditor.py`

#### Overview

Audits password policies against security standards (NIST SP 800-63B, industry best practices) and generates compliance scores.

#### Classes

| Class | Purpose |
|-------|---------|
| `SecurityStandard` | Defines compliance requirements |
| `PasswordPolicy` | Stores parsed policy settings |
| `PolicyConfigParser` | Parses key=value config files |
| `PasswordPolicyAuditor` | Runs compliance checks |
| `LDAPPolicyReader` | Reads policy from OpenLDAP |

#### Security Standards

##### NIST SP 800-63B (2023)

| Setting | Value | Rationale |
|---------|-------|-----------|
| Min Length | 8 (12 recommended) | Entropy requirement |
| Complexity | Not required | Reduces user friction |
| Max Age | No rotation | Only change on breach |
| MFA | Required | Defense in depth |
| Common Passwords | Block | Prevent easy guessing |

##### Industry Best Practice

| Setting | Value | Rationale |
|---------|-------|-----------|
| Min Length | 12 | Higher entropy |
| Complexity | Required | Character type mix |
| Max Age | 90 days | Periodic rotation |
| History | 12 passwords | Prevent reuse |
| Lockout | 5 attempts | Brute force protection |

#### Scoring System

| Category | Weight | Checks |
|----------|--------|--------|
| Length | 25% | Min >= standard, max >= 64 |
| Complexity | 15% | Required character types |
| Rotation | 10% | Max age policy |
| Lockout | 20% | Threshold and duration |
| History | 10% | Password reuse prevention |
| MFA | 15% | Multi-factor required |
| Common Passwords | 5% | Dictionary blocking |

#### Grade Calculation

| Grade | Criteria |
|-------|----------|
| A | Score >= 90, no high/critical issues |
| B | Score >= 80 |
| C | Score >= 70 |
| D | Score >= 60 or high issues |
| F | Score < 60 or critical issues |

#### Config File Format

```ini
# Password Policy Configuration
minlen=12
maxlen=128
require_upper=yes
require_lower=yes
require_digit=yes
require_special=yes
max_age=90
history=12
lockout_threshold=5
lockout_duration=30
require_mfa=yes
```

#### CLI Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--config` | Yes* | - | Path to config file |
| `--ldap-uri` | Yes* | - | LDAP server URI |
| `--base-dn` | With LDAP | - | LDAP base DN |
| `--standard` | No | `nist-strict` | Standard to audit against |
| `--output` | No | stdout | Output JSON file |

*Either `--config` or `--ldap-uri` required

---

### API Security Scanner

**Location:** `modules/api/scanner.py`

#### Overview

Scans API endpoints for vulnerabilities mapped to OWASP API Security Top 10 (2023).

#### Classes

| Class | Purpose |
|-------|---------|
| `Vulnerability` | Stores discovered vulnerability |
| `ScanResult` | Aggregates scan results |
| `APISecurityScanner` | Main scanning engine |

#### OWASP API Top 10 Mapping

| ID | Name | Tests Performed |
|----|------|-----------------|
| API1:2023 | Broken Object Level Authorization | BOLA/IDOR via ID manipulation |
| API2:2023 | Broken Authentication | Unauthenticated access, weak creds |
| API4:2023 | Unrestricted Resource Consumption | 20 rapid requests (rate limiting) |
| API8:2023 | Security Misconfiguration | Missing headers, SQL injection, errors |

#### Security Tests

##### 1. Broken Authentication (API2)

```python
# Tests sensitive endpoints without auth
endpoints = ["/users/admin", "/api/users", "/config", "/debug"]
response = GET(endpoint)  # No auth headers
if response.status == 200 and has_data(response):
    report_vulnerability("API2", "Unauthenticated Access")
```

##### 2. Injection Testing (API8)

```python
# SQL injection payloads
payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "admin'--"
]
for payload in payloads:
    response = POST("/login", {"username": payload})
    if contains_sql_error(response):
        report_vulnerability("API8", "SQL Injection")
```

##### 3. Rate Limiting (API4)

```python
# Send 20 rapid requests
responses = []
for i in range(20):
    responses.append(GET("/"))

if not any(r.status == 429 for r in responses):
    report_vulnerability("API4", "No Rate Limiting")
```

##### 4. Weak Credentials (API2)

```python
weak_creds = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456")
]
for user, pwd in weak_creds:
    if login_succeeds(user, pwd):
        report_vulnerability("API2", "Weak Credentials")
```

#### CLI Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--target` | Yes | - | Target API URL |
| `--endpoints` | No | defaults | Comma-separated endpoints |
| `--output` | No | stdout | Output JSON file |
| `--timeout` | No | 10 | Request timeout (seconds) |
| `--verify-ssl` | No | False | Verify SSL certs |

#### Output Alert Format

```json
{
  "module": "api",
  "type": "security_scan",
  "severity": "critical",
  "timestamp": "2026-02-09T16:00:00Z",
  "target": "http://victim-app:8000",
  "summary": {
    "total_vulnerabilities": 5,
    "by_severity": {
      "critical": 2,
      "high": 1,
      "medium": 1,
      "low": 1
    }
  },
  "vulnerabilities": [
    {
      "owasp_id": "API2:2023",
      "owasp_name": "Broken Authentication",
      "severity": "critical",
      "title": "Unauthenticated Access to Sensitive Endpoint",
      "endpoint": "/users/admin",
      "method": "GET",
      "evidence": { ... },
      "remediation": "Implement proper authentication..."
    }
  ]
}
```

---

## Docker Services

### Service Configuration

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| victim | Custom FastAPI | 8000 | Vulnerable test API |
| attacker | Kali Linux | - | Attack simulation |
| zeek | zeek/zeek | - | Traffic capture |
| analyzer | Python | - | Legacy detection |

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

| Container | IP Address |
|-----------|------------|
| victim | 10.0.0.10 |
| attacker | 10.0.0.50 |
| zeek | 10.0.0.20 |

---

## Data Flow

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
         │  Log Files │ (conn.log, http.log)
         └─────┬──────┘
               │
3. ANALYSIS    ▼
        ┌────────────────────────────────────────┐
        │            Security Modules            │
        │  ┌──────────┐ ┌──────────┐ ┌────────┐ │
        │  │ Network  │ │ Password │ │  API   │ │
        │  │ Detector │ │ Auditor  │ │ Scanner│ │
        │  └────┬─────┘ └────┬─────┘ └───┬────┘ │
        └───────┼────────────┼───────────┼──────┘
                │            │           │
                └────────────┼───────────┘
                             ▼
4. OUTPUT           ┌────────────────┐
                    │  JSON Alerts   │
                    │  (Unified)     │
                    └────────────────┘
```

---

## API Reference

### Victim API Endpoints

#### Authentication
```http
POST /login
Content-Type: application/json

{"username": "admin", "password": "admin123"}
```

#### User Operations
```http
GET /users                    # List all users (no auth!)
GET /users/{username}         # Get user details (IDOR)
GET /api/user/{id}/profile    # Get by ID (IDOR)
```

#### Debug/Admin
```http
GET /debug/config             # Exposes secrets
GET /admin/users              # All user data
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

```
# modules/network
pandas>=1.5.0
numpy>=1.21.0
scikit-learn>=1.0.0

# modules/password
ldap3>=2.9.0  # Optional for LDAP

# modules/api
requests>=2.28.0
```

---

## Changelog

### [2.0.0] - 2026-02-09

#### Added - Phase 2 Security Modules

**Network Anomaly Detector** (`modules/network/anomaly_detector.py`)
- Zeek conn.log parsing (TSV format, comment handling)
- IsolationForest ML-based anomaly detection
- Z-score statistical fallback
- Baseline collection and persistence (pickle/JSON)
- CLI with collect/detect modes
- JSON alert output with severity levels

**Password Policy Auditor** (`modules/password/auditor.py`)
- Config file parsing (key=value format)
- NIST SP 800-63B compliance checking
- Industry best practices standard
- Compliance scoring (0-100) and grading (A-F)
- Optional LDAP/OpenLDAP integration
- CLI with config/LDAP input modes

**API Security Scanner** (`modules/api/scanner.py`)
- OWASP API Security Top 10 (2023) mapping
- Broken Authentication detection (API2)
- BOLA/IDOR testing (API1)
- Rate limiting verification (API4)
- SQL injection testing (API8)
- Security header checking
- Weak credential testing
- CLI with target/endpoint arguments

#### Improved
- Unified JSON alert format across all modules
- Comprehensive logging with `logging.basicConfig`
- Type hints throughout codebase
- Graceful error handling
- Detailed docstrings and comments

### [1.0.0] - 2026-02-08

#### Added - Phase 1 Docker Lab
- Victim FastAPI with 6 vulnerabilities
- Attacker Kali Linux container
- Zeek network capture
- Analyzer legacy service
- Docker Compose orchestration

---

## 📞 Support

For issues or questions, contact the SecuriSphere development team.

---

*SecuriSphere - BTech Final Year Project*
