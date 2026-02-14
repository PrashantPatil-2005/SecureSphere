# SecuriSphere: Phase 3 - Monitoring Agents & Detection Logic

## 🚀 Project Overview

**Phase 3** of SecuriSphere introduces the **Detection Layer**. We have implemented three specialized monitoring agents that analyze traffic and logs in real-time to identify security threats. These agents normalize their findings into a unified event schema and publish them to a central Redis channel (`security_events`), paving the way for the Correlation Engine (Phase 4).

**Current Status:**
- **Phase 3 (Monitoring Agents):** Completed.
    - **Network Monitor:** Packet-level analysis.
    - **API Monitor:** Application-layer log analysis.
    - **Auth Monitor:** Identity and access analysis.

---

## 🛠️ Architecture & Data Flow

The monitoring architecture is designed to be modular and event-driven:

1.  **Data Sources:**
    - **Network Traffic:** Raw packets captured via `AF_PACKET` (Scapy).
    - **API Logs:** JSON logs published to Redis channel `api_logs`.
    - **Auth Events:** JSON events published to Redis channel `auth_events`.

2.  **Monitoring Agents:**
    - Each agent runs in a separate Docker container.
    - Agents apply detection logic (signatures, anomalies, heuristics).
    - Agents **normalize** alerts into a standard JSON schema.

3.  **Output:**
    - All detected threats are published to the `security_events` Redis channel.
    - This allows for a single downstream consumer (Correlation Engine) to ingest all alert types.

---

## 🛡️ Monitoring Agents

### 1. Network Monitor (`network-monitor`)
**Role:** Passive Network Traffic Analysis (NTA).
**Technology:** Python, Scapy, Redis.
**Privileges:** Requires `NET_RAW` and `NET_ADMIN` capabilities.

**Detections:**
- **Port Scan:** Detects a single source IP connecting to >15 unique ports within a 30-second window.
- **Traffic Anomaly:** Learns a baseline of traffic volume (packets/sec) during the first 5 minutes. alerting on spikes >3 standard deviations above the mean.
- **DNS Tunneling:** Analyzes DNS queries for high entropy (Shannon entropy > 4.5) and long labels, indicative of data exfiltration or C2 communication.

### 2. API Monitor (`api-monitor`)
**Role:** Web Application Firewall (WAF) / Log Analysis.
**Input:** Subscribes to `api_logs` channel from API Server.
**Technology:** Python, Flask (for health), Redis.

**Detections:**
- **SQL Injection (SQLi):** Identifies suspicious patterns in query parameters (e.g., `' OR '1'='1`, `UNION SELECT`, `--`).
- **Path Traversal:** Detects attempts to access system files (e.g., `../`, `/etc/passwd`, `C:\Windows`).
- **Rate Abuse:** Tracks request rates per IP.
    - **High Rate:** >100 requests per minute.
    - **Enumeration:** Accessing >20 unique endpoints per minute.
- **Sensitive Access:** Alerts on unauthorized access attempts to administrative paths (`/api/admin/*`).

### 3. Auth Monitor (`auth-monitor`)
**Role:** Identity Threat Detection and Response (ITDR).
**Input:** Subscribes to `auth_events` channel from Auth Service.
**Technology:** Python, Flask (for health), Redis.

**Detections:**
- **Brute Force:** Detects >5 failed login attempts for a single username within 2 minutes.
- **Credential Stuffing:** Detects a single IP attempting to login with >5 different usernames within 5 minutes.
- **Suspicious Login:** Flags a successful login that was immediately preceded by multiple failed attempts (potential account takeover).
- **Lockout Storm:** Detects a high volume of `account_lockout` events (>3) from a single IP, indicating a broad spray attack.

---

## 📝 Unified Event Schema

All monitors publish alerts in the following JSON format:

```json
{
  "event_id": "uuid-v4",
  "timestamp": "ISO8601-UTC",
  "source_layer": "network|api|auth",
  "source_monitor": "monitor_name_v1",
  "event_category": "reconnaissance|exploitation|brute_force|anomaly",
  "event_type": "specific_detection_name",
  "severity": {
    "level": "low|medium|high|critical",
    "score": 0-100
  },
  "source_entity": { "ip": "1.2.3.4", ... },
  "target_entity": { "ip": "10.0.0.1", "port": 80, "username": "admin" },
  "detection_details": { "evidence": "...", "confidence": 0.9 },
  "mitre_technique": "T1xxx"
}
```

---

## 🔍 Verification & Testing

The system includes automated scripts to verify detection capabilities.

### 1. Integration Tests
Run a full simulation of attacks against the running environment:
```bash
make test-monitors
```
**This script simulates:**
- SQL Injection & Path Traversal attacks.
- Brute Force & Credential Stuffing.
- Verifies that specific alerts are generated in Redis.

### 2. Automated Test Suite
Run the Pytest suite for granular assertions:
```bash
make test-phase3
```
**Checks:**
- Monitor health endpoints.
- Correct event schema formatting.
- Accurate detection of specific attack patterns.

### 3. Manual Verification
You can inspect live events by subscribing to the Redis channel:
```bash
make monitor-events
```
Then, manually trigger an attack (e.g., `curl "http://localhost:5000/api/admin/config"`) and watch for the alert.

---

## ⚙️ Management

**Start Phase 3 Services:**
```bash
make start-monitors
```

**Build Services:**
```bash
make build-monitors
```

**View Logs:**
```bash
make logs-netmon
make logs-apimon
make logs-authmon
```
