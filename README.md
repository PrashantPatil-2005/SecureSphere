# SecuriSphere
> A multi-layer cybersecurity monitoring and threat correlation framework for containerized environments.

## Architecture

```ascii
+----------------+      +----------------+      +----------------+
|  Monitor Layer | ---> |  Event Bus     | ---> |  Engine Layer  |
| (Net, API, Auth)|     | (Redis Pub/Sub)|      | (Correlation)  |
+----------------+      +----------------+      +----------------+
                                                        |
                                                        v
+----------------+      +----------------+      +----------------+
|   Dashboard    | <--- |    Database    | <--- |   Backend      |
|    (React)     |      |  (PostgreSQL)  |      |    (API)       |
+----------------+      +----------------+      +----------------+
```

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Git](https://git-scm.com/downloads)

## Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/your/securisphere.git
   cd securisphere
   ```

2. **Setup the environment**
   ```bash
   make setup
   ```

3. **Start the application**
   ```bash
   make start
   ```

## Phase 1 Status

Phase 1 completes the project foundation:
- [x] Project structure
- [x] Docker Compose with Redis & PostgreSQL
- [x] Database Schema
- [x] Basic Scripts & Makefile

**To verify Phase 1:**
Run `make health` to check if Redis and PostgreSQL are up and running correctly.

## Available Commands

| Command | Description |
|---------|-------------|
| `make setup` | Run initial setup (create .env, dirs, start db) |
| `make start` | Start all services |
| `make stop` | Stop all services |
| `make reset` | Stop services and remove all data volumes |
| `make health` | Run health checks |
| `make logs` | View logs from all containers |
| `make shell-db` | Access PostgreSQL shell |
| `make shell-redis` | Access Redis shell |
| `make test-api` | Run curl tests for API Server |
| `make test-auth` | Run curl tests for Auth Service |
| `make test-phase2` | Run full pytest suite for Phase 2 |
| `make build-frontend` | Build the React dashboard |
| `make start-frontend` | Start the dashboard service |
| `make open-dashboard` | Open dashboard in browser |

## Phase 2: Target Services

### API Server (Port 5000)
Intentionally vulnerable Flask API simulating an e-commerce backend.
- **GET /api/products/search?q=**: Vulnerable to SQL Injection
- **GET /api/files?name=**: Vulnerable to Path Traversal
- **GET /api/admin/config**: Vulnerable to Broken Access Control (No Auth)
- **GET /api/admin/users/export**: Vulnerable to Sensitive Data Exposure

### Auth Service (Port 5001)
Authentication service tracking login attempts.
- **POST /auth/login**: Login handler
- **Lockout Mechanism**: Account locked after 5 failed attempts
- **POST /auth/reset/<username>**: Reset locked account

## Phase 5: Dashboard (Port 3000)

### Tabs
- **Dashboard**: Overview with metrics, layer activity, timeline chart, recent events
- **Events**: Filterable event list with detail modal
- **Incidents**: Correlated incidents (populated after Phase 6)
- **Risk Scores**: Entity risk scores (populated after Phase 6)
- **System**: System status for all components

### Features
- Real-time updates via WebSocket
- Dark cybersecurity theme
- Responsive design
- Event filtering by layer and severity
- Click events for full detail view
- Connection status indicator

### Access
Open [http://localhost:3000](http://localhost:3000) in your browser.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_PORT` | Port for Redis | 6379 |
| `POSTGRES_PORT` | Port for PostgreSQL | 5432 |
| `POSTGRES_DB` | Database name | securisphere_db |
| `MONITOR_INTERFACE` | Network interface to monitor | eth0 |
| `FRONTEND_PORT` | Port for Dashboard | 3000 |
| `REACT_APP_BACKEND_URL` | Connect URL for Frontend | http://localhost:8000 |

See `.env.example` for all available configuration options.

## Phase 6: Correlation Engine (Port 5070)

The "Brain" of SecuriSphere. It consumes normalized events from Redis, applies correlation rules, and publishes actionable incidents.

### Correlation Rules
| Rule | Pattern | Severity |
|------|---------|----------|
| **Recon → Exploit** | Port scan + SQLi/PathTraversal from same IP | Critical |
| **Credential Compromise** | Brute force + successful login | Critical |
| **Full Kill Chain** | Attacks on Network + API + Auth layers from same IP | Critical |
| **Automated Tool** | API abuse + Auth attack combined | High |
| **Distributed Attack** | 3+ IPs targeting same account | Critical |
| **Data Exfiltration** | Exploitation + sensitive access | High |
| **Persistent Threat** | 10+ events over 5+ minutes | High |

### Risk Scoring
- **Points**: Low (+10), Medium (+25), High (+50), Critical (+100)
- **Bonus**: ×1.5 for cross-layer attacks
- **Decay**: -5 points every minute
- **Levels**: Normal (0-30), Suspicious (31-70), Threatening (71-150), Critical (151+)

### Health & Stats
- Health: `GET http://localhost:5070/engine/health`
- Stats: `GET http://localhost:5070/engine/stats`
- Risk Scores: `GET http://localhost:5070/engine/risk-scores`

## Phase 7: Attack Simulator

### Available Scenarios
| # | Scenario | Description | Expected Correlations |
|---|----------|-------------|----------------------|
| 1 | Full Kill Chain | Multi-stage: recon→exploit→creds→exfil | Kill Chain, Recon→Exploit, API+Auth |
| 2 | API Abuse | Enumeration, fuzzing, SQLi, data access | Data Exfiltration, Persistent Threat |
| 3 | Credential Attack | Brute force, stuffing, lockout DoS | Credential Compromise, Lockout Storm |
| 4 | Benign Traffic | Normal usage patterns | None (false positive test) |
| 5 | Stealth Attack | Low-and-slow methodology | Persistent Threat (delayed) |

### Running Attacks
```bash
# Individual scenarios
make attack-killchain
make attack-api
make attack-creds
make attack-benign
make attack-stealth

# All scenarios
make attack-all

# Demo mode (slow, for presentation)
make demo

# Interactive menu
make run-demo
```

## Phase 8: Integration Testing & Evaluation

### Running Tests
```bash
# Integration tests only
make test-integration

# Full evaluation (all scenarios + metrics)
make evaluate

# Complete evaluation suite (tests + evaluation)
make run-evaluation
```

## Database Schema

- **security_events**: Raw security events from all monitors
- **correlated_incidents**: High-level incidents generated by correlation engine
- **risk_scores**: Dynamic risk scores for entities (IPs, users)
- **baseline_metrics**: Statistical baselines for anomaly detection

## Troubleshooting

- **Database connection failed**: Ensure `make setup` ran successfully and containers are healthy.
- **Redis connection failed**: Check `make logs-redis` for errors.
- **Port conflicts**: Modify ports in `.env` if 5432 or 6379 are taken.
- **Dashboard not loading**: Ensure backend is running (`make health`) and port 3000 is open.

## Project Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation & Infrastructure | ✅ |
| 2 | Target Services (API, Auth) | ✅ |
| 3 | Security Monitors | ✅ |
| 4 | Event Normalization | ✅ |
| 5 | Backend API | ✅ |
| 6 | Frontend Dashboard | ✅ |
| 7 | Correlation Engine | ⬜ |
| 8 | Risk Scoring | ⬜ |
| 9 | Attack Simulation | ⬜ |
| 10 | Integration Testing | ⬜ |
