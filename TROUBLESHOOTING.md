# 🔧 Troubleshooting Guide

This guide covers common issues you might encounter when running SecuriSphere and how to resolve them.

---

## 1. Dashboard Not Showing Events

**Symptom**: You run an attack, but the Dashboard "Live Feed" and "Incidents" remain empty.

**Possible Causes & Solutions**:

*   **Cause A: WebSocket Disconnection**
    *   **Check**: Look at the "System Health" widget on the Dashboard. If "Backend" is red, the WebSocket is disconnected.
    *   **Fix**: Refresh the browser page. Ensure the backend is running (`docker ps`).

*   **Cause B: Redis Connection Issue**
    *   **Check**: Run `make health`. If Redis is "Unhealthy", services can't publish events.
    *   **Fix**: Restart the stack:
        ```bash
        make restart
        ```

*   **Cause C: Monitor Logs Not Mounted**
    *   **Check**: Inspect monitor logs: `make logs-apimon`. If you see "FileNotFoundError" or similar.
    *   **Fix**: This should be fixed in the latest `docker-compose.yml`, but ensure your `api-server` and `monitors` share the `securisphere-logs` volume.

---

## 2. "SQL Injection" False Positives

**Symptom**: Normal traffic (like searching for 'laptop') triggers an SQL Injection alert.

**Cause**: The Regex patterns in `api_monitor.py` might be too aggressive or matching on benign keywords in certain contexts.

**Fix**:
1.  We have tuned the `rule_critical_exploit_attempt` to require **2+ events** generally, unless it is a specific high-confidence pattern.
2.  If this persists, verify you are running the latest code where we refined the Regex patterns.
3.  Run `make attack-benign` to verify the fix.

---

## 3. Simulator Fails with "Connection Refused"

**Symptom**: Running `make attack-killchain` prints connection errors immediately.

**Cause**: The target services (`api-server`, `auth-service`) are not fully ready yet.

**Fix**:
1.  Wait 30 seconds after `make start` before running attacks.
2.  Run `make health` to confirm all services report "healthy".

---

## 4. Database Setup Errors

**Symptom**: `make setup` fails or the API logs show "no such table: users".

**Cause**: The `init_db.sh` script failed to run or the volume is corrupted.

**Fix**:
1.  Full reset (Warning: deletes data):
    ```bash
    make reset
    make setup
    make start
    ```

---

## 5. Docker Port Conflicts

**Symptom**: Error `Bind for 0.0.0.0:xxxx failed: port is already allocated`.

**Cause**: Another service (Postgres, Redis, or another web app) is using one of the project ports (3000, 5000, 5432, 6379, 8000).

**Fix**:
1.  Stop other services on your machine.
2.  Or, modify `docker-compose.yml` to map to different host ports (e.g., `8001:8000`).

---

## 6. Logs & Debugging

If you're stuck, the best way to debug is to look at the logs for the specific component:

- **Backend/Dashboard Issues**: `make logs-backend`
- **Detection Issues**: `make logs-engine`
- **Target API Issues**: `make logs-api`

To inspect the raw event bus:
```bash
# Watch all security events in real-time
make monitor-events
```
