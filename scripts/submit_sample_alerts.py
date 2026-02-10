#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Phase 3: Sample Alert Submitter
# =============================================================================
"""
Pushes pre-crafted sample alerts to the Phase 3 backend to test
the correlation engine. The alerts are designed to trigger ALL 5
correlation rules.

Usage:
    # Make sure the backend is running first:
    #   python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
    
    # Then run this script:
    #   python scripts/submit_sample_alerts.py
    
    # With custom URL:
    #   python scripts/submit_sample_alerts.py --url http://localhost:9000
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta

import requests

# =============================================================================
# Configuration
# =============================================================================
DEFAULT_URL = "http://localhost:8000"
ASSET = "victim-app:8000"

# Base timestamp — all alerts are relative to this time
BASE_TIME = datetime.utcnow()


def ts(minutes_offset: int = 0) -> str:
    """Generate ISO timestamp offset from BASE_TIME."""
    return (BASE_TIME + timedelta(minutes=minutes_offset)).isoformat()


# =============================================================================
# Sample Alerts — Designed to Trigger All 5 Correlation Rules
# =============================================================================
SAMPLE_ALERTS = [
    # =========================================================================
    # Alert 1: Network anomaly — unusual traffic spike
    # (Used by Rules 1, 2, 3, 4, 5)
    # =========================================================================
    {
        "module": "network",
        "type": "connection_anomaly",
        "severity": "high",
        "timestamp": ts(0),
        "asset": ASSET,
        "details": {
            "detection_method": "isolation_forest",
            "connection": {
                "src_ip": "192.168.1.100",
                "dst_ip": "172.28.0.10",
                "dst_port": 8000,
                "protocol": "tcp",
                "conn_state": "S0"
            },
            "features": {
                "duration": 0.001,
                "orig_bytes": 54000,
                "resp_bytes": 0,
                "total_bytes": 54000
            },
            "analysis": {
                "z_score": 4.5,
                "baseline_mean": 1200.0,
                "baseline_std": 800.0,
                "isolation_forest_score": -0.85
            }
        }
    },

    # =========================================================================
    # Alert 2: Password audit — weak policy detected
    # (Triggers Rule 1: Credential Abuse with Alert 1)
    # (Triggers Rule 5: Identity Compromise with Alert 1)
    # =========================================================================
    {
        "module": "password",
        "type": "policy_audit",
        "severity": "high",
        "timestamp": ts(2),  # 2 minutes after Alert 1
        "asset": ASSET,
        "details": {
            "summary": {
                "score": 25,
                "grade": "D",
                "compliant": False,
                "standard": "NIST SP 800-63B",
                "issues_count": 8
            },
            "issues_by_severity": {
                "critical": [
                    {"title": "Minimum length too short", "current_value": 6, "recommended_value": 12},
                    {"title": "No MFA requirement", "current_value": False, "recommended_value": True}
                ],
                "high": [
                    {"title": "Common passwords allowed", "current_value": True, "recommended_value": False}
                ]
            },
            "recommendations": [
                "Increase minimum password length to 12 characters",
                "Enable multi-factor authentication",
                "Block common/breached passwords"
            ]
        }
    },

    # =========================================================================
    # Alert 3: API scan — broken authentication found
    # (Triggers Rule 2: Recon + Exploitation with Alert 1)
    # (Triggers Rule 4: API Takeover with Alert 1)
    # =========================================================================
    {
        "module": "api",
        "type": "security_scan",
        "severity": "critical",
        "timestamp": ts(3),  # 3 minutes after Alert 1
        "asset": ASSET,
        "details": {
            "summary": {
                "total_vulnerabilities": 5,
                "by_severity": {
                    "critical": 2,
                    "high": 2,
                    "medium": 1
                }
            },
            "vulnerabilities": [
                {
                    "owasp_id": "API2:2023",
                    "owasp_name": "Broken Authentication",
                    "severity": "critical",
                    "title": "Default credentials accepted",
                    "endpoint": "/login",
                    "method": "POST",
                    "evidence": {"username": "admin", "password": "admin123", "status_code": 200}
                },
                {
                    "owasp_id": "API1:2023",
                    "owasp_name": "Broken Object Level Authorization",
                    "severity": "critical",
                    "title": "IDOR on user endpoint",
                    "endpoint": "/api/users/1",
                    "method": "GET",
                    "evidence": {"accessed_other_user": True}
                },
                {
                    "owasp_id": "API8:2023",
                    "owasp_name": "Security Misconfiguration",
                    "severity": "high",
                    "title": "Debug mode enabled in production",
                    "endpoint": "/docs",
                    "method": "GET",
                    "evidence": {"debug_endpoints_exposed": True}
                }
            ]
        }
    },

    # =========================================================================
    # Alert 4: Network — port scan detected (medium)
    # (Contributes to Rule 3: Multi-Signal Attack with Alerts 1, 2, 3)
    # =========================================================================
    {
        "module": "network",
        "type": "connection_anomaly",
        "severity": "medium",
        "timestamp": ts(5),  # 5 minutes after Alert 1
        "asset": ASSET,
        "details": {
            "detection_method": "statistical_zscore",
            "connection": {
                "src_ip": "192.168.1.100",
                "dst_ip": "172.28.0.10",
                "dst_port": 22,
                "protocol": "tcp",
                "conn_state": "REJ"
            },
            "features": {
                "duration": 0.0,
                "orig_bytes": 60,
                "resp_bytes": 0,
                "total_bytes": 60
            },
            "analysis": {
                "z_score": 3.2,
                "baseline_mean": 1200.0,
                "baseline_std": 800.0
            }
        }
    },

    # =========================================================================
    # Alert 5: Network — SSH brute force attempt
    # (Contributes to Rule 3: Multi-Signal — 3+ medium+ alerts in window)
    # =========================================================================
    {
        "module": "network",
        "type": "connection_anomaly",
        "severity": "medium",
        "timestamp": ts(7),  # 7 minutes after Alert 1
        "asset": ASSET,
        "details": {
            "detection_method": "isolation_forest",
            "connection": {
                "src_ip": "192.168.1.100",
                "dst_ip": "172.28.0.10",
                "dst_port": 8000,
                "protocol": "tcp",
                "conn_state": "S0"
            },
            "features": {
                "duration": 120.5,
                "orig_bytes": 250000,
                "resp_bytes": 15000,
                "total_bytes": 265000
            },
            "analysis": {
                "z_score": 5.1,
                "baseline_mean": 1200.0,
                "baseline_std": 800.0,
                "isolation_forest_score": -0.92
            }
        }
    },

    # =========================================================================
    # Alert 6: Password — different asset (for variety)
    # =========================================================================
    {
        "module": "password",
        "type": "policy_audit",
        "severity": "medium",
        "timestamp": ts(8),
        "asset": ASSET,
        "details": {
            "summary": {
                "score": 55,
                "grade": "C",
                "compliant": False,
                "standard": "NIST SP 800-63B",
                "issues_count": 4
            },
            "issues_by_severity": {
                "high": [
                    {"title": "Password history not enforced", "current_value": 0, "recommended_value": 5}
                ],
                "medium": [
                    {"title": "No account lockout policy", "current_value": 0, "recommended_value": 10}
                ]
            }
        }
    },

    # =========================================================================
    # Alert 7: API — rate limiting missing  
    # =========================================================================
    {
        "module": "api",
        "type": "security_scan",
        "severity": "high",
        "timestamp": ts(9),
        "asset": ASSET,
        "details": {
            "summary": {
                "total_vulnerabilities": 2,
                "by_severity": {"high": 1, "medium": 1}
            },
            "vulnerabilities": [
                {
                    "owasp_id": "API4:2023",
                    "owasp_name": "Unrestricted Resource Consumption",
                    "severity": "high",
                    "title": "No rate limiting on login endpoint",
                    "endpoint": "/login",
                    "method": "POST",
                    "evidence": {"requests_sent": 100, "all_accepted": True}
                }
            ]
        }
    },

    # =========================================================================
    # Alert 8: Network — new IP login (simulated for Rule 5)
    # =========================================================================
    {
        "module": "network",
        "type": "new_ip_login",
        "severity": "medium",
        "timestamp": ts(10),
        "asset": ASSET,
        "details": {
            "detection_method": "ip_reputation",
            "connection": {
                "src_ip": "203.0.113.42",
                "dst_ip": "172.28.0.10",
                "dst_port": 8000,
                "protocol": "tcp",
                "conn_state": "SF"
            },
            "analysis": {
                "new_ip": True,
                "geo_location": "Unknown",
                "previous_ips": ["192.168.1.100", "192.168.1.101"]
            }
        }
    },
]


# =============================================================================
# Submit Alerts
# =============================================================================
def submit_alerts(base_url: str, alerts: list) -> None:
    """Submit all sample alerts to the backend."""
    endpoint = f"{base_url}/alerts"
    
    print("=" * 70)
    print("  SecuriSphere — Phase 3: Sample Alert Submitter")
    print("=" * 70)
    print(f"  Target: {endpoint}")
    print(f"  Alerts to submit: {len(alerts)}")
    print("=" * 70)
    print()

    success_count = 0
    fail_count = 0

    for i, alert in enumerate(alerts, 1):
        try:
            print(f"  [{i}/{len(alerts)}] Submitting: "
                  f"module={alert['module']:<10} "
                  f"type={alert['type']:<25} "
                  f"severity={alert['severity']:<10} ", end="")

            resp = requests.post(endpoint, json=alert, timeout=10)
            resp.raise_for_status()

            data = resp.json()
            print(f"✅ → alert #{data['id']}")
            success_count += 1

            # Small delay to let correlation engine process
            time.sleep(0.3)

        except requests.exceptions.ConnectionError:
            print(f"❌ Connection failed!")
            print(f"\n  ⚠️  Is the backend running? Start it with:")
            print(f"      python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000\n")
            fail_count += 1
            if i == 1:
                print("  Aborting — backend not reachable.")
                sys.exit(1)

        except requests.exceptions.HTTPError as e:
            print(f"❌ HTTP {resp.status_code}: {resp.text}")
            fail_count += 1

        except Exception as e:
            print(f"❌ Error: {e}")
            fail_count += 1

    # =========================================================================
    # Summary
    # =========================================================================
    print()
    print("=" * 70)
    print(f"  Results: {success_count} succeeded, {fail_count} failed")
    print("=" * 70)
    print()

    # Fetch and display incidents
    if success_count > 0:
        print("  Fetching correlated incidents...")
        print()
        try:
            resp = requests.get(f"{base_url}/incidents", timeout=10)
            resp.raise_for_status()
            incidents = resp.json()

            if incidents:
                print(f"  🔔 {len(incidents)} Correlated Incident(s) Found:")
                print("  " + "-" * 66)
                for inc in incidents:
                    print(f"\n  📋 Incident: {inc['incident_id'][:8]}...")
                    print(f"     Rule:     {inc['rule_name']}")
                    print(f"     Severity: {inc['severity'].upper()}")
                    print(f"     Alerts:   {inc['alert_ids']}")
                    print(f"     Story:    {inc['story'][:120]}...")
                    print()
            else:
                print("  ℹ️  No incidents yet — try submitting more alerts.")

            # Also show stats
            resp = requests.get(f"{base_url}/stats", timeout=10)
            if resp.ok:
                stats = resp.json()
                print("  " + "-" * 66)
                print(f"  📊 Dashboard Stats:")
                print(f"     Total Alerts:    {stats['total_alerts']}")
                print(f"     Total Incidents: {stats['total_incidents']}")
                print(f"     By Module:       {json.dumps(stats['alerts_by_module'])}")
                print(f"     By Severity:     {json.dumps(stats['alerts_by_severity'])}")

        except Exception as e:
            print(f"  ⚠️  Could not fetch incidents: {e}")

    print()
    print("=" * 70)
    print("  ✅ Done! Check the API at:")
    print(f"     GET {base_url}/alerts")
    print(f"     GET {base_url}/incidents")
    print(f"     GET {base_url}/stats")
    print(f"     GET {base_url}/docs   (Swagger UI)")
    print("=" * 70)


# =============================================================================
# Main
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Submit sample alerts to SecuriSphere Phase 3 backend"
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"Backend base URL (default: {DEFAULT_URL})"
    )
    args = parser.parse_args()

    submit_alerts(args.url, SAMPLE_ALERTS)
