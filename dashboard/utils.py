#!/usr/bin/env python3
# =============================================================================
# SecuriSphere — Phase 4: Data Utilities & Helpers
# =============================================================================
"""
This module handles ALL data fetching for the Streamlit dashboard.

Key responsibilities:
    1. Fetch alerts / incidents / stats from the FastAPI backend (http://localhost:8000)
    2. Provide hardcoded SAMPLE DATA as fallback when backend is down
    3. Inject simulated attack alerts for demo purposes
    4. Compute derived metrics (risk score, compliance score)
    5. Export incidents as CSV; generate simple PDF report

All fetch functions use @st.cache_data(ttl=5) for 5-second caching.
"""

import csv
import io
import json
import random
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

# =============================================================================
# Backend Configuration
# =============================================================================
BACKEND_URL = "http://localhost:8000"

# =============================================================================
# Severity ordering (mirrors backend/models.py)
# =============================================================================
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# =============================================================================
# SECTION 1: Data Fetching from Backend
# =============================================================================
# These functions call the Phase 3 FastAPI backend and return Python dicts/lists.
# If the backend is unreachable, they return sample (fallback) data so the
# dashboard still works for demo purposes.
# =============================================================================

@st.cache_data(ttl=5)
def fetch_alerts() -> List[Dict[str, Any]]:
    """
    GET /alerts — Retrieve all stored alerts from the backend.
    
    Returns a list of alert dicts, each with:
        id, module, type, severity, timestamp, asset, details, created_at
    
    Falls back to sample data if backend is unreachable.
    """
    try:
        resp = requests.get(f"{BACKEND_URL}/alerts", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException:
        return get_sample_alerts()


@st.cache_data(ttl=5)
def fetch_incidents() -> List[Dict[str, Any]]:
    """
    GET /incidents — Retrieve all correlated incidents.
    
    Returns a list of incident dicts, each with:
        incident_id, rule_name, severity, story, alert_ids, created_at
    
    Falls back to sample data if backend is unreachable.
    """
    try:
        resp = requests.get(f"{BACKEND_URL}/incidents", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException:
        return get_sample_incidents()


@st.cache_data(ttl=5)
def fetch_stats() -> Dict[str, Any]:
    """
    GET /stats — Retrieve summary statistics.
    
    Returns dict with:
        total_alerts, total_incidents, alerts_by_module, alerts_by_severity,
        incidents_by_severity
    
    Falls back to sample data if backend is unreachable.
    """
    try:
        resp = requests.get(f"{BACKEND_URL}/stats", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException:
        return get_sample_stats()


def check_backend_health() -> bool:
    """
    GET /health — Quick check if backend is online.
    Returns True if healthy, False otherwise.
    """
    try:
        resp = requests.get(f"{BACKEND_URL}/health", timeout=2)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


# =============================================================================
# SECTION 2: Attack Simulation (POST alerts to backend)
# =============================================================================
# These functions inject realistic attack alerts into the backend so the
# correlation engine produces incidents in real-time during a demo.
# =============================================================================

def inject_attack_alerts(scenario: str) -> bool:
    """
    Simulate an attack by POSTing a sequence of alerts to the backend.
    
    Supported scenarios:
        "weak_password_bruteforce"  — Weak Password + Brute Force
        "api_recon_exploit"         — API Recon + Exploit
        "multi_stage_attack"        — Multi-Stage Attack (all modules)
    
    Returns True if all alerts were posted successfully.
    """
    now = datetime.utcnow()
    alerts = _build_attack_alerts(scenario, now)
    
    success = True
    for alert in alerts:
        try:
            resp = requests.post(f"{BACKEND_URL}/alerts", json=alert, timeout=3)
            if resp.status_code != 201:
                success = False
        except requests.exceptions.RequestException:
            success = False
    
    # Clear cached data so dashboard picks up new alerts immediately
    fetch_alerts.clear()
    fetch_incidents.clear()
    fetch_stats.clear()
    
    return success


def _build_attack_alerts(scenario: str, now: datetime) -> List[Dict[str, Any]]:
    """Build a list of alert payloads for a given attack scenario."""
    
    if scenario == "weak_password_bruteforce":
        return [
            {
                "module": "password",
                "type": "policy_audit",
                "severity": "high",
                "timestamp": (now - timedelta(minutes=5)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "policy": "minimum_length",
                    "required": 12,
                    "actual": 6,
                    "username": "admin",
                    "issues": ["Password too short", "No special characters", "Common dictionary word"]
                }
            },
            {
                "module": "network",
                "type": "connection_anomaly",
                "severity": "medium",
                "timestamp": (now - timedelta(minutes=3)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "source_ip": "192.168.1.100",
                    "dest_port": 8000,
                    "conn_count": 847,
                    "baseline_count": 45,
                    "anomaly_type": "brute_force_attempt",
                    "protocol": "HTTP"
                }
            },
            {
                "module": "network",
                "type": "connection_anomaly",
                "severity": "high",
                "timestamp": (now - timedelta(minutes=1)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "source_ip": "192.168.1.100",
                    "dest_port": 8000,
                    "conn_count": 1523,
                    "baseline_count": 45,
                    "anomaly_type": "sustained_brute_force",
                    "protocol": "HTTP"
                }
            }
        ]
    
    elif scenario == "api_recon_exploit":
        return [
            {
                "module": "network",
                "type": "connection_anomaly",
                "severity": "medium",
                "timestamp": (now - timedelta(minutes=6)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "source_ip": "10.0.0.50",
                    "dest_port": 8000,
                    "conn_count": 312,
                    "baseline_count": 30,
                    "anomaly_type": "port_scan",
                    "protocol": "TCP"
                }
            },
            {
                "module": "api",
                "type": "security_scan",
                "severity": "high",
                "timestamp": (now - timedelta(minutes=4)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "endpoint": "/api/users/{id}",
                    "owasp_category": "BOLA (Broken Object Level Authorization)",
                    "method": "GET",
                    "description": "User IDs are sequential integers; no authorization check on resource ownership",
                    "evidence": "Accessed /api/users/1 through /api/users/50 with single auth token"
                }
            },
            {
                "module": "api",
                "type": "security_scan",
                "severity": "medium",
                "timestamp": (now - timedelta(minutes=2)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "endpoint": "/api/admin/config",
                    "owasp_category": "Security Misconfiguration",
                    "method": "GET",
                    "description": "Admin configuration endpoint exposed without authentication",
                    "evidence": "200 OK response with database credentials in plaintext"
                }
            }
        ]
    
    elif scenario == "multi_stage_attack":
        return [
            {
                "module": "network",
                "type": "connection_anomaly",
                "severity": "medium",
                "timestamp": (now - timedelta(minutes=8)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "source_ip": "172.16.0.99",
                    "dest_port": 8000,
                    "conn_count": 500,
                    "baseline_count": 40,
                    "anomaly_type": "reconnaissance_scan"
                }
            },
            {
                "module": "password",
                "type": "policy_audit",
                "severity": "high",
                "timestamp": (now - timedelta(minutes=6)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "policy": "complexity",
                    "username": "svc_account",
                    "issues": ["No uppercase letters", "No numbers", "Reused from previous breach"]
                }
            },
            {
                "module": "api",
                "type": "security_scan",
                "severity": "high",
                "timestamp": (now - timedelta(minutes=4)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "endpoint": "/api/auth/login",
                    "owasp_category": "Broken Authentication",
                    "method": "POST",
                    "description": "No rate limiting on login endpoint; no account lockout after failed attempts"
                }
            },
            {
                "module": "network",
                "type": "connection_anomaly",
                "severity": "high",
                "timestamp": (now - timedelta(minutes=2)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "source_ip": "172.16.0.99",
                    "dest_port": 8000,
                    "conn_count": 2100,
                    "baseline_count": 40,
                    "anomaly_type": "active_exploitation"
                }
            },
            {
                "module": "api",
                "type": "security_scan",
                "severity": "critical",
                "timestamp": (now - timedelta(minutes=1)).isoformat(),
                "asset": "victim-app:8000",
                "details": {
                    "endpoint": "/api/users",
                    "owasp_category": "Injection",
                    "method": "POST",
                    "description": "SQL injection via user registration field — full database dump possible"
                }
            }
        ]
    
    return []


# =============================================================================
# SECTION 3: Sample / Fallback Data
# =============================================================================
# These functions return realistic-looking data so the dashboard renders
# even when the backend is offline. Essential for demo reliability.
# =============================================================================

def get_sample_alerts() -> List[Dict[str, Any]]:
    """Return hardcoded sample alerts matching the AlertOut schema."""
    now = datetime.utcnow()
    return [
        {
            "id": 1,
            "module": "network",
            "type": "connection_anomaly",
            "severity": "medium",
            "timestamp": (now - timedelta(minutes=20)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"source_ip": "192.168.1.100", "conn_count": 312, "baseline_count": 45, "anomaly_type": "port_scan"},
            "created_at": (now - timedelta(minutes=20)).isoformat()
        },
        {
            "id": 2,
            "module": "password",
            "type": "policy_audit",
            "severity": "high",
            "timestamp": (now - timedelta(minutes=18)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"policy": "minimum_length", "required": 12, "actual": 6, "username": "admin", "issues": ["Password too short", "No special characters"]},
            "created_at": (now - timedelta(minutes=18)).isoformat()
        },
        {
            "id": 3,
            "module": "api",
            "type": "security_scan",
            "severity": "high",
            "timestamp": (now - timedelta(minutes=15)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"endpoint": "/api/users/{id}", "owasp_category": "BOLA", "method": "GET", "description": "No authorization check on resource ownership"},
            "created_at": (now - timedelta(minutes=15)).isoformat()
        },
        {
            "id": 4,
            "module": "network",
            "type": "connection_anomaly",
            "severity": "high",
            "timestamp": (now - timedelta(minutes=12)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"source_ip": "192.168.1.100", "conn_count": 1523, "baseline_count": 45, "anomaly_type": "brute_force"},
            "created_at": (now - timedelta(minutes=12)).isoformat()
        },
        {
            "id": 5,
            "module": "password",
            "type": "policy_audit",
            "severity": "medium",
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"policy": "complexity", "username": "user1", "issues": ["No uppercase letters"]},
            "created_at": (now - timedelta(minutes=10)).isoformat()
        },
        {
            "id": 6,
            "module": "api",
            "type": "security_scan",
            "severity": "medium",
            "timestamp": (now - timedelta(minutes=8)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"endpoint": "/api/admin/config", "owasp_category": "Security Misconfiguration", "method": "GET", "description": "Admin endpoint exposed without auth"},
            "created_at": (now - timedelta(minutes=8)).isoformat()
        },
        {
            "id": 7,
            "module": "api",
            "type": "security_scan",
            "severity": "critical",
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"endpoint": "/api/auth/login", "owasp_category": "Broken Authentication", "method": "POST", "description": "No rate limiting; no lockout"},
            "created_at": (now - timedelta(minutes=5)).isoformat()
        },
        {
            "id": 8,
            "module": "network",
            "type": "connection_anomaly",
            "severity": "medium",
            "timestamp": (now - timedelta(minutes=3)).isoformat(),
            "asset": "victim-app:8000",
            "details": {"source_ip": "10.0.0.50", "conn_count": 200, "baseline_count": 30, "anomaly_type": "unusual_traffic"},
            "created_at": (now - timedelta(minutes=3)).isoformat()
        },
    ]


def get_sample_incidents() -> List[Dict[str, Any]]:
    """Return hardcoded sample incidents matching the IncidentOut schema."""
    now = datetime.utcnow()
    return [
        {
            "incident_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "rule_name": "Credential Abuse Likely",
            "severity": "critical",
            "story": (
                "🔴 CRITICAL — Credential Abuse Likely\n\n"
                "What happened:\n"
                "  • A weak password policy was flagged (alert #2, severity: high)\n"
                "  • Abnormal network traffic was detected (alert #4, severity: high)\n"
                "  • Both events hit the SAME asset: 'victim-app:8000'\n"
                "  • Time gap between events: 360 seconds\n\n"
                "Why this is critical:\n"
                "  An attacker likely obtained valid credentials through policy weaknesses "
                "and is now conducting unauthorized access. The network anomaly may represent "
                "data exfiltration or lateral movement using the compromised account.\n\n"
                "Recommended action:\n"
                "  Immediately rotate credentials on 'victim-app:8000', enable MFA, "
                "and review access logs for unauthorised sessions."
            ),
            "alert_ids": [2, 4],
            "created_at": (now - timedelta(minutes=10)).isoformat()
        },
        {
            "incident_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
            "rule_name": "Recon + Active Exploitation",
            "severity": "critical",
            "story": (
                "🔴 CRITICAL — Reconnaissance + Active Exploitation\n\n"
                "What happened:\n"
                "  • Network anomaly detected (alert #1) — likely port scanning\n"
                "  • API vulnerability found (alert #3, type: security_scan)\n"
                "  • Both target the same asset: 'victim-app:8000'\n\n"
                "Why this is critical:\n"
                "  This is the classic two-stage attack pattern. The attacker first scanned "
                "the network to discover services, then exploited a known API vulnerability. "
                "The combination indicates an active, targeted intrusion.\n\n"
                "Recommended action:\n"
                "  Patch the API vulnerability immediately, review firewall rules, "
                "and check for any data accessed during the window."
            ),
            "alert_ids": [1, 3],
            "created_at": (now - timedelta(minutes=8)).isoformat()
        },
        {
            "incident_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
            "rule_name": "Multi-Signal Attack in Progress",
            "severity": "critical",
            "story": (
                "🟠 CRITICAL — Multi-Signal Attack Detected\n\n"
                "What happened:\n"
                "  • 5 security alerts fired on asset 'victim-app:8000' within 15 minutes\n"
                "  • Modules involved: api, network, password\n"
                "  • Severity levels: medium, high, high, medium, critical\n\n"
                "Why this is critical:\n"
                "  Multiple independent security signals converging on the same asset "
                "in a short timeframe is a strong indicator of a coordinated attack.\n\n"
                "Recommended action:\n"
                "  Initiate incident response. Isolate the affected asset, review all "
                "alerts in sequence, and determine the attack timeline."
            ),
            "alert_ids": [1, 2, 3, 4, 7],
            "created_at": (now - timedelta(minutes=5)).isoformat()
        },
    ]


def get_sample_stats() -> Dict[str, Any]:
    """Return hardcoded sample statistics matching the /stats endpoint."""
    return {
        "total_alerts": 8,
        "total_incidents": 3,
        "alerts_by_module": {
            "network": 3,
            "password": 2,
            "api": 3,
        },
        "alerts_by_severity": {
            "info": 0,
            "low": 0,
            "medium": 3,
            "high": 3,
            "critical": 2,
        },
        "incidents_by_severity": {
            "high": 0,
            "critical": 3,
        },
    }


# =============================================================================
# SECTION 4: Derived Metrics & Scoring
# =============================================================================
# These functions compute dashboard-specific metrics from raw alert/incident data.
# =============================================================================

def compute_risk_score(alerts: List[Dict], incidents: List[Dict]) -> int:
    """
    Compute an overall risk score (0–100) based on alert severities and incidents.
    
    Scoring logic:
        - Each alert contributes points based on severity
        - Each incident adds extra weight (correlation bonus)
        - Score is capped at 100
    
    This gives a single number the evaluator can glance at instantly.
    """
    severity_weights = {"info": 1, "low": 3, "medium": 8, "high": 15, "critical": 25}
    
    # Points from individual alerts
    alert_score = sum(
        severity_weights.get(a.get("severity", "info"), 1) 
        for a in alerts
    )
    
    # Bonus from correlated incidents (correlation = higher risk)
    incident_bonus = len(incidents) * 15
    
    # Normalize to 0-100 (assume 200 is "max danger")
    raw = alert_score + incident_bonus
    return min(100, int((raw / 200) * 100))


def compute_compliance_score(alerts: List[Dict]) -> int:
    """
    Compute a compliance score (0–100) from password + API alerts.
    
    Logic: Start at 100, deduct points for each violation found.
    Higher severity violations cost more points.
    """
    deductions = {"info": 2, "low": 5, "medium": 10, "high": 20, "critical": 30}
    
    compliance_alerts = [
        a for a in alerts 
        if a.get("module") in ("password", "api")
    ]
    
    total_deduction = sum(
        deductions.get(a.get("severity", "info"), 5) 
        for a in compliance_alerts
    )
    
    return max(0, 100 - total_deduction)


def compute_password_compliance(alerts: List[Dict]) -> int:
    """Compliance score specifically from password module alerts."""
    deductions = {"info": 3, "low": 8, "medium": 15, "high": 25, "critical": 35}
    pwd_alerts = [a for a in alerts if a.get("module") == "password"]
    total_ded = sum(deductions.get(a.get("severity", "info"), 5) for a in pwd_alerts)
    return max(0, 100 - total_ded)


def compute_api_compliance(alerts: List[Dict]) -> int:
    """Compliance score specifically from API module alerts."""
    deductions = {"info": 3, "low": 8, "medium": 15, "high": 25, "critical": 35}
    api_alerts = [a for a in alerts if a.get("module") == "api"]
    total_ded = sum(deductions.get(a.get("severity", "info"), 5) for a in api_alerts)
    return max(0, 100 - total_ded)


# =============================================================================
# SECTION 5: Export Functions
# =============================================================================

def export_incidents_csv(incidents: List[Dict]) -> str:
    """
    Convert incidents list to CSV string for download.
    Columns: Incident ID, Rule, Severity, Story (first line), Alert Count, Created At
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Incident ID", "Rule Name", "Severity", "Story Summary", "Alert Count", "Created At"])
    
    for inc in incidents:
        story_summary = inc.get("story", "").split("\n")[0][:100]
        writer.writerow([
            inc.get("incident_id", ""),
            inc.get("rule_name", ""),
            inc.get("severity", ""),
            story_summary,
            len(inc.get("alert_ids", [])),
            inc.get("created_at", ""),
        ])
    
    return output.getvalue()


def generate_pdf_report(alerts: List[Dict], incidents: List[Dict], stats: Dict) -> bytes:
    """
    Generate a simple PDF incident report using fpdf2.
    
    Returns the PDF as bytes for st.download_button.
    Falls back to a text summary if fpdf2 is not installed.
    """
    try:
        from fpdf import FPDF
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Title
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 15, "SecuriSphere - Security Report", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", ln=True, align="C")
        pdf.ln(10)
        
        # Executive Summary
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 10)
        risk = compute_risk_score(alerts, incidents)
        compliance = compute_compliance_score(alerts)
        pdf.cell(0, 7, f"Total Alerts: {stats.get('total_alerts', len(alerts))}", ln=True)
        pdf.cell(0, 7, f"Correlated Incidents: {stats.get('total_incidents', len(incidents))}", ln=True)
        pdf.cell(0, 7, f"Risk Score: {risk}/100", ln=True)
        pdf.cell(0, 7, f"Compliance Score: {compliance}/100", ln=True)
        pdf.ln(8)
        
        # Incidents
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Correlated Incidents", ln=True)
        
        for i, inc in enumerate(incidents, 1):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, f"{i}. [{inc.get('severity', '').upper()}] {inc.get('rule_name', '')}", ln=True)
            pdf.set_font("Helvetica", "", 9)
            
            story = inc.get("story", "No story available")
            # Clean emoji characters for PDF
            story_clean = story.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, story_clean)
            pdf.ln(5)
        
        return pdf.output()
    
    except ImportError:
        # Fallback if fpdf2 is not installed
        report = f"SecuriSphere Security Report\n{'='*40}\n"
        report += f"Generated: {datetime.utcnow().isoformat()}\n\n"
        report += f"Total Alerts: {len(alerts)}\n"
        report += f"Incidents: {len(incidents)}\n\n"
        for inc in incidents:
            report += f"[{inc.get('severity', '').upper()}] {inc.get('rule_name', '')}\n"
            report += f"{inc.get('story', '')}\n\n"
        return report.encode("utf-8")


# =============================================================================
# SECTION 6: Utility Helpers
# =============================================================================

def severity_color(severity: str) -> str:
    """Return the hex color for a given severity level."""
    colors = {
        "info": "#6B7280",
        "low": "#10B981",
        "medium": "#F59E0B",
        "high": "#EF4444",
        "critical": "#B91C1C",
    }
    return colors.get(severity.lower(), "#6B7280")


def severity_badge_html(severity: str, large: bool = False) -> str:
    """Generate an HTML badge span for a severity level."""
    size_class = "badge-lg" if large else ""
    return f'<span class="badge badge-{severity.lower()} {size_class}">{severity.upper()}</span>'


def format_timestamp(ts: str) -> str:
    """Format an ISO timestamp to a human-readable string."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        return ts


def get_alert_by_id(alerts: List[Dict], alert_id: int) -> Optional[Dict]:
    """Find an alert by its ID in a list of alerts."""
    for a in alerts:
        if a.get("id") == alert_id:
            return a
    return None
