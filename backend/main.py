#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Phase 3: FastAPI Backend (Central Alert Hub)
# =============================================================================
"""
Central FastAPI application that serves as the integration hub for all
SecuriSphere security modules.

Endpoints:
    POST /alerts     — Receive and store alerts from any module
    GET  /alerts     — List all stored alerts (with optional filters)
    GET  /incidents  — List all correlated incidents
    GET  /health     — Health check

On every new alert, the correlation engine is triggered automatically
to check if the new alert creates any new incident patterns.
"""

import json
import logging
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from backend.correlation_engine import CorrelationEngine
from backend.database import AlertRecord, IncidentRecord, get_db, init_db
from backend.models import AlertIn, AlertOut, IncidentOut

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-28s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("securisphere.backend")


# =============================================================================
# FastAPI Application
# =============================================================================
app = FastAPI(
    title="SecuriSphere — Phase 3: Integration & Correlation",
    description=(
        "Central alert hub and correlation engine for SecuriSphere. "
        "Receives alerts from network, password, and API modules, "
        "correlates them into security incidents with escalated severity."
    ),
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow the Phase 4 Streamlit dashboard to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Correlation engine singleton
correlation_engine = CorrelationEngine()


# =============================================================================
# Startup Event — Initialize Database
# =============================================================================
@app.on_event("startup")
def on_startup():
    """Create database tables on application startup."""
    logger.info("=" * 60)
    logger.info("SecuriSphere Phase 3 Backend starting...")
    logger.info("=" * 60)
    init_db()
    logger.info("Backend ready. Accepting alerts at POST /alerts")


# =============================================================================
# GET / — Root Redirect to Swagger Docs
# =============================================================================
@app.get("/", include_in_schema=False)
def root():
    """Redirect root URL to the interactive API documentation."""
    return RedirectResponse(url="/docs")

# =============================================================================
# POST /alerts — Receive Alert from Any Module
# =============================================================================
@app.post(
    "/alerts",
    response_model=AlertOut,
    status_code=201,
    summary="Submit a new security alert",
    tags=["Alerts"],
)
def create_alert(alert: AlertIn, db: Session = Depends(get_db)):
    """
    Accept a JSON alert from any Phase 2 module and store it in the database.
    
    After storing, the correlation engine runs automatically to check
    if this new alert triggers any incident patterns.
    
    Accepts the standard alert format:
    ```json
    {
        "module": "network",
        "type": "connection_anomaly",
        "severity": "high",
        "timestamp": "2026-02-10T07:00:00",
        "asset": "victim-app:8000",
        "details": { ... }
    }
    ```
    """
    logger.info(
        "📥 NEW ALERT: module=%s type=%s severity=%s asset=%s",
        alert.module, alert.type, alert.severity, alert.asset,
    )

    # Validate module name
    valid_modules = {"network", "password", "api"}
    if alert.module not in valid_modules:
        logger.warning("Unknown module: %s (accepting anyway)", alert.module)

    # Validate severity
    valid_severities = {"info", "low", "medium", "high", "critical"}
    if alert.severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity '{alert.severity}'. Must be one of: {valid_severities}"
        )

    # Create DB record
    db_alert = AlertRecord(
        module=alert.module,
        type=alert.type,
        severity=alert.severity,
        timestamp=alert.timestamp,
        asset=alert.asset,
        details=json.dumps(alert.details),
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)

    logger.info("  → Stored as alert #%d", db_alert.id)

    # =======================================================================
    # Trigger Correlation Engine on every new alert
    # =======================================================================
    try:
        new_incidents = correlation_engine.run(db)
        if new_incidents:
            logger.info(
                "  → Correlation produced %d new incident(s)!",
                len(new_incidents)
            )
            for inc in new_incidents:
                logger.info(
                    "    🔔 INCIDENT: %s [%s]",
                    inc.rule_name, inc.severity.upper()
                )
    except Exception as e:
        logger.error("Correlation engine error: %s", e, exc_info=True)

    return AlertOut(
        id=db_alert.id,
        module=db_alert.module,
        type=db_alert.type,
        severity=db_alert.severity,
        timestamp=db_alert.timestamp,
        asset=db_alert.asset,
        details=json.loads(db_alert.details),
        created_at=str(db_alert.created_at),
    )


# =============================================================================
# GET /alerts — List All Alerts
# =============================================================================
@app.get(
    "/alerts",
    response_model=List[AlertOut],
    summary="List all stored alerts",
    tags=["Alerts"],
)
def list_alerts(
    module: Optional[str] = Query(None, description="Filter by module (network, password, api)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    asset: Optional[str] = Query(None, description="Filter by asset"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    db: Session = Depends(get_db),
):
    """
    List all alerts with optional filtering.
    
    Query parameters:
        - `module`: Filter by source module (network, password, api)
        - `severity`: Filter by severity level  
        - `asset`: Filter by target asset
        - `limit`: Maximum number of results (default 100)
    """
    query = db.query(AlertRecord)

    if module:
        query = query.filter(AlertRecord.module == module)
    if severity:
        query = query.filter(AlertRecord.severity == severity)
    if asset:
        query = query.filter(AlertRecord.asset == asset)

    alerts = query.order_by(AlertRecord.id.desc()).limit(limit).all()

    return [
        AlertOut(
            id=a.id,
            module=a.module,
            type=a.type,
            severity=a.severity,
            timestamp=a.timestamp,
            asset=a.asset,
            details=json.loads(a.details) if a.details else {},
            created_at=str(a.created_at),
        )
        for a in alerts
    ]


# =============================================================================
# GET /incidents — List Correlated Incidents
# =============================================================================
@app.get(
    "/incidents",
    response_model=List[IncidentOut],
    summary="List all correlated incidents",
    tags=["Incidents"],
)
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
    db: Session = Depends(get_db),
):
    """
    List all correlated security incidents.
    
    Each incident groups multiple alerts that together indicate
    a higher-severity security event, with a human-readable "story"
    explaining the escalation.
    """
    query = db.query(IncidentRecord)

    if severity:
        query = query.filter(IncidentRecord.severity == severity)

    incidents = query.order_by(IncidentRecord.created_at.desc()).limit(limit).all()

    return [
        IncidentOut(
            incident_id=inc.incident_id,
            rule_name=inc.rule_name,
            severity=inc.severity,
            story=inc.story,
            alert_ids=[a.id for a in inc.alerts],
            created_at=str(inc.created_at),
        )
        for inc in incidents
    ]


# =============================================================================
# POST /correlate — Manually Trigger Correlation
# =============================================================================
@app.post(
    "/correlate",
    summary="Manually trigger the correlation engine",
    tags=["Correlation"],
)
def trigger_correlation(db: Session = Depends(get_db)):
    """
    Manually trigger the correlation engine to process all alerts.
    Useful for testing or when the automatic post-alert trigger is skipped.
    """
    new_incidents = correlation_engine.run(db)
    return {
        "status": "completed",
        "new_incidents": len(new_incidents),
        "incidents": [
            {
                "incident_id": inc.incident_id,
                "rule_name": inc.rule_name,
                "severity": inc.severity,
            }
            for inc in new_incidents
        ],
    }


# =============================================================================
# GET /health — Health Check
# =============================================================================
@app.get(
    "/health",
    summary="Health check",
    tags=["System"],
)
def health_check():
    """Return backend health status."""
    return {
        "status": "healthy",
        "service": "SecuriSphere Phase 3 — Integration & Correlation",
        "version": "3.0.0",
    }


# =============================================================================
# GET /stats — Dashboard Statistics
# =============================================================================
@app.get(
    "/stats",
    summary="Get alert and incident statistics",
    tags=["System"],
)
def get_stats(db: Session = Depends(get_db)):
    """Return summary statistics for the dashboard."""
    total_alerts = db.query(AlertRecord).count()
    total_incidents = db.query(IncidentRecord).count()

    # Count by module
    module_counts = {}
    for module in ["network", "password", "api"]:
        module_counts[module] = (
            db.query(AlertRecord)
            .filter(AlertRecord.module == module)
            .count()
        )

    # Count by severity
    severity_counts = {}
    for sev in ["info", "low", "medium", "high", "critical"]:
        severity_counts[sev] = (
            db.query(AlertRecord)
            .filter(AlertRecord.severity == sev)
            .count()
        )

    # Incident severity breakdown
    incident_severity = {}
    for sev in ["high", "critical"]:
        incident_severity[sev] = (
            db.query(IncidentRecord)
            .filter(IncidentRecord.severity == sev)
            .count()
        )

    return {
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "alerts_by_module": module_counts,
        "alerts_by_severity": severity_counts,
        "incidents_by_severity": incident_severity,
    }
