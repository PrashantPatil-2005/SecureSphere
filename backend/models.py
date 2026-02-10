#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Phase 3: Pydantic Models
# =============================================================================
"""
Pydantic models for alert ingestion and correlated incident output.

Models:
    AlertIn      — Schema for incoming alerts from any Phase 2 module
    AlertOut     — Response schema including auto-generated DB id
    IncidentOut  — Correlated incident with UUID, story, and linked alerts

All Phase 2 modules (network, password, api) produce alerts in this format:
    {
        "module": "network|password|api",
        "type": "connection_anomaly|policy_audit|security_scan",
        "severity": "low|medium|high|critical",
        "timestamp": "ISO 8601 string",
        "asset": "victim-app:8000",
        "details": { ... module-specific data ... }
    }
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# =============================================================================
# Severity Levels (ordered for comparison / escalation)
# =============================================================================
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_gte(a: str, b: str) -> bool:
    """Return True if severity `a` is greater than or equal to `b`."""
    return SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0)


def max_severity(*severities: str) -> str:
    """Return the highest severity from the given values."""
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


# =============================================================================
# Alert Models
# =============================================================================

class AlertIn(BaseModel):
    """
    Incoming alert from any Phase 2 module.
    
    The `details` field is a flexible dict that accepts module-specific data
    (e.g., connection info from network, vulnerability list from api, 
    audit issues from password).
    """
    module: str = Field(
        ..., 
        description="Source module: 'network', 'password', or 'api'",
        examples=["network"]
    )
    type: str = Field(
        ..., 
        description="Alert type, e.g. 'connection_anomaly', 'policy_audit', 'security_scan'",
        examples=["connection_anomaly"]
    )
    severity: str = Field(
        ..., 
        description="Alert severity: 'info', 'low', 'medium', 'high', 'critical'",
        examples=["high"]
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat(),
        description="ISO 8601 timestamp of the alert"
    )
    asset: str = Field(
        default="victim-app:8000",
        description="Target asset identifier"
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Module-specific alert data (connection info, vulns, issues, etc.)"
    )


class AlertOut(BaseModel):
    """Alert response model — includes the auto-generated database ID."""
    id: int
    module: str
    type: str
    severity: str
    timestamp: str
    asset: str
    details: Dict[str, Any]
    created_at: str

    class Config:
        from_attributes = True


# =============================================================================
# Correlated Incident Models
# =============================================================================

class IncidentOut(BaseModel):
    """
    Correlated incident — groups multiple alerts into a single security event.
    
    Fields:
        incident_id : UUID for unique identification
        rule_name   : Which correlation rule produced this incident
        severity    : Escalated severity (typically higher than individual alerts)
        story       : Human-readable narrative explaining the correlation
        alert_ids   : List of DB alert IDs that contributed to this incident
        created_at  : When the incident was created
    """
    incident_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique incident identifier (UUID)"
    )
    rule_name: str = Field(
        ..., 
        description="Correlation rule that triggered this incident"
    )
    severity: str = Field(
        ..., 
        description="Escalated severity level"
    )
    story: str = Field(
        ..., 
        description="Human-readable narrative explaining why this incident was escalated"
    )
    alert_ids: List[int] = Field(
        default_factory=list,
        description="IDs of alerts that make up this incident"
    )
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat(),
        description="When this incident was created"
    )

    class Config:
        from_attributes = True
