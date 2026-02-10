#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Phase 3: Database Setup (SQLite + SQLAlchemy)
# =============================================================================
"""
Database configuration and ORM models for SecuriSphere Phase 3.

Tables:
    alerts          — Raw alerts from all Phase 2 modules
    incidents       — Correlated incidents produced by the correlation engine
    incident_alerts — Many-to-many join table linking incidents ↔ alerts

Uses SQLite for simplicity (no external database required).
The DB file is stored at ./backend/securisphere.db.
"""

import json
import logging
from datetime import datetime
from typing import Generator

from sqlalchemy import (
    Column, DateTime, ForeignKey, Integer, String, Text,
    Table, create_engine, event
)
from sqlalchemy.orm import (
    Session, declarative_base, relationship, sessionmaker
)

# =============================================================================
# Logging
# =============================================================================
logger = logging.getLogger(__name__)

# =============================================================================
# Database Configuration
# =============================================================================
DATABASE_URL = "sqlite:///./backend/securisphere.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite + FastAPI
    echo=False,
)

# Enable WAL mode for better concurrent read performance
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =============================================================================
# Association Table: Many-to-Many (Incidents ↔ Alerts)
# =============================================================================
incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", String, ForeignKey("incidents.incident_id"), primary_key=True),
    Column("alert_id", Integer, ForeignKey("alerts.id"), primary_key=True),
)


# =============================================================================
# ORM Model: Alert
# =============================================================================
class AlertRecord(Base):
    """
    Stores raw alerts from Phase 2 modules (network, password, api).
    
    The `details` column stores module-specific data as a JSON string.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    module = Column(String(50), nullable=False, index=True)       # network | password | api
    type = Column(String(100), nullable=False)                     # connection_anomaly, etc.
    severity = Column(String(20), nullable=False, index=True)      # info | low | medium | high | critical
    timestamp = Column(String(50), nullable=False)                 # ISO 8601 from the module
    asset = Column(String(200), nullable=False, default="victim-app:8000", index=True)
    details = Column(Text, nullable=False, default="{}")           # JSON blob
    created_at = Column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    # Relationship — which incidents include this alert
    incidents = relationship(
        "IncidentRecord",
        secondary=incident_alerts,
        back_populates="alerts",
    )

    def details_dict(self) -> dict:
        """Parse the JSON details column into a Python dict."""
        try:
            return json.loads(self.details) if self.details else {}
        except json.JSONDecodeError:
            return {}

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} module={self.module} "
            f"severity={self.severity} asset={self.asset}>"
        )


# =============================================================================
# ORM Model: Incident (Correlated)
# =============================================================================
class IncidentRecord(Base):
    """
    Stores correlated incidents produced by the correlation engine.
    
    Each incident groups multiple alerts that together indicate
    a higher-severity security event.
    """
    __tablename__ = "incidents"

    incident_id = Column(String(36), primary_key=True, index=True)  # UUID
    rule_name = Column(String(200), nullable=False)                  # Which rule matched
    severity = Column(String(20), nullable=False)                    # Escalated severity
    story = Column(Text, nullable=False)                             # Human-readable narrative
    created_at = Column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    # Relationship — which alerts are part of this incident
    alerts = relationship(
        "AlertRecord",
        secondary=incident_alerts,
        back_populates="incidents",
    )

    def __repr__(self) -> str:
        return (
            f"<Incident id={self.incident_id} rule={self.rule_name} "
            f"severity={self.severity}>"
        )


# =============================================================================
# Database Initialization
# =============================================================================
def init_db() -> None:
    """Create all tables if they don't already exist."""
    logger.info("Initializing database at %s", DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully.")


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency — yields a database session.
    
    Usage in FastAPI:
        @app.get("/alerts")
        def list_alerts(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
