#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Phase 3: APScheduler for Periodic Correlation
# =============================================================================
"""
Optional scheduler that runs the correlation engine every 60 seconds.

This is a fallback mechanism in case the real-time POST /alerts trigger
doesn't catch all correlation patterns (e.g., when alerts arrive
from different modules at different times).

Usage:
    The scheduler is integrated into the FastAPI startup event.
    It runs in the background and does not block the main application.
"""

import logging

from apscheduler.schedulers.background import BackgroundScheduler

from backend.correlation_engine import CorrelationEngine
from backend.database import SessionLocal

# =============================================================================
# Logging
# =============================================================================
logger = logging.getLogger("securisphere.scheduler")


# =============================================================================
# Scheduled Correlation Job
# =============================================================================
def run_correlation_job():
    """
    Scheduled job — runs correlation engine against all stored alerts.
    
    Creates its own database session (since scheduler runs in a
    background thread, separate from FastAPI request lifecycle).
    """
    logger.info("⏰ Scheduled correlation job starting...")
    db = SessionLocal()
    try:
        engine = CorrelationEngine()
        new_incidents = engine.run(db)
        if new_incidents:
            logger.info(
                "⏰ Scheduled run produced %d new incident(s)",
                len(new_incidents),
            )
            for inc in new_incidents:
                logger.info(
                    "   🔔 %s [%s] — %d alerts",
                    inc.rule_name,
                    inc.severity.upper(),
                    len(inc.alerts),
                )
        else:
            logger.info("⏰ Scheduled run: no new incidents")
    except Exception as e:
        logger.error("Scheduled correlation failed: %s", e, exc_info=True)
    finally:
        db.close()


# =============================================================================
# Scheduler Setup
# =============================================================================
def start_scheduler(interval_seconds: int = 60) -> BackgroundScheduler:
    """
    Start the APScheduler background scheduler.
    
    Args:
        interval_seconds: How often to run correlation (default: 60s)
        
    Returns:
        Running BackgroundScheduler instance
    """
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_correlation_job,
        trigger="interval",
        seconds=interval_seconds,
        id="correlation_job",
        name="Periodic Correlation Engine",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "📅 Scheduler started — correlation runs every %d seconds",
        interval_seconds,
    )
    return scheduler
