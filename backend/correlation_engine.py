#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Phase 3: Correlation Engine
# =============================================================================
"""
Core correlation engine that analyzes incoming alerts and groups them
into higher-severity "incidents" using 5 configurable detection rules.

Design philosophy:
    - Rules are hardcoded but structured for easy extension
    - Each rule returns a list of new incidents (or empty list)
    - Duplicate incidents for the same alert combination are prevented
    - Each alert participates in AT MOST ONE incident per rule
      (closest-match / best-pair strategy to avoid noise)
    - Human-readable "story" field explains every escalation

Correlation Rules:
    Rule 1: Credential Abuse Likely
    Rule 2: Recon + Active Exploitation
    Rule 3: Multi-Signal Attack in Progress
    Rule 4: API Takeover Attempt  
    Rule 5: Identity Compromise Risk
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from backend.database import AlertRecord, IncidentRecord, incident_alerts
from backend.models import SEVERITY_ORDER, max_severity, severity_gte

# =============================================================================
# Logging
# =============================================================================
logger = logging.getLogger(__name__)


# =============================================================================
# Helper Functions
# =============================================================================
def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Parse an ISO 8601 timestamp string into a datetime object.
    Handles multiple common formats gracefully.
    """
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    logger.warning("Could not parse timestamp: %s", ts_str)
    return None


def _time_gap(alert_a: AlertRecord, alert_b: AlertRecord) -> timedelta:
    """Return the absolute time gap between two alerts (or a large value on error)."""
    ts_a = _parse_timestamp(alert_a.timestamp)
    ts_b = _parse_timestamp(alert_b.timestamp)
    if ts_a is None or ts_b is None:
        return timedelta(days=999)
    return abs(ts_a - ts_b)


def _alerts_within_window(
    alert_a: AlertRecord,
    alert_b: AlertRecord,
    window_minutes: int = 10,
) -> bool:
    """Check if two alerts occurred within `window_minutes` of each other."""
    return _time_gap(alert_a, alert_b) <= timedelta(minutes=window_minutes)


def _get_existing_alert_sets(db: Session) -> Set[frozenset]:
    """
    Get all existing (incident → alert) sets to prevent duplicate incidents.
    Returns a set of frozensets of alert IDs already grouped.
    """
    existing = set()
    incidents = db.query(IncidentRecord).all()
    for inc in incidents:
        alert_ids = frozenset(a.id for a in inc.alerts)
        existing.add(alert_ids)
    return existing


def _get_existing_incidents_by_rule(
    db: Session, rule_name: str
) -> List[IncidentRecord]:
    """Get all existing incidents for a specific rule."""
    return (
        db.query(IncidentRecord)
        .filter(IncidentRecord.rule_name == rule_name)
        .all()
    )


# =============================================================================
# Correlation Engine
# =============================================================================
class CorrelationEngine:
    """
    Analyzes stored alerts and produces correlated incidents.
    
    Each rule uses a "best match" strategy: for pairwise rules, each
    alert from one module is paired with its *closest* (in time) alert
    from the other module. This avoids the O(n*m) explosion that would
    occur if every possible combination were turned into an incident.
    
    Call `run(db)` to execute all rules against the current alert database.
    New incidents are persisted automatically.
    
    Usage:
        engine = CorrelationEngine()
        new_incidents = engine.run(db_session)
    """

    def __init__(self) -> None:
        # Registry of all correlation rules — add new rules here
        self.rules = [
            self.rule_1_credential_abuse,
            self.rule_2_recon_exploitation,
            self.rule_3_multi_signal_attack,
            self.rule_4_api_takeover,
            self.rule_5_identity_compromise,
        ]

    def run(self, db: Session) -> List[IncidentRecord]:
        """
        Execute all correlation rules and persist any new incidents.
        
        Args:
            db: Active SQLAlchemy session
            
        Returns:
            List of newly created IncidentRecord objects
        """
        logger.info("=" * 60)
        logger.info("CORRELATION ENGINE: Starting analysis run")
        logger.info("=" * 60)

        all_alerts = db.query(AlertRecord).all()
        logger.info("Total alerts in database: %d", len(all_alerts))

        existing_sets = _get_existing_alert_sets(db)
        new_incidents: List[IncidentRecord] = []

        for rule_func in self.rules:
            rule_name = rule_func.__name__
            logger.info("Running rule: %s", rule_name)
            try:
                # Rule 3 gets a db reference for superset deduplication
                if rule_name == "rule_3_multi_signal_attack":
                    incidents = rule_func(all_alerts, existing_sets, _db=db)
                else:
                    incidents = rule_func(all_alerts, existing_sets)
                for inc in incidents:
                    db.add(inc)
                    db.flush()
                    alert_ids = frozenset(a.id for a in inc.alerts)
                    existing_sets.add(alert_ids)
                    new_incidents.append(inc)
                    logger.info(
                        "  → NEW INCIDENT: %s | severity=%s | alerts=%s",
                        inc.rule_name, inc.severity,
                        [a.id for a in inc.alerts]
                    )
            except Exception as e:
                logger.error("Error in rule %s: %s", rule_name, e, exc_info=True)

        db.commit()

        logger.info(
            "CORRELATION ENGINE: Complete — %d new incidents created",
            len(new_incidents)
        )
        return new_incidents

    # =========================================================================
    # RULE 1: Credential Abuse Likely
    # =========================================================================
    # TRIGGER: Password alert (severity >= medium) AND the *closest* network
    #          anomaly on the SAME asset within a 10-minute window.
    # RATIONALE: Weak/compromised credentials combined with abnormal
    #            network activity suggest active credential abuse.
    # One incident per password alert (closest network match).
    # =========================================================================
    def rule_1_credential_abuse(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        incidents = []
        used_net_ids: Set[int] = set()  # Track used network alerts

        password_alerts = [
            a for a in alerts
            if a.module == "password" and severity_gte(a.severity, "medium")
        ]
        network_alerts = [
            a for a in alerts
            if a.module == "network"
        ]

        for pwd_alert in password_alerts:
            # Find the closest network alert on the same asset within 10 min
            best_net = None
            best_gap = timedelta(days=999)
            for net_alert in network_alerts:
                if net_alert.id in used_net_ids:
                    continue
                if pwd_alert.asset != net_alert.asset:
                    continue
                gap = _time_gap(pwd_alert, net_alert)
                if gap <= timedelta(minutes=10) and gap < best_gap:
                    best_gap = gap
                    best_net = net_alert

            if best_net is None:
                continue

            pair = frozenset([pwd_alert.id, best_net.id])
            if pair in existing:
                continue

            used_net_ids.add(best_net.id)

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Credential Abuse Likely",
                severity="critical",
                story=(
                    f"🔴 CRITICAL — Credential Abuse Likely\n"
                    f"A weak/compromised password policy (alert #{pwd_alert.id}, "
                    f"severity: {pwd_alert.severity}) was detected alongside "
                    f"abnormal network traffic (alert #{best_net.id}) on asset "
                    f"'{pwd_alert.asset}' within a 10-minute window.\n"
                    f"This combination strongly suggests that compromised "
                    f"credentials are being actively exploited. An attacker "
                    f"may have obtained valid credentials through policy "
                    f"weaknesses and is now conducting unauthorized access."
                ),
                alerts=[pwd_alert, best_net],
            )
            incidents.append(inc)
        return incidents

    # =========================================================================
    # RULE 2: Recon + Active Exploitation
    # =========================================================================
    # TRIGGER: Network anomaly AND API vulnerability on the SAME asset.
    # RATIONALE: Network scanning/probing followed by API vulnerability
    #            exploitation indicates a multi-stage attack.
    # One incident per API alert (closest network match).
    # =========================================================================
    def rule_2_recon_exploitation(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        incidents = []
        used_net_ids: Set[int] = set()

        network_alerts = [a for a in alerts if a.module == "network"]
        api_alerts = [a for a in alerts if a.module == "api"]

        for api_alert in api_alerts:
            best_net = None
            best_gap = timedelta(days=999)
            for net_alert in network_alerts:
                if net_alert.id in used_net_ids:
                    continue
                if net_alert.asset != api_alert.asset:
                    continue
                gap = _time_gap(api_alert, net_alert)
                if gap < best_gap:
                    best_gap = gap
                    best_net = net_alert

            if best_net is None:
                continue

            pair = frozenset([best_net.id, api_alert.id])
            if pair in existing:
                continue

            used_net_ids.add(best_net.id)

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Recon + Active Exploitation",
                severity="critical",
                story=(
                    f"🔴 CRITICAL — Reconnaissance + Active Exploitation\n"
                    f"Network anomaly (alert #{best_net.id}) combined with "
                    f"API vulnerability (alert #{api_alert.id}, "
                    f"type: {api_alert.type}) detected on asset "
                    f"'{best_net.asset}'.\n"
                    f"This pattern indicates an attacker first performed "
                    f"network reconnaissance (port scanning, service "
                    f"enumeration) and then actively exploited discovered "
                    f"API weaknesses. Immediate investigation recommended."
                ),
                alerts=[best_net, api_alert],
            )
            incidents.append(inc)
        return incidents

    # =========================================================================
    # RULE 3: Multi-Signal Attack in Progress
    # =========================================================================
    # TRIGGER: 3 or more alerts with severity >= medium on the SAME asset
    #          within a 15-minute window.
    # RATIONALE: Multiple medium+ signals converging on one asset
    #            indicates a coordinated or escalating attack.
    # Creates ONE incident per asset — the largest group in the window.
    # =========================================================================
    def rule_3_multi_signal_attack(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
        _db: Optional[Session] = None,
    ) -> List[IncidentRecord]:
        incidents = []

        # Group medium+ alerts by asset
        asset_alerts: Dict[str, List[AlertRecord]] = {}
        for a in alerts:
            if severity_gte(a.severity, "medium"):
                asset_alerts.setdefault(a.asset, []).append(a)

        for asset, asset_alert_list in asset_alerts.items():
            if len(asset_alert_list) < 3:
                continue

            # Sort by timestamp
            sorted_alerts = sorted(
                asset_alert_list,
                key=lambda a: _parse_timestamp(a.timestamp) or datetime.min
            )

            # Find the LARGEST group within a 15-minute window
            best_group: List[AlertRecord] = []
            for i in range(len(sorted_alerts)):
                group = [sorted_alerts[i]]
                for j in range(i + 1, len(sorted_alerts)):
                    if _alerts_within_window(
                        sorted_alerts[i], sorted_alerts[j], window_minutes=15
                    ):
                        group.append(sorted_alerts[j])
                if len(group) > len(best_group):
                    best_group = group

            if len(best_group) < 3:
                continue

            new_ids = frozenset(a.id for a in best_group)
            if new_ids in existing:
                continue

            # ---- Superset deduplication ----
            # If this new group is a strict superset of an existing
            # multi-signal incident, remove the old (smaller) incident
            # and replace it with the new (larger) one.
            if _db is not None:
                old_incidents = _get_existing_incidents_by_rule(
                    _db, "Multi-Signal Attack in Progress"
                )
                for old_inc in old_incidents:
                    old_ids = frozenset(a.id for a in old_inc.alerts)
                    if old_ids < new_ids:  # strict subset
                        logger.info(
                            "  Replacing subset incident %s (%s) with larger group",
                            old_inc.incident_id[:8], sorted(old_ids)
                        )
                        existing.discard(old_ids)
                        _db.delete(old_inc)
                _db.flush()

            modules_involved = sorted(set(a.module for a in best_group))
            severities = [a.severity for a in best_group]
            escalated = max_severity(*severities)
            if SEVERITY_ORDER.get(escalated, 0) < SEVERITY_ORDER["high"]:
                escalated = "high"

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Multi-Signal Attack in Progress",
                severity=escalated,
                story=(
                    f"🟠 {escalated.upper()} — Multi-Signal Attack Detected\n"
                    f"{len(best_group)} alerts (severity: {', '.join(severities)}) "
                    f"detected on asset '{asset}' within a 15-minute window.\n"
                    f"Modules involved: {', '.join(modules_involved)}.\n"
                    f"Alert IDs: {[a.id for a in best_group]}.\n"
                    f"Multiple security signals converging on the same asset "
                    f"in a short timeframe indicates a coordinated or "
                    f"escalating attack. This may be a multi-vector assault "
                    f"targeting different layers of the application."
                ),
                alerts=list(best_group),
            )
            incidents.append(inc)
        return incidents

    # =========================================================================
    # RULE 4: API Takeover Attempt
    # =========================================================================
    # TRIGGER: API broken authentication alert AND network alert indicating
    #          high-volume failed login attempts (severity >= medium).
    # RATIONALE: Broken auth endpoints combined with brute-force network
    #            traffic strongly suggest an API takeover attempt.
    # One incident per API auth alert (closest network match).
    # =========================================================================
    def rule_4_api_takeover(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        incidents = []
        used_net_ids: Set[int] = set()

        # API alerts related to authentication issues
        api_auth_alerts = [
            a for a in alerts
            if a.module == "api" and (
                "auth" in a.type.lower()
                or "broken_authentication" in a.type.lower()
                or "security_scan" in a.type.lower()
            )
        ]
        # Network alerts showing high-volume / failed login patterns
        network_login_alerts = [
            a for a in alerts
            if a.module == "network" and severity_gte(a.severity, "medium")
        ]

        for api_alert in api_auth_alerts:
            best_net = None
            best_gap = timedelta(days=999)
            for net_alert in network_login_alerts:
                if net_alert.id in used_net_ids:
                    continue
                if api_alert.asset != net_alert.asset:
                    continue
                gap = _time_gap(api_alert, net_alert)
                if gap < best_gap:
                    best_gap = gap
                    best_net = net_alert

            if best_net is None:
                continue

            pair = frozenset([api_alert.id, best_net.id])
            if pair in existing:
                continue

            used_net_ids.add(best_net.id)

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="API Takeover Attempt",
                severity="critical",
                story=(
                    f"🔴 CRITICAL — API Takeover Attempt\n"
                    f"API broken authentication vulnerability "
                    f"(alert #{api_alert.id}) detected alongside "
                    f"high-volume network activity suggesting brute-force "
                    f"login attempts (alert #{best_net.id}) on asset "
                    f"'{api_alert.asset}'.\n"
                    f"An attacker is likely exploiting weak authentication "
                    f"mechanisms while simultaneously conducting credential "
                    f"stuffing or brute-force attacks against the API. "
                    f"Immediate lockdown and credential rotation recommended."
                ),
                alerts=[api_alert, best_net],
            )
            incidents.append(inc)
        return incidents

    # =========================================================================
    # RULE 5: Identity Compromise Risk
    # =========================================================================
    # TRIGGER: Weak password policy alert AND network alert specifically
    #          of type "new_ip_login" or "unusual_access" on the same asset.
    # RATIONALE: Weak credentials + new-IP login = identity compromise.
    # Narrower than Rule 1: requires a NEW IP event, not just any anomaly.
    # One incident per password alert (closest new-IP match).
    # =========================================================================
    def rule_5_identity_compromise(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        incidents = []
        used_net_ids: Set[int] = set()

        password_alerts = [
            a for a in alerts if a.module == "password"
        ]
        # Only new-IP / unusual access network alerts (NOT generic anomalies)
        new_ip_alerts = [
            a for a in alerts
            if a.module == "network" and a.type in (
                "new_ip_login", "unusual_access"
            )
        ]

        for pwd_alert in password_alerts:
            best_net = None
            best_gap = timedelta(days=999)
            for net_alert in new_ip_alerts:
                if net_alert.id in used_net_ids:
                    continue
                if pwd_alert.asset != net_alert.asset:
                    continue
                gap = _time_gap(pwd_alert, net_alert)
                if gap < best_gap:
                    best_gap = gap
                    best_net = net_alert

            if best_net is None:
                continue

            pair = frozenset([pwd_alert.id, best_net.id])
            if pair in existing:
                continue

            used_net_ids.add(best_net.id)

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Identity Compromise Risk",
                severity="high",
                story=(
                    f"🟠 HIGH — Identity Compromise Risk\n"
                    f"Weak password policy (alert #{pwd_alert.id}) "
                    f"combined with a login from a new/unusual IP address "
                    f"(alert #{best_net.id}) on asset '{pwd_alert.asset}'.\n"
                    f"A weak password policy makes credentials easier to "
                    f"guess or brute-force. When combined with access from "
                    f"an unrecognized source, this pattern suggests that "
                    f"a user's identity may have been compromised. "
                    f"Recommend enforcing MFA and password rotation."
                ),
                alerts=[pwd_alert, best_net],
            )
            incidents.append(inc)
        return incidents
