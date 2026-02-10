#!/usr/bin/env python3
# =============================================================================
# SecuriSphere — Phase 3: Correlation Engine
# =============================================================================
#
#  ╔══════════════════════════════════════════════════════════════════╗
#  ║  WHAT THIS FILE DOES                                           ║
#  ║  ──────────────────                                            ║
#  ║  1. Pulls recent alerts from the DB (last 30 minutes)          ║
#  ║  2. Runs 5 correlation rules against them                      ║
#  ║  3. Creates Incident objects with:                              ║
#  ║     • Escalated severity  (e.g. medium+medium → critical)      ║
#  ║     • Human-readable "story" (natural-language explanation)     ║
#  ║     • Grouped alert IDs                                        ║
#  ║  4. Saves new incidents to the database                        ║
#  ║  5. Returns the list of newly created Incidents                ║
#  ╚══════════════════════════════════════════════════════════════════╝
#
#  CORRELATION RULES AT A GLANCE
#  ─────────────────────────────
#  Rule 1 │ Credential Abuse Likely
#         │ Weak password + network anomaly on same asset → CRITICAL
#  Rule 2 │ Recon + Active Exploitation
#         │ Network scanning + API vulnerability on same asset → CRITICAL
#  Rule 3 │ Multi-Signal Attack in Progress
#         │ 3+ medium/high alerts on same asset in 15 min → CRITICAL
#  Rule 4 │ API Takeover Attempt
#         │ API auth flaw + brute-force network traffic → CRITICAL
#  Rule 5 │ Identity Compromise Risk
#         │ Weak password + login from new IP address → HIGH
#
#  DESIGN CHOICES (student notes)
#  ──────────────────────────────
#  • Pure Python loops — no pandas needed, easy to debug
#  • "Best match" pairing — each alert matches its CLOSEST partner
#    (prevents the N×M explosion of incidents)
#  • Superset dedup — if multi-signal group grows, old subset is replaced
#  • Every function is heavily commented for readability
# =============================================================================

import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from sqlalchemy.orm import Session

from backend.database import AlertRecord, IncidentRecord, incident_alerts
from backend.models import SEVERITY_ORDER, max_severity, severity_gte


# ─── Logger ──────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)


# =============================================================================
#  HELPER FUNCTIONS  (small utilities used by the rules below)
# =============================================================================

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Convert an ISO-8601 timestamp string → Python datetime.

    We try several common formats because modules may send timestamps in
    slightly different shapes.  Returns None if nothing works.

    Example:
        >>> parse_timestamp("2026-02-10T07:00:00")
        datetime.datetime(2026, 2, 10, 7, 0)
    """
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",   # 2026-02-10T07:00:00.123456
        "%Y-%m-%dT%H:%M:%S",      # 2026-02-10T07:00:00
        "%Y-%m-%d %H:%M:%S.%f",   # 2026-02-10 07:00:00.123456
        "%Y-%m-%d %H:%M:%S",      # 2026-02-10 07:00:00
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    logger.warning("Could not parse timestamp: %s", ts_str)
    return None


def time_gap_between(alert_a: AlertRecord, alert_b: AlertRecord) -> timedelta:
    """
    Calculate the absolute time difference between two alerts.
    Returns a very large value (999 days) if either timestamp is unparseable,
    so the pair will never be considered "within window".
    """
    ts_a = parse_timestamp(alert_a.timestamp)
    ts_b = parse_timestamp(alert_b.timestamp)
    if ts_a is None or ts_b is None:
        return timedelta(days=999)       # effectively "infinite" gap
    return abs(ts_a - ts_b)


def are_within_window(
    alert_a: AlertRecord,
    alert_b: AlertRecord,
    window_minutes: int = 10,
) -> bool:
    """
    Check if two alerts happened within `window_minutes` of each other.

    Example:
        If alert_a.timestamp = "07:00" and alert_b.timestamp = "07:08",
        are_within_window(a, b, window_minutes=10) → True  (8 min < 10 min)
    """
    return time_gap_between(alert_a, alert_b) <= timedelta(minutes=window_minutes)


def get_recent_alerts(db: Session, minutes: int = 30) -> List[AlertRecord]:
    """
    Fetch alerts from the last `minutes` minutes.

    This is the INPUT to the engine — we only correlate recent activity,
    not the entire history, to keep things fast and relevant.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_str = cutoff.isoformat()

    # SQLAlchemy query: SELECT * FROM alerts WHERE timestamp >= cutoff
    recent = (
        db.query(AlertRecord)
        .filter(AlertRecord.timestamp >= cutoff_str)
        .order_by(AlertRecord.timestamp.asc())
        .all()
    )
    logger.info("Fetched %d alerts from the last %d minutes", len(recent), minutes)
    return recent


def get_existing_incident_sets(db: Session) -> Set[frozenset]:
    """
    Load every existing incident's alert-ID set so we can avoid duplicates.

    For example, if incident X already groups alerts {1, 3}, we store
    frozenset({1, 3}).  Before creating a new incident, we check
    "is this set already in here?"  If yes → skip.
    """
    existing: Set[frozenset] = set()
    for inc in db.query(IncidentRecord).all():
        alert_ids = frozenset(a.id for a in inc.alerts)
        existing.add(alert_ids)
    return existing


def find_incidents_by_rule(db: Session, rule_name: str) -> List[IncidentRecord]:
    """Fetch all existing incidents that were created by a specific rule."""
    return (
        db.query(IncidentRecord)
        .filter(IncidentRecord.rule_name == rule_name)
        .all()
    )


# =============================================================================
#  THE CORRELATION ENGINE  (the main class)
# =============================================================================

class CorrelationEngine:
    """
    Central brain of Phase 3.

    How to use:
        engine = CorrelationEngine()
        new_incidents = engine.run(db_session)
        # new_incidents is a list of IncidentRecord objects just created

    How it works internally:
        1. Pull recent alerts (last 30 min) from the database
        2. Load already-existing incidents (to avoid duplicates)
        3. Loop through each rule function
        4. Each rule returns a list of new IncidentRecord objects
        5. Save them to the DB and return them
    """

    def __init__(self) -> None:
        """
        Register all five correlation rules.
        To add a new rule, simply append another method to this list.
        """
        self.rules = [
            self.rule_1_credential_abuse,
            self.rule_2_recon_exploitation,
            self.rule_3_multi_signal_attack,
            self.rule_4_api_takeover,
            self.rule_5_identity_compromise,
        ]

    # ─────────────────────────────────────────────────────────────────────────
    #  run()  — the main entry point
    # ─────────────────────────────────────────────────────────────────────────
    def run(self, db: Session) -> List[IncidentRecord]:
        """
        Execute ALL correlation rules and return newly created incidents.

        Steps:
            1. Fetch recent alerts from the database (last 30 minutes)
            2. Load existing incident sets to prevent duplicates
            3. Run each rule → collect new IncidentRecords
            4. Persist to DB and return the list
        """
        logger.info("=" * 60)
        logger.info("CORRELATION ENGINE — Starting analysis run")
        logger.info("=" * 60)

        # ── Step 1: Get recent alerts ────────────────────────────────────
        all_alerts = get_recent_alerts(db, minutes=30)
        logger.info("Total recent alerts to analyse: %d", len(all_alerts))

        if not all_alerts:
            logger.info("No recent alerts — nothing to correlate.")
            return []

        # ── Step 2: Load existing incidents ──────────────────────────────
        existing_sets = get_existing_incident_sets(db)
        new_incidents: List[IncidentRecord] = []

        # ── Step 3: Run each rule ────────────────────────────────────────
        for rule_func in self.rules:
            rule_name = rule_func.__name__
            logger.info("Running rule: %s", rule_name)

            try:
                # Rule 3 needs a DB reference for superset deduplication
                if rule_name == "rule_3_multi_signal_attack":
                    incidents = rule_func(all_alerts, existing_sets, db=db)
                else:
                    incidents = rule_func(all_alerts, existing_sets)

                # ── Step 4: Persist each new incident ────────────────────
                for inc in incidents:
                    db.add(inc)
                    db.flush()   # flush so the incident gets an ID
                    alert_ids = frozenset(a.id for a in inc.alerts)
                    existing_sets.add(alert_ids)
                    new_incidents.append(inc)
                    logger.info(
                        "  → NEW INCIDENT: %s | severity=%s | alerts=%s",
                        inc.rule_name,
                        inc.severity,
                        [a.id for a in inc.alerts],
                    )
            except Exception as e:
                logger.error("Error in %s: %s", rule_name, e, exc_info=True)

        # Save everything to disk
        db.commit()

        logger.info(
            "CORRELATION ENGINE — Complete: %d new incident(s) created",
            len(new_incidents),
        )
        return new_incidents


    # =====================================================================
    #  RULE 1 — Credential Abuse Likely
    # =====================================================================
    #
    #  TRIGGER:
    #      Password policy alert  (severity >= medium)
    #      +  Network anomaly     (any severity)
    #      →  on the SAME asset, within 10 minutes
    #
    #  WHY IT MATTERS:
    #      Weak or compromised passwords PLUS abnormal network traffic
    #      strongly suggest someone is actively using stolen credentials.
    #
    #  ESCALATED SEVERITY:  critical
    #
    # =====================================================================
    def rule_1_credential_abuse(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        """
        Pair each password alert with its CLOSEST network anomaly.
        "Closest" = smallest time gap.  One incident per password alert.
        """
        incidents: List[IncidentRecord] = []
        used_network_ids: Set[int] = set()   # track which network alerts are taken

        # ── Step A: Filter alerts by module ──────────────────────────────
        password_alerts = [
            a for a in alerts
            if a.module == "password" and severity_gte(a.severity, "medium")
        ]
        network_alerts = [
            a for a in alerts
            if a.module == "network"
        ]

        # ── Step B: For each password alert, find the BEST network match ─
        for pwd_alert in password_alerts:
            best_match = None
            best_gap = timedelta(days=999)

            for net_alert in network_alerts:
                # Skip if this network alert is already used in this rule
                if net_alert.id in used_network_ids:
                    continue
                # Must be on the same asset
                if pwd_alert.asset != net_alert.asset:
                    continue
                # Must be within 10 minutes
                gap = time_gap_between(pwd_alert, net_alert)
                if gap <= timedelta(minutes=10) and gap < best_gap:
                    best_gap = gap
                    best_match = net_alert

            # No matching network alert found?  Skip this password alert.
            if best_match is None:
                continue

            # ── Step C: Check for duplicates ─────────────────────────────
            pair = frozenset([pwd_alert.id, best_match.id])
            if pair in existing:
                continue   # Already created in a previous run

            # Mark the network alert as "used" so it doesn't pair again
            used_network_ids.add(best_match.id)

            # ── Step D: Build the Incident ───────────────────────────────
            story = (
                f"🔴 CRITICAL — Credential Abuse Likely\n"
                f"\n"
                f"What happened:\n"
                f"  • A weak/compromised password policy was flagged "
                f"(alert #{pwd_alert.id}, severity: {pwd_alert.severity})\n"
                f"  • Abnormal network traffic was detected "
                f"(alert #{best_match.id}, severity: {best_match.severity})\n"
                f"  • Both events hit the SAME asset: '{pwd_alert.asset}'\n"
                f"  • Time gap between events: {best_gap.total_seconds():.0f} seconds\n"
                f"\n"
                f"Why this is critical:\n"
                f"  An attacker likely obtained valid credentials through "
                f"policy weaknesses and is now conducting unauthorized access. "
                f"The network anomaly may represent data exfiltration or "
                f"lateral movement using the compromised account.\n"
                f"\n"
                f"Recommended action:\n"
                f"  Immediately rotate credentials on '{pwd_alert.asset}', "
                f"enable MFA, and review access logs for unauthorised sessions."
            )

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Credential Abuse Likely",
                severity="critical",
                story=story,
                alerts=[pwd_alert, best_match],
            )
            incidents.append(inc)

        return incidents


    # =====================================================================
    #  RULE 2 — Recon + Active Exploitation
    # =====================================================================
    #
    #  TRIGGER:
    #      Network anomaly  (reconnaissance / scanning activity)
    #      +  API vulnerability  (exploitable weakness found)
    #      →  on the SAME asset
    #
    #  WHY IT MATTERS:
    #      This is the classic attack pattern: scan first, exploit second.
    #      Network recon + an API vuln on the same target means an attacker
    #      found weaknesses and is actively exploiting them.
    #
    #  ESCALATED SEVERITY:  critical
    #
    # =====================================================================
    def rule_2_recon_exploitation(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        """
        Pair each API vulnerability alert with its closest network anomaly.
        One incident per API alert.
        """
        incidents: List[IncidentRecord] = []
        used_network_ids: Set[int] = set()

        network_alerts = [a for a in alerts if a.module == "network"]
        api_alerts     = [a for a in alerts if a.module == "api"]

        for api_alert in api_alerts:
            best_match = None
            best_gap = timedelta(days=999)

            for net_alert in network_alerts:
                if net_alert.id in used_network_ids:
                    continue
                if net_alert.asset != api_alert.asset:
                    continue
                gap = time_gap_between(api_alert, net_alert)
                if gap < best_gap:
                    best_gap = gap
                    best_match = net_alert

            if best_match is None:
                continue

            pair = frozenset([best_match.id, api_alert.id])
            if pair in existing:
                continue

            used_network_ids.add(best_match.id)

            story = (
                f"🔴 CRITICAL — Reconnaissance + Active Exploitation\n"
                f"\n"
                f"What happened:\n"
                f"  • Network anomaly detected (alert #{best_match.id}) — "
                f"likely port scanning or service enumeration\n"
                f"  • API vulnerability found (alert #{api_alert.id}, "
                f"type: {api_alert.type}) — an exploitable weakness\n"
                f"  • Both target the same asset: '{best_match.asset}'\n"
                f"\n"
                f"Why this is critical:\n"
                f"  This is the classic two-stage attack pattern. The attacker "
                f"first scanned the network to discover services, then "
                f"exploited a known API vulnerability. The combination "
                f"indicates an active, targeted intrusion — not a random probe.\n"
                f"\n"
                f"Recommended action:\n"
                f"  Patch the API vulnerability immediately, review firewall "
                f"rules, and check for any data accessed during the window."
            )

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Recon + Active Exploitation",
                severity="critical",
                story=story,
                alerts=[best_match, api_alert],
            )
            incidents.append(inc)

        return incidents


    # =====================================================================
    #  RULE 3 — Multi-Signal Attack in Progress
    # =====================================================================
    #
    #  TRIGGER:
    #      3 or more alerts with severity >= medium
    #      on the SAME asset, within a 15-minute window
    #
    #  WHY IT MATTERS:
    #      Multiple security signals converging on one target in a short
    #      time = coordinated multi-vector attack (or rapid escalation).
    #
    #  ESCALATED SEVERITY:  max(all severities), minimum "high"
    #
    #  SPECIAL LOGIC:
    #      Only ONE incident per asset (the largest group).
    #      If a previous run created a smaller group, it's replaced.
    #
    # =====================================================================
    def rule_3_multi_signal_attack(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
        db: Optional[Session] = None,
    ) -> List[IncidentRecord]:
        """
        Find the largest cluster of medium+ alerts per asset, all within
        a 15-minute window.  Replace smaller subsets from prior runs.
        """
        incidents: List[IncidentRecord] = []

        # ── Step A: Group medium+ alerts by asset ────────────────────────
        # Example: {"victim-app:8000": [alert1, alert3, alert5, ...]}
        asset_buckets: Dict[str, List[AlertRecord]] = {}
        for a in alerts:
            if severity_gte(a.severity, "medium"):
                asset_buckets.setdefault(a.asset, []).append(a)

        # ── Step B: For each asset, find the biggest 15-min group ────────
        for asset, bucket in asset_buckets.items():
            if len(bucket) < 3:
                continue  # Need at least 3 alerts to trigger

            # Sort by time so we can do a sliding-window scan
            bucket.sort(key=lambda a: parse_timestamp(a.timestamp) or datetime.min)

            # Sliding window: anchor on each alert, extend as far as 15 min allows
            best_group: List[AlertRecord] = []
            for i in range(len(bucket)):
                group = [bucket[i]]
                for j in range(i + 1, len(bucket)):
                    if are_within_window(bucket[i], bucket[j], window_minutes=15):
                        group.append(bucket[j])
                if len(group) > len(best_group):
                    best_group = group

            if len(best_group) < 3:
                continue

            new_ids = frozenset(a.id for a in best_group)
            if new_ids in existing:
                continue   # Exact same group already exists

            # ── Step C: Superset deduplication ───────────────────────────
            # If this new group is BIGGER than an old multi-signal incident,
            # delete the old one (it's a strict subset).
            if db is not None:
                old_incidents = find_incidents_by_rule(
                    db, "Multi-Signal Attack in Progress"
                )
                for old_inc in old_incidents:
                    old_ids = frozenset(a.id for a in old_inc.alerts)
                    if old_ids < new_ids:      # old is a strict subset
                        logger.info(
                            "  Replacing old subset incident %s (alerts %s) "
                            "with larger group (alerts %s)",
                            old_inc.incident_id[:8],
                            sorted(old_ids),
                            sorted(new_ids),
                        )
                        existing.discard(old_ids)
                        db.delete(old_inc)
                db.flush()

            # ── Step D: Build the incident ───────────────────────────────
            modules_involved = sorted(set(a.module for a in best_group))
            severities = [a.severity for a in best_group]
            escalated = max_severity(*severities)
            # Floor at "high" — 3+ signals always warrants at least HIGH
            if SEVERITY_ORDER.get(escalated, 0) < SEVERITY_ORDER["high"]:
                escalated = "high"

            story = (
                f"🟠 {escalated.upper()} — Multi-Signal Attack Detected\n"
                f"\n"
                f"What happened:\n"
                f"  • {len(best_group)} security alerts fired on asset "
                f"'{asset}' within a 15-minute window\n"
                f"  • Modules involved: {', '.join(modules_involved)}\n"
                f"  • Severity levels: {', '.join(severities)}\n"
                f"  • Alert IDs: {[a.id for a in best_group]}\n"
                f"\n"
                f"Why this is {escalated}:\n"
                f"  Multiple independent security signals converging on "
                f"the same asset in a short timeframe is a strong indicator "
                f"of a coordinated attack. The attacker may be launching a "
                f"multi-vector assault targeting network, API, and "
                f"credential layers simultaneously.\n"
                f"\n"
                f"Recommended action:\n"
                f"  Initiate incident response. Isolate the affected asset, "
                f"review all {len(best_group)} alerts in sequence, and "
                f"determine the attack timeline."
            )

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Multi-Signal Attack in Progress",
                severity=escalated,
                story=story,
                alerts=list(best_group),
            )
            incidents.append(inc)

        return incidents


    # =====================================================================
    #  RULE 4 — API Takeover Attempt
    # =====================================================================
    #
    #  TRIGGER:
    #      API authentication vulnerability alert
    #      +  Network alert with severity >= medium (brute-force traffic)
    #      →  on the SAME asset
    #
    #  WHY IT MATTERS:
    #      Broken auth + brute-force = someone is actively trying to
    #      take over the API by exploiting weak authentication.
    #
    #  ESCALATED SEVERITY:  critical
    #
    # =====================================================================
    def rule_4_api_takeover(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        """
        Pair each API auth alert with the closest medium+ network alert.
        """
        incidents: List[IncidentRecord] = []
        used_network_ids: Set[int] = set()

        # API alerts about authentication problems
        api_auth_alerts = [
            a for a in alerts
            if a.module == "api" and (
                "auth" in a.type.lower()
                or "broken_authentication" in a.type.lower()
                or "security_scan" in a.type.lower()
            )
        ]
        # Network alerts showing brute-force / high-volume patterns
        network_bruteforce_alerts = [
            a for a in alerts
            if a.module == "network" and severity_gte(a.severity, "medium")
        ]

        for api_alert in api_auth_alerts:
            best_match = None
            best_gap = timedelta(days=999)

            for net_alert in network_bruteforce_alerts:
                if net_alert.id in used_network_ids:
                    continue
                if api_alert.asset != net_alert.asset:
                    continue
                gap = time_gap_between(api_alert, net_alert)
                if gap < best_gap:
                    best_gap = gap
                    best_match = net_alert

            if best_match is None:
                continue

            pair = frozenset([api_alert.id, best_match.id])
            if pair in existing:
                continue

            used_network_ids.add(best_match.id)

            story = (
                f"🔴 CRITICAL — API Takeover Attempt\n"
                f"\n"
                f"What happened:\n"
                f"  • API broken authentication vulnerability detected "
                f"(alert #{api_alert.id})\n"
                f"  • High-volume network activity suggesting brute-force "
                f"login attempts (alert #{best_match.id})\n"
                f"  • Both on asset: '{api_alert.asset}'\n"
                f"\n"
                f"Why this is critical:\n"
                f"  An attacker is exploiting weak authentication mechanisms "
                f"while simultaneously running credential stuffing or "
                f"brute-force attacks against the API endpoints. This is "
                f"an active takeover attempt, not passive scanning.\n"
                f"\n"
                f"Recommended action:\n"
                f"  Lock down authentication endpoints, enable rate limiting, "
                f"rotate API keys and credentials, and review access logs "
                f"for any successful unauthorized logins."
            )

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="API Takeover Attempt",
                severity="critical",
                story=story,
                alerts=[api_alert, best_match],
            )
            incidents.append(inc)

        return incidents


    # =====================================================================
    #  RULE 5 — Identity Compromise Risk
    # =====================================================================
    #
    #  TRIGGER:
    #      Any password policy alert
    #      +  Network alert of type "new_ip_login" or "unusual_access"
    #      →  on the SAME asset
    #
    #  WHY IT MATTERS:
    #      If the password is weak AND someone logs in from a brand-new
    #      IP address, the account is likely compromised.
    #
    #  NOTE:  This is narrower than Rule 1.  Rule 1 matches any network
    #         anomaly; Rule 5 specifically requires a "new IP" event.
    #
    #  ESCALATED SEVERITY:  high
    #
    # =====================================================================
    def rule_5_identity_compromise(
        self,
        alerts: List[AlertRecord],
        existing: Set[frozenset],
    ) -> List[IncidentRecord]:
        """
        Pair each password alert with the closest new-IP network alert.
        """
        incidents: List[IncidentRecord] = []
        used_network_ids: Set[int] = set()

        password_alerts = [a for a in alerts if a.module == "password"]

        # Only match network alerts that specifically indicate a new IP login
        new_ip_alerts = [
            a for a in alerts
            if a.module == "network"
            and a.type in ("new_ip_login", "unusual_access")
        ]

        for pwd_alert in password_alerts:
            best_match = None
            best_gap = timedelta(days=999)

            for net_alert in new_ip_alerts:
                if net_alert.id in used_network_ids:
                    continue
                if pwd_alert.asset != net_alert.asset:
                    continue
                gap = time_gap_between(pwd_alert, net_alert)
                if gap < best_gap:
                    best_gap = gap
                    best_match = net_alert

            if best_match is None:
                continue

            pair = frozenset([pwd_alert.id, best_match.id])
            if pair in existing:
                continue

            used_network_ids.add(best_match.id)

            story = (
                f"🟠 HIGH — Identity Compromise Risk\n"
                f"\n"
                f"What happened:\n"
                f"  • Weak password policy detected (alert #{pwd_alert.id})\n"
                f"  • Login from a new/unusual IP address "
                f"(alert #{best_match.id}, type: {best_match.type})\n"
                f"  • Both on asset: '{pwd_alert.asset}'\n"
                f"\n"
                f"Why this is high severity:\n"
                f"  A weak password makes credentials easy to guess or "
                f"brute-force.  When combined with a login from an "
                f"unrecognised IP address, this strongly suggests that "
                f"a user's account has been compromised by an external actor.\n"
                f"\n"
                f"Recommended action:\n"
                f"  Enforce MFA immediately, force a password rotation, "
                f"and investigate the login source IP for geo-location anomalies."
            )

            inc = IncidentRecord(
                incident_id=str(uuid.uuid4()),
                rule_name="Identity Compromise Risk",
                severity="high",
                story=story,
                alerts=[pwd_alert, best_match],
            )
            incidents.append(inc)

        return incidents
