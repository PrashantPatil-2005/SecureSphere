#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - Password Policy Auditor
# =============================================================================
"""
Password Policy Auditing Module

Reads password policies from configuration files and checks them against
security standards (NIST SP 800-63B and industry best practices).

Features:
- Parse config files with key=value policy definitions
- Check against NIST-like standards (length >= 12, complexity, etc.)
- Compute compliance score and issues list
- Generate JSON alerts for policy violations
- Optional LDAP integration for OpenLDAP password policy queries

Usage:
    # Audit a policy config file
    python auditor.py --config /path/to/password.conf
    
    # Audit with LDAP query (if OpenLDAP running)
    python auditor.py --ldap-uri ldap://localhost --base-dn "dc=example,dc=com"
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# =============================================================================
# NIST SP 800-63B and Industry Best Practice Standards
# =============================================================================

@dataclass
class SecurityStandard:
    """Defines a security standard for password policies."""
    name: str
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = False  # NIST no longer recommends forced complexity
    require_lowercase: bool = False
    require_digits: bool = False
    require_special: bool = False
    max_age_days: int = 0  # 0 = no forced rotation (NIST recommendation)
    min_age_days: int = 0
    history_count: int = 0  # 0 = no history requirement
    lockout_threshold: int = 10
    lockout_duration_minutes: int = 30
    allow_common_passwords: bool = False
    require_mfa: bool = True
    description: str = ""


# Predefined security standards
NIST_800_63B = SecurityStandard(
    name="NIST SP 800-63B",
    min_length=8,  # NIST minimum, but 12+ recommended
    max_length=64,
    require_uppercase=False,
    require_lowercase=False,
    require_digits=False,
    require_special=False,
    max_age_days=0,  # No forced rotation
    history_count=0,
    lockout_threshold=100,  # NIST allows high threshold with rate limiting
    lockout_duration_minutes=0,
    allow_common_passwords=False,
    require_mfa=True,
    description="NIST Digital Identity Guidelines - moderate security"
)

NIST_800_63B_STRICT = SecurityStandard(
    name="NIST SP 800-63B (Strict)",
    min_length=12,
    max_length=128,
    require_uppercase=False,
    require_lowercase=False,
    require_digits=False,
    require_special=False,
    max_age_days=0,
    history_count=0,
    lockout_threshold=10,
    lockout_duration_minutes=30,
    allow_common_passwords=False,
    require_mfa=True,
    description="NIST Digital Identity Guidelines - high security"
)

INDUSTRY_BEST_PRACTICE = SecurityStandard(
    name="Industry Best Practice",
    min_length=12,
    max_length=128,
    require_uppercase=True,
    require_lowercase=True,
    require_digits=True,
    require_special=True,
    max_age_days=90,
    min_age_days=1,
    history_count=12,
    lockout_threshold=5,
    lockout_duration_minutes=30,
    allow_common_passwords=False,
    require_mfa=True,
    description="Traditional enterprise security requirements"
)

AVAILABLE_STANDARDS = {
    "nist": NIST_800_63B,
    "nist-strict": NIST_800_63B_STRICT,
    "industry": INDUSTRY_BEST_PRACTICE
}


# =============================================================================
# Policy Configuration Parser
# =============================================================================

@dataclass
class PasswordPolicy:
    """Represents a parsed password policy configuration."""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digits: bool = False
    require_special: bool = False
    max_age_days: int = 90
    min_age_days: int = 0
    history_count: int = 5
    lockout_threshold: int = 5
    lockout_duration_minutes: int = 30
    allow_common_passwords: bool = False
    require_mfa: bool = False
    source: str = "config"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return asdict(self)


class PolicyConfigParser:
    """
    Parser for password policy configuration files.
    
    Supports key=value format with the following keys:
    - minlen / min_length: Minimum password length
    - maxlen / max_length: Maximum password length
    - require_upper / ucredit: Require uppercase letters
    - require_lower / lcredit: Require lowercase letters
    - require_digit / dcredit: Require digits
    - require_special / ocredit: Require special characters
    - max_age / maxage: Maximum password age in days
    - min_age / minage: Minimum password age in days
    - history / remember: Number of passwords to remember
    - lockout_threshold / deny: Failed attempts before lockout
    - lockout_duration / unlock_time: Lockout duration in minutes
    - allow_common / dictcheck: Allow common passwords
    - require_mfa / mfa: Require multi-factor authentication
    """
    
    # Mapping of config keys to policy attributes
    KEY_MAPPING = {
        # Length
        "minlen": "min_length",
        "min_length": "min_length",
        "minlength": "min_length",
        "maxlen": "max_length",
        "max_length": "max_length",
        "maxlength": "max_length",
        # Complexity
        "require_upper": "require_uppercase",
        "ucredit": "require_uppercase",
        "uppercase": "require_uppercase",
        "require_lower": "require_lowercase",
        "lcredit": "require_lowercase",
        "lowercase": "require_lowercase",
        "require_digit": "require_digits",
        "dcredit": "require_digits",
        "digits": "require_digits",
        "require_special": "require_special",
        "ocredit": "require_special",
        "special": "require_special",
        # Age
        "max_age": "max_age_days",
        "maxage": "max_age_days",
        "password_max_age": "max_age_days",
        "min_age": "min_age_days",
        "minage": "min_age_days",
        "password_min_age": "min_age_days",
        # History
        "history": "history_count",
        "remember": "history_count",
        "password_history": "history_count",
        # Lockout
        "lockout_threshold": "lockout_threshold",
        "deny": "lockout_threshold",
        "fail_attempts": "lockout_threshold",
        "lockout_duration": "lockout_duration_minutes",
        "unlock_time": "lockout_duration_minutes",
        "lockout_time": "lockout_duration_minutes",
        # Other
        "allow_common": "allow_common_passwords",
        "dictcheck": "allow_common_passwords",
        "require_mfa": "require_mfa",
        "mfa": "require_mfa",
    }
    
    # Values that represent "yes/true"
    TRUE_VALUES = {"yes", "true", "1", "on", "enabled", "require"}
    FALSE_VALUES = {"no", "false", "0", "off", "disabled"}
    
    def __init__(self, config_path: str):
        """
        Initialize the parser.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = Path(config_path)
        
    def parse(self) -> PasswordPolicy:
        """
        Parse the configuration file.
        
        Returns:
            PasswordPolicy object with parsed settings
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If parsing fails
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        logger.info(f"Parsing policy config: {self.config_path}")
        
        policy = PasswordPolicy(source=str(self.config_path))
        
        try:
            with open(self.config_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    
                    # Parse key=value
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        self._apply_setting(policy, key, value, line_num)
                    else:
                        logger.warning(f"Line {line_num}: Invalid format, skipping: {line}")
            
            logger.info(f"Parsed policy: min_length={policy.min_length}, complexity requirements set")
            return policy
            
        except Exception as e:
            logger.error(f"Failed to parse config: {e}")
            raise ValueError(f"Failed to parse config: {e}")
    
    def _apply_setting(self, policy: PasswordPolicy, key: str, value: str, line_num: int) -> None:
        """Apply a single setting to the policy."""
        # Map the key to policy attribute
        attr = self.KEY_MAPPING.get(key)
        
        if not attr:
            logger.debug(f"Line {line_num}: Unknown key '{key}', skipping")
            return
        
        # Determine the type and convert value
        current_value = getattr(policy, attr)
        
        if isinstance(current_value, bool):
            # Boolean conversion
            value_lower = value.lower()
            if value_lower in self.TRUE_VALUES:
                setattr(policy, attr, True)
            elif value_lower in self.FALSE_VALUES:
                setattr(policy, attr, False)
            else:
                # PAM-style: negative values mean required (e.g., ucredit=-1)
                try:
                    int_val = int(value)
                    setattr(policy, attr, int_val < 0)
                except ValueError:
                    logger.warning(f"Line {line_num}: Invalid boolean value '{value}' for '{key}'")
        
        elif isinstance(current_value, int):
            # Integer conversion
            try:
                # Handle PAM-style negative values (absolute value)
                int_val = abs(int(value))
                setattr(policy, attr, int_val)
            except ValueError:
                logger.warning(f"Line {line_num}: Invalid integer value '{value}' for '{key}'")


# =============================================================================
# Password Policy Auditor
# =============================================================================

@dataclass
class AuditIssue:
    """Represents a single audit issue/finding."""
    category: str
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    recommendation: str
    standard_reference: str = ""
    current_value: Any = None
    recommended_value: Any = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to dictionary."""
        return asdict(self)


@dataclass
class AuditResult:
    """Results of a password policy audit."""
    policy: PasswordPolicy
    standard: SecurityStandard
    score: int  # 0-100
    grade: str  # A, B, C, D, F
    issues: List[AuditIssue] = field(default_factory=list)
    compliant: bool = False
    audit_timestamp: str = ""
    
    def __post_init__(self):
        if not self.audit_timestamp:
            self.audit_timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "policy": self.policy.to_dict(),
            "standard": asdict(self.standard),
            "score": self.score,
            "grade": self.grade,
            "compliant": self.compliant,
            "issues_count": len(self.issues),
            "issues_by_severity": {
                "critical": sum(1 for i in self.issues if i.severity == "critical"),
                "high": sum(1 for i in self.issues if i.severity == "high"),
                "medium": sum(1 for i in self.issues if i.severity == "medium"),
                "low": sum(1 for i in self.issues if i.severity == "low"),
                "info": sum(1 for i in self.issues if i.severity == "info"),
            },
            "issues": [i.to_dict() for i in self.issues],
            "audit_timestamp": self.audit_timestamp
        }


class PasswordPolicyAuditor:
    """
    Audits password policies against security standards.
    
    Checks policies for compliance with NIST SP 800-63B and
    industry best practices, computing a compliance score and
    identifying security issues.
    """
    
    # Scoring weights for different categories
    SCORE_WEIGHTS = {
        "length": 25,
        "complexity": 15,
        "rotation": 10,
        "lockout": 20,
        "history": 10,
        "mfa": 15,
        "common_passwords": 5,
    }
    
    def __init__(self, standard: str = "nist-strict"):
        """
        Initialize the auditor.
        
        Args:
            standard: Security standard to audit against
                     ("nist", "nist-strict", "industry")
        """
        if standard not in AVAILABLE_STANDARDS:
            raise ValueError(f"Unknown standard: {standard}. Available: {list(AVAILABLE_STANDARDS.keys())}")
        
        self.standard = AVAILABLE_STANDARDS[standard]
        logger.info(f"Using security standard: {self.standard.name}")
    
    def audit_config(self, config_path: str) -> AuditResult:
        """
        Audit a password policy from a configuration file.
        
        Args:
            config_path: Path to policy configuration file
            
        Returns:
            AuditResult with score, grade, and issues
        """
        parser = PolicyConfigParser(config_path)
        policy = parser.parse()
        return self.audit_policy(policy)
    
    def audit_policy(self, policy: PasswordPolicy) -> AuditResult:
        """
        Audit a password policy against the security standard.
        
        Args:
            policy: PasswordPolicy object to audit
            
        Returns:
            AuditResult with score, grade, and issues
        """
        logger.info("Starting password policy audit...")
        
        issues: List[AuditIssue] = []
        scores: Dict[str, int] = {}
        
        # Check each category
        scores["length"] = self._check_length(policy, issues)
        scores["complexity"] = self._check_complexity(policy, issues)
        scores["rotation"] = self._check_rotation(policy, issues)
        scores["lockout"] = self._check_lockout(policy, issues)
        scores["history"] = self._check_history(policy, issues)
        scores["mfa"] = self._check_mfa(policy, issues)
        scores["common_passwords"] = self._check_common_passwords(policy, issues)
        
        # Calculate total score
        total_score = 0
        for category, score in scores.items():
            weight = self.SCORE_WEIGHTS.get(category, 0)
            total_score += (score / 100) * weight
        
        total_score = int(total_score)
        
        # Determine grade
        grade = self._calculate_grade(total_score, issues)
        
        # Check overall compliance (no critical or high issues)
        critical_high_count = sum(1 for i in issues if i.severity in ("critical", "high"))
        compliant = critical_high_count == 0 and total_score >= 70
        
        result = AuditResult(
            policy=policy,
            standard=self.standard,
            score=total_score,
            grade=grade,
            issues=issues,
            compliant=compliant
        )
        
        logger.info(f"Audit complete: Score={total_score}, Grade={grade}, Issues={len(issues)}")
        return result
    
    def _check_length(self, policy: PasswordPolicy, issues: List[AuditIssue]) -> int:
        """Check password length requirements."""
        score = 100
        
        # Minimum length check
        if policy.min_length < self.standard.min_length:
            severity = "critical" if policy.min_length < 8 else "high"
            score -= 50 if severity == "critical" else 30
            
            issues.append(AuditIssue(
                category="length",
                severity=severity,
                title="Minimum password length too short",
                description=f"Current minimum length ({policy.min_length}) is below the recommended minimum ({self.standard.min_length}).",
                recommendation=f"Increase minimum password length to at least {self.standard.min_length} characters.",
                standard_reference=f"{self.standard.name}: Minimum {self.standard.min_length} characters",
                current_value=policy.min_length,
                recommended_value=self.standard.min_length
            ))
        elif policy.min_length < 12:
            score -= 10
            issues.append(AuditIssue(
                category="length",
                severity="medium",
                title="Minimum password length could be stronger",
                description=f"Current minimum length ({policy.min_length}) meets basic requirements but 12+ is recommended.",
                recommendation="Consider increasing minimum password length to 12 or more characters.",
                standard_reference="Industry best practice: 12+ characters",
                current_value=policy.min_length,
                recommended_value=12
            ))
        
        # Maximum length check (should allow long passwords)
        if policy.max_length < 64:
            score -= 20
            issues.append(AuditIssue(
                category="length",
                severity="medium",
                title="Maximum password length too restrictive",
                description=f"Current maximum length ({policy.max_length}) may prevent use of passphrases.",
                recommendation="Allow passwords up to at least 64 characters to support passphrases.",
                standard_reference=f"{self.standard.name}: Support at least {self.standard.max_length} characters",
                current_value=policy.max_length,
                recommended_value=self.standard.max_length
            ))
        
        return max(0, score)
    
    def _check_complexity(self, policy: PasswordPolicy, issues: List[AuditIssue]) -> int:
        """Check password complexity requirements."""
        score = 100
        
        # Note: NIST no longer recommends forced complexity rules
        # However, if standard requires them, we check
        
        if self.standard.name == "Industry Best Practice":
            # Industry standard requires complexity
            missing = []
            if self.standard.require_uppercase and not policy.require_uppercase:
                missing.append("uppercase")
            if self.standard.require_lowercase and not policy.require_lowercase:
                missing.append("lowercase")
            if self.standard.require_digits and not policy.require_digits:
                missing.append("digits")
            if self.standard.require_special and not policy.require_special:
                missing.append("special characters")
            
            if missing:
                score -= len(missing) * 15
                issues.append(AuditIssue(
                    category="complexity",
                    severity="medium",
                    title="Missing complexity requirements",
                    description=f"Policy does not require: {', '.join(missing)}.",
                    recommendation="Enable complexity requirements for character types.",
                    standard_reference=f"{self.standard.name}: Require mixed character types",
                    current_value=f"Missing: {', '.join(missing)}",
                    recommended_value="All character types required"
                ))
        else:
            # NIST approach: complexity not required, but check for overly strict rules
            enforced = []
            if policy.require_uppercase:
                enforced.append("uppercase")
            if policy.require_lowercase:
                enforced.append("lowercase")
            if policy.require_digits:
                enforced.append("digits")
            if policy.require_special:
                enforced.append("special")
            
            if len(enforced) >= 3:
                issues.append(AuditIssue(
                    category="complexity",
                    severity="info",
                    title="Complexity rules may be counterproductive",
                    description=f"Policy enforces multiple character types: {', '.join(enforced)}. NIST no longer recommends this.",
                    recommendation="Consider removing composition rules and focusing on length and breach detection.",
                    standard_reference="NIST SP 800-63B: No composition rules recommended",
                    current_value=f"Required: {', '.join(enforced)}",
                    recommended_value="Focus on length over complexity"
                ))
        
        return max(0, score)
    
    def _check_rotation(self, policy: PasswordPolicy, issues: List[AuditIssue]) -> int:
        """Check password rotation/age requirements."""
        score = 100
        
        # NIST recommends no periodic rotation
        if self.standard.max_age_days == 0:
            if policy.max_age_days > 0 and policy.max_age_days < 365:
                issues.append(AuditIssue(
                    category="rotation",
                    severity="info",
                    title="Periodic password rotation enforced",
                    description=f"Policy requires password change every {policy.max_age_days} days. NIST no longer recommends periodic rotation.",
                    recommendation="Consider removing periodic rotation and only require change on evidence of compromise.",
                    standard_reference="NIST SP 800-63B: No periodic rotation",
                    current_value=f"{policy.max_age_days} days",
                    recommended_value="No forced rotation"
                ))
        else:
            # Industry standard expects rotation
            if policy.max_age_days == 0:
                score -= 30
                issues.append(AuditIssue(
                    category="rotation",
                    severity="medium",
                    title="No password expiration policy",
                    description="Passwords never expire, which may not meet compliance requirements.",
                    recommendation=f"Consider implementing password expiration (e.g., every {self.standard.max_age_days} days).",
                    standard_reference=f"{self.standard.name}: {self.standard.max_age_days} day maximum age",
                    current_value="Never expires",
                    recommended_value=f"{self.standard.max_age_days} days"
                ))
            elif policy.max_age_days > self.standard.max_age_days:
                score -= 15
                issues.append(AuditIssue(
                    category="rotation",
                    severity="low",
                    title="Password expiration period too long",
                    description=f"Password expires after {policy.max_age_days} days, longer than recommended.",
                    recommendation=f"Reduce password expiration to {self.standard.max_age_days} days or less.",
                    standard_reference=f"{self.standard.name}: {self.standard.max_age_days} day maximum age",
                    current_value=f"{policy.max_age_days} days",
                    recommended_value=f"{self.standard.max_age_days} days"
                ))
        
        return max(0, score)
    
    def _check_lockout(self, policy: PasswordPolicy, issues: List[AuditIssue]) -> int:
        """Check account lockout settings."""
        score = 100
        
        # Lockout threshold check
        if policy.lockout_threshold == 0:
            score -= 50
            issues.append(AuditIssue(
                category="lockout",
                severity="critical",
                title="No account lockout configured",
                description="Accounts are not locked after failed login attempts, allowing unlimited brute force attacks.",
                recommendation=f"Configure account lockout after {self.standard.lockout_threshold} failed attempts.",
                standard_reference=f"{self.standard.name}: Lockout after {self.standard.lockout_threshold} failures",
                current_value="Disabled",
                recommended_value=f"{self.standard.lockout_threshold} attempts"
            ))
        elif policy.lockout_threshold > self.standard.lockout_threshold * 2:
            score -= 20
            issues.append(AuditIssue(
                category="lockout",
                severity="medium",
                title="Lockout threshold too high",
                description=f"Account locks after {policy.lockout_threshold} failures, which may be too permissive.",
                recommendation=f"Reduce lockout threshold to {self.standard.lockout_threshold} or fewer attempts.",
                standard_reference=f"{self.standard.name}: {self.standard.lockout_threshold} attempt threshold",
                current_value=f"{policy.lockout_threshold} attempts",
                recommended_value=f"{self.standard.lockout_threshold} attempts"
            ))
        
        # Lockout duration check
        if policy.lockout_threshold > 0 and policy.lockout_duration_minutes == 0:
            issues.append(AuditIssue(
                category="lockout",
                severity="info",
                title="Permanent lockout configured",
                description="Locked accounts require administrator intervention to unlock.",
                recommendation="Consider implementing timed lockout for better user experience.",
                standard_reference="Best practice: Temporary lockout with progressive delays",
                current_value="Permanent",
                recommended_value=f"{self.standard.lockout_duration_minutes} minutes"
            ))
        
        return max(0, score)
    
    def _check_history(self, policy: PasswordPolicy, issues: List[AuditIssue]) -> int:
        """Check password history settings."""
        score = 100
        
        if self.standard.history_count > 0:
            if policy.history_count == 0:
                score -= 40
                issues.append(AuditIssue(
                    category="history",
                    severity="high",
                    title="No password history enforcement",
                    description="Users can reuse previous passwords immediately.",
                    recommendation=f"Enforce password history of at least {self.standard.history_count} passwords.",
                    standard_reference=f"{self.standard.name}: Remember {self.standard.history_count} passwords",
                    current_value="Disabled",
                    recommended_value=f"{self.standard.history_count} passwords"
                ))
            elif policy.history_count < self.standard.history_count:
                score -= 20
                issues.append(AuditIssue(
                    category="history",
                    severity="medium",
                    title="Password history too short",
                    description=f"Only {policy.history_count} passwords remembered, users may cycle through quickly.",
                    recommendation=f"Increase password history to {self.standard.history_count} passwords.",
                    standard_reference=f"{self.standard.name}: Remember {self.standard.history_count} passwords",
                    current_value=f"{policy.history_count} passwords",
                    recommended_value=f"{self.standard.history_count} passwords"
                ))
        
        return max(0, score)
    
    def _check_mfa(self, policy: PasswordPolicy, issues: List[AuditIssue]) -> int:
        """Check multi-factor authentication requirement."""
        score = 100
        
        if self.standard.require_mfa and not policy.require_mfa:
            score -= 50
            issues.append(AuditIssue(
                category="mfa",
                severity="high",
                title="Multi-factor authentication not required",
                description="MFA is not enforced, leaving accounts vulnerable to credential theft.",
                recommendation="Require multi-factor authentication for all users.",
                standard_reference=f"{self.standard.name}: MFA required",
                current_value="Not required",
                recommended_value="Required"
            ))
        
        return max(0, score)
    
    def _check_common_passwords(self, policy: PasswordPolicy, issues: List[AuditIssue]) -> int:
        """Check common password/dictionary checking."""
        score = 100
        
        if not self.standard.allow_common_passwords and policy.allow_common_passwords:
            score -= 40
            issues.append(AuditIssue(
                category="common_passwords",
                severity="high",
                title="Common password checking disabled",
                description="Users can set easily guessed passwords from common password lists.",
                recommendation="Enable dictionary/common password checking.",
                standard_reference=f"{self.standard.name}: Block common passwords",
                current_value="Allowed",
                recommended_value="Blocked"
            ))
        
        return max(0, score)
    
    def _calculate_grade(self, score: int, issues: List[AuditIssue]) -> str:
        """Calculate letter grade based on score and issues."""
        # Critical issues automatically lower grade
        critical_count = sum(1 for i in issues if i.severity == "critical")
        high_count = sum(1 for i in issues if i.severity == "high")
        
        if critical_count > 0:
            return "F"
        elif high_count >= 3:
            return "D"
        elif score >= 90 and high_count == 0:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def generate_alert(self, result: AuditResult) -> Dict[str, Any]:
        """
        Generate a JSON alert for audit results.
        
        Args:
            result: AuditResult from audit
            
        Returns:
            Alert dictionary
        """
        # Determine overall severity
        if result.grade == "F":
            severity = "critical"
        elif result.grade == "D":
            severity = "high"
        elif result.grade in ("B", "C"):
            severity = "medium"
        else:
            severity = "low"
        
        alert = {
            "module": "password",
            "type": "policy_audit",
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "score": result.score,
                "grade": result.grade,
                "compliant": result.compliant,
                "standard": result.standard.name,
                "issues_count": len(result.issues),
            },
            "issues_by_severity": {
                "critical": [i.to_dict() for i in result.issues if i.severity == "critical"],
                "high": [i.to_dict() for i in result.issues if i.severity == "high"],
                "medium": [i.to_dict() for i in result.issues if i.severity == "medium"],
                "low": [i.to_dict() for i in result.issues if i.severity == "low"],
                "info": [i.to_dict() for i in result.issues if i.severity == "info"],
            },
            "policy": result.policy.to_dict(),
            "recommendations": [i.recommendation for i in result.issues if i.severity in ("critical", "high")]
        }
        
        return alert


# =============================================================================
# LDAP Integration (Optional)
# =============================================================================

class LDAPPolicyReader:
    """
    Reads password policy from OpenLDAP server.
    
    Requires ldap3 package to be installed.
    """
    
    def __init__(
        self,
        ldap_uri: str,
        base_dn: str,
        bind_dn: Optional[str] = None,
        bind_password: Optional[str] = None
    ):
        """
        Initialize LDAP connection parameters.
        
        Args:
            ldap_uri: LDAP server URI (e.g., ldap://localhost:389)
            base_dn: Base DN for searches
            bind_dn: Optional bind DN for authentication
            bind_password: Optional bind password
        """
        self.ldap_uri = ldap_uri
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        
    def read_policy(self) -> Optional[PasswordPolicy]:
        """
        Read password policy from LDAP server.
        
        Returns:
            PasswordPolicy if successful, None otherwise
        """
        try:
            from ldap3 import Server, Connection, ALL, SUBTREE
        except ImportError:
            logger.warning("ldap3 package not installed. Install with: pip install ldap3")
            return None
        
        try:
            logger.info(f"Connecting to LDAP: {self.ldap_uri}")
            
            server = Server(self.ldap_uri, get_info=ALL)
            
            if self.bind_dn and self.bind_password:
                conn = Connection(server, self.bind_dn, self.bind_password, auto_bind=True)
            else:
                conn = Connection(server, auto_bind=True)
            
            # Search for password policy
            # OpenLDAP stores policies under cn=config or in ppolicy overlay
            policy_search_bases = [
                f"cn=config",
                f"ou=policies,{self.base_dn}",
                f"cn=default,ou=policies,{self.base_dn}",
            ]
            
            policy = PasswordPolicy(source=self.ldap_uri)
            
            for search_base in policy_search_bases:
                try:
                    conn.search(
                        search_base,
                        "(objectClass=pwdPolicy)",
                        search_scope=SUBTREE,
                        attributes=["*"]
                    )
                    
                    if conn.entries:
                        entry = conn.entries[0]
                        
                        # Map LDAP attributes to policy
                        if hasattr(entry, "pwdMinLength"):
                            policy.min_length = int(entry.pwdMinLength.value)
                        if hasattr(entry, "pwdMaxAge"):
                            # LDAP stores in seconds, convert to days
                            policy.max_age_days = int(entry.pwdMaxAge.value) // 86400
                        if hasattr(entry, "pwdMinAge"):
                            policy.min_age_days = int(entry.pwdMinAge.value) // 86400
                        if hasattr(entry, "pwdInHistory"):
                            policy.history_count = int(entry.pwdInHistory.value)
                        if hasattr(entry, "pwdMaxFailure"):
                            policy.lockout_threshold = int(entry.pwdMaxFailure.value)
                        if hasattr(entry, "pwdLockoutDuration"):
                            # LDAP stores in seconds, convert to minutes
                            policy.lockout_duration_minutes = int(entry.pwdLockoutDuration.value) // 60
                        
                        logger.info(f"Found LDAP password policy in {search_base}")
                        break
                        
                except Exception as e:
                    logger.debug(f"No policy found in {search_base}: {e}")
                    continue
            
            conn.unbind()
            return policy
            
        except Exception as e:
            logger.error(f"Failed to read LDAP policy: {e}")
            return None


# =============================================================================
# CLI Interface
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for CLI."""
    parser = argparse.ArgumentParser(
        description="SecuriSphere Password Policy Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit a config file against NIST strict standard
  python auditor.py --config /etc/security/pwquality.conf

  # Audit against industry best practices
  python auditor.py --config policy.conf --standard industry

  # Audit LDAP password policy
  python auditor.py --ldap-uri ldap://localhost --base-dn "dc=example,dc=com"

  # Output results to file
  python auditor.py --config policy.conf --output audit_results.json
        """
    )
    
    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--config",
        help="Path to password policy configuration file"
    )
    input_group.add_argument(
        "--ldap-uri",
        help="LDAP server URI (e.g., ldap://localhost:389)"
    )
    
    # LDAP options
    parser.add_argument(
        "--base-dn",
        help="LDAP base DN (required with --ldap-uri)"
    )
    parser.add_argument(
        "--bind-dn",
        help="LDAP bind DN for authentication"
    )
    parser.add_argument(
        "--bind-password",
        help="LDAP bind password"
    )
    
    # Audit options
    parser.add_argument(
        "--standard",
        choices=list(AVAILABLE_STANDARDS.keys()),
        default="nist-strict",
        help="Security standard to audit against (default: nist-strict)"
    )
    
    parser.add_argument(
        "--output",
        help="Output file for audit results (JSON format)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser


def main():
    """Main entry point for CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate LDAP arguments
    if args.ldap_uri and not args.base_dn:
        parser.error("--base-dn is required when using --ldap-uri")
    
    # Initialize auditor
    auditor = PasswordPolicyAuditor(standard=args.standard)
    
    try:
        # Get policy from config or LDAP
        if args.config:
            print(f"Auditing policy from: {args.config}")
            result = auditor.audit_config(args.config)
        else:
            print(f"Auditing policy from LDAP: {args.ldap_uri}")
            ldap_reader = LDAPPolicyReader(
                ldap_uri=args.ldap_uri,
                base_dn=args.base_dn,
                bind_dn=args.bind_dn,
                bind_password=args.bind_password
            )
            policy = ldap_reader.read_policy()
            
            if policy is None:
                print("Error: Failed to read policy from LDAP", file=sys.stderr)
                sys.exit(1)
            
            result = auditor.audit_policy(policy)
        
        # Generate alert
        alert = auditor.generate_alert(result)
        
        # Output results
        if args.output:
            with open(args.output, "w") as f:
                json.dump(alert, f, indent=2)
            print(f"\nAudit results written to: {args.output}")
        
        # Print summary
        print("\n" + "=" * 60)
        print("PASSWORD POLICY AUDIT RESULTS")
        print("=" * 60)
        print(f"  Standard:   {result.standard.name}")
        print(f"  Score:      {result.score}/100")
        print(f"  Grade:      {result.grade}")
        print(f"  Compliant:  {'Yes' if result.compliant else 'No'}")
        print(f"  Issues:     {len(result.issues)}")
        print("=" * 60)
        
        # Print issues by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_issues = [i for i in result.issues if i.severity == severity]
            if severity_issues:
                print(f"\n{severity.upper()} Issues:")
                for issue in severity_issues:
                    print(f"  - {issue.title}")
                    if args.verbose:
                        print(f"    {issue.description}")
                        print(f"    Recommendation: {issue.recommendation}")
        
        if not args.output:
            print("\n\nFull Alert (JSON):")
            print(json.dumps(alert, indent=2))
        
        # Exit code based on compliance
        sys.exit(0 if result.compliant else 1)
        
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.exception("Audit failed")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
