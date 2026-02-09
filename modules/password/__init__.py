# =============================================================================
# SecuriSphere - Password Module
# =============================================================================
"""
Password policy auditing and compliance checking module.

This module provides functionality for:
- Reading password policies from configuration files
- Checking policies against security standards (NIST, etc.)
- Computing compliance scores and identifying issues
- Generating JSON alerts for policy violations
- Optional LDAP integration for querying password settings
"""

from .auditor import PasswordPolicyAuditor

__all__ = ["PasswordPolicyAuditor"]
