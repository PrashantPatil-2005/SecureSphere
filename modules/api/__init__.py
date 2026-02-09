# =============================================================================
# SecuriSphere - API Module
# =============================================================================
"""
API security scanning and vulnerability detection module.

This module provides functionality for:
- Testing API endpoints for security vulnerabilities
- Checking broken authentication and authorization
- Testing injection vulnerabilities
- Verifying rate limiting implementation
- Mapping findings to OWASP API Security Top 10
"""

from .scanner import APISecurityScanner

__all__ = ["APISecurityScanner"]
