#!/usr/bin/env python3
# =============================================================================
# SecuriSphere - API Security Scanner
# =============================================================================
"""
API Security Vulnerability Scanner

Tests API endpoints for common security vulnerabilities mapped to
OWASP API Security Top 10 (2023).

Features:
- Broken Authentication (API2): Test unauthenticated access to protected resources
- Injection (API8): Test SQL injection, command injection payloads
- Rate Limiting (API4): Test for unrestricted resource consumption (20 rapid requests)
- Broken Authorization (API1): Test BOLA/IDOR vulnerabilities
- Security Misconfiguration: Check headers, error handling

Simulation (from attacker container):
    # Test broken authentication (should fail but returns data):
    curl http://victim-app:8000/users/admin
    curl http://victim-app:8000/api/users
    
    # Test SQL injection on login:
    curl -X POST http://victim-app:8000/login \\
        -H "Content-Type: application/json" \\
        -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "x"}'
    
    # Test weak credentials:
    curl -X POST http://victim-app:8000/login \\
        -H "Content-Type: application/json" \\
        -d '{"username": "admin", "password": "admin123"}'
    
    # Test rate limiting (20 rapid requests):
    for i in $(seq 1 20); do curl -s http://victim-app:8000/ & done; wait

Usage:
    # Scan a target API
    python scanner.py --target http://victim-app:8000
    
    # Scan with custom endpoints
    python scanner.py --target http://localhost:8000 --endpoints /api/users,/api/admin
    
    # Output to file
    python scanner.py --target http://localhost:8000 --output vulns.json
"""

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException, Timeout

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# =============================================================================
# OWASP API Security Top 10 (2023)
# =============================================================================

OWASP_API_TOP_10: Dict[str, Dict[str, str]] = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "description": (
            "APIs expose endpoints that handle object identifiers, "
            "creating a wide attack surface of Object Level Access Control issues."
        ),
        "severity": "critical"
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": (
            "Authentication mechanisms are often implemented incorrectly, "
            "allowing attackers to compromise authentication tokens."
        ),
        "severity": "critical"
    },
    "API3": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": (
            "APIs fail to validate that an authenticated user has permission "
            "to access specific object properties."
        ),
        "severity": "high"
    },
    "API4": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": (
            "APIs do not limit the amount of requests that can be made, "
            "leading to Denial of Service or increased costs."
        ),
        "severity": "high"
    },
    "API5": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "description": (
            "Authorization flaws allow users to access administrative functionality."
        ),
        "severity": "critical"
    },
    "API6": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": (
            "APIs are susceptible to excessive automated use of their "
            "business functionality."
        ),
        "severity": "high"
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "description": (
            "APIs fetching remote resources without validating user-supplied URLs."
        ),
        "severity": "high"
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "description": (
            "APIs often have insecure default configurations, missing security "
            "hardening, or misconfigured security controls."
        ),
        "severity": "medium"
    },
    "API9": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "description": (
            "APIs expose more endpoints than intended or have outdated documentation."
        ),
        "severity": "medium"
    },
    "API10": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": (
            "APIs consume data from third-party APIs without proper validation."
        ),
        "severity": "medium"
    }
}


# =============================================================================
# Attack Payloads
# =============================================================================

# SQL Injection payloads for testing login/input endpoints
SQL_INJECTION_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
    "admin'--",
    "1; SELECT * FROM users",
]

# Command injection payloads
COMMAND_INJECTION_PAYLOADS: List[str] = [
    "; ls -la",
    "| cat /etc/passwd",
    "`whoami`",
    "$(id)",
    "; ping -c 3 localhost",
]

# XSS payloads (for future use)
XSS_PAYLOADS: List[str] = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
]

# Weak credentials for testing
WEAK_CREDENTIALS: List[tuple] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
]


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Vulnerability:
    """
    Represents a discovered vulnerability.
    
    Contains OWASP mapping, severity, evidence, and remediation.
    """
    owasp_id: str
    owasp_name: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    endpoint: str
    method: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    cvss_score: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass 
class ScanResult:
    """
    Results of an API security scan.
    
    Contains summary statistics and list of vulnerabilities.
    """
    target: str
    scan_timestamp: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    endpoints_scanned: int = 0
    requests_made: int = 0
    scan_duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "scan_timestamp": self.scan_timestamp,
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "by_severity": {
                    "critical": sum(
                        1 for v in self.vulnerabilities if v.severity == "critical"
                    ),
                    "high": sum(
                        1 for v in self.vulnerabilities if v.severity == "high"
                    ),
                    "medium": sum(
                        1 for v in self.vulnerabilities if v.severity == "medium"
                    ),
                    "low": sum(
                        1 for v in self.vulnerabilities if v.severity == "low"
                    ),
                    "info": sum(
                        1 for v in self.vulnerabilities if v.severity == "info"
                    ),
                },
                "endpoints_scanned": self.endpoints_scanned,
                "requests_made": self.requests_made,
                "scan_duration_seconds": self.scan_duration_seconds
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }


# =============================================================================
# API Security Scanner
# =============================================================================

class APISecurityScanner:
    """
    Scans API endpoints for security vulnerabilities.
    
    Tests for OWASP API Security Top 10 issues including:
    - Broken Authentication (API2)
    - Injection attacks (related to API8)
    - Rate limiting (API4)
    - Broken Object Level Authorization (API1)
    - Security Misconfiguration (API8)
    """
    
    # Default endpoints to test if none specified
    DEFAULT_ENDPOINTS: List[str] = [
        "/",
        "/api",
        "/api/v1",
        "/users",
        "/users/admin",
        "/users/1",
        "/admin",
        "/login",
        "/auth/login",
        "/api/login",
        "/api/users",
        "/api/admin",
        "/health",
        "/status",
        "/config",
        "/debug",
    ]
    
    def __init__(
        self,
        target: str,
        timeout: int = 10,
        max_workers: int = 5,
        verify_ssl: bool = False
    ) -> None:
        """
        Initialize the scanner.
        
        Args:
            target: Base URL of the target API
            timeout: Request timeout in seconds
            max_workers: Maximum concurrent workers (for future use)
            verify_ssl: Whether to verify SSL certificates
        """
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.request_count = 0
        self.vulnerabilities: List[Vulnerability] = []
        
        logger.info(f"Initialized scanner for target: {self.target}")
    
    def scan(self, endpoints: Optional[List[str]] = None) -> ScanResult:
        """
        Run a full security scan.
        
        Executes all security tests against the target API.
        
        Args:
            endpoints: List of endpoints to scan (uses defaults if None)
            
        Returns:
            ScanResult with discovered vulnerabilities
        """
        start_time = time.time()
        logger.info(f"Starting API security scan: {self.target}")
        
        if endpoints is None:
            endpoints = self.DEFAULT_ENDPOINTS
        
        # Reset state for new scan
        self.vulnerabilities = []
        self.request_count = 0
        
        # Run all security tests
        self._test_broken_auth(endpoints)
        self._test_injection()
        self._test_rate_limiting()
        self._test_security_headers()
        self._test_bola(endpoints)
        self._test_error_handling()
        
        duration = time.time() - start_time
        
        result = ScanResult(
            target=self.target,
            scan_timestamp=datetime.utcnow().isoformat(),
            vulnerabilities=self.vulnerabilities,
            endpoints_scanned=len(endpoints),
            requests_made=self.request_count,
            scan_duration_seconds=round(duration, 2)
        )
        
        logger.info(
            f"Scan complete: {len(self.vulnerabilities)} vulnerabilities found "
            f"in {duration:.2f}s"
        )
        return result
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Make an HTTP request and track count.
        
        Handles errors gracefully, returning None on failure.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object or None on failure
        """
        url = urljoin(self.target, endpoint)
        self.request_count += 1
        
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            logger.debug(f"{method} {url} -> {response.status_code}")
            return response
            
        except Timeout:
            logger.debug(f"Timeout: {method} {url}")
            return None
            
        except RequestException as e:
            logger.debug(f"Request failed: {method} {url} - {e}")
            return None
    
    def _add_vulnerability(
        self,
        owasp_key: str,
        title: str,
        description: str,
        endpoint: str,
        method: str,
        evidence: Dict[str, Any],
        remediation: str = "",
        severity_override: Optional[str] = None
    ) -> None:
        """
        Add a discovered vulnerability to the results.
        
        Args:
            owasp_key: OWASP API Top 10 key (e.g., "API2")
            title: Short title of the vulnerability
            description: Detailed description
            endpoint: Affected endpoint
            method: HTTP method used
            evidence: Dict with evidence details
            remediation: Recommended fix
            severity_override: Override default severity
        """
        owasp = OWASP_API_TOP_10.get(owasp_key, {})
        
        vuln = Vulnerability(
            owasp_id=owasp.get("id", owasp_key),
            owasp_name=owasp.get("name", "Unknown"),
            severity=severity_override or owasp.get("severity", "medium"),
            title=title,
            description=description,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation
        )
        
        self.vulnerabilities.append(vuln)
        logger.warning(
            f"[{vuln.severity.upper()}] {vuln.title}: {method} {endpoint}"
        )
    
    # =========================================================================
    # Security Tests
    # =========================================================================
    
    def _test_broken_auth(self, endpoints: List[str]) -> None:
        """
        Test for Broken Authentication (API2).
        
        Checks if protected endpoints (admin, users, config) are
        accessible without authentication.
        """
        logger.info("Testing for Broken Authentication (API2)...")
        
        # Keywords that typically indicate protected endpoints
        sensitive_keywords = ["admin", "user", "config", "debug", "private"]
        
        for endpoint in endpoints:
            # Only test endpoints that look sensitive
            if not any(kw in endpoint.lower() for kw in sensitive_keywords):
                continue
            
            response = self._make_request("GET", endpoint)
            
            if response is None:
                continue
            
            # Check if we got data without auth (200 status)
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Check if response contains meaningful data
                    if isinstance(data, (dict, list)) and len(str(data)) > 10:
                        self._add_vulnerability(
                            owasp_key="API2",
                            title="Unauthenticated Access to Sensitive Endpoint",
                            description=(
                                f"Endpoint {endpoint} returns sensitive data "
                                f"without authentication."
                            ),
                            endpoint=endpoint,
                            method="GET",
                            evidence={
                                "status_code": response.status_code,
                                "response_preview": str(data)[:200],
                                "content_length": len(response.text)
                            },
                            remediation=(
                                "Implement proper authentication checks for all "
                                "sensitive endpoints. Use JWT, OAuth, or session tokens."
                            )
                        )
                except json.JSONDecodeError:
                    # Not JSON, might still be sensitive HTML/text
                    if len(response.text) > 100:
                        self._add_vulnerability(
                            owasp_key="API2",
                            title="Unauthenticated Access to Sensitive Endpoint",
                            description=(
                                f"Endpoint {endpoint} accessible without authentication."
                            ),
                            endpoint=endpoint,
                            method="GET",
                            evidence={
                                "status_code": response.status_code,
                                "content_length": len(response.text)
                            },
                            remediation=(
                                "Implement proper authentication checks."
                            ),
                            severity_override="high"
                        )
            
            # Check for auth bypass via headers
            bypass_headers = [
                {"X-Original-URL": endpoint},
                {"X-Rewrite-URL": endpoint},
                {"X-Forwarded-For": "127.0.0.1"},
            ]
            
            for headers in bypass_headers:
                bypass_response = self._make_request("GET", endpoint, headers=headers)
                
                if bypass_response and bypass_response.status_code == 200:
                    # If original was blocked but bypass works
                    if response.status_code in (401, 403):
                        self._add_vulnerability(
                            owasp_key="API2",
                            title="Authentication Bypass via Header Manipulation",
                            description=(
                                "Authentication can be bypassed using special headers."
                            ),
                            endpoint=endpoint,
                            method="GET",
                            evidence={
                                "bypass_header": headers,
                                "original_status": response.status_code,
                                "bypass_status": bypass_response.status_code
                            },
                            remediation=(
                                "Do not trust client-supplied headers for "
                                "authentication decisions. Validate auth server-side."
                            )
                        )
    
    def _test_injection(self) -> None:
        """
        Test for Injection vulnerabilities.
        
        Tests login endpoint with SQL injection payloads and weak credentials.
        Maps to API8 (Security Misconfiguration) as injection often indicates
        misconfigured input validation.
        """
        logger.info("Testing for Injection vulnerabilities (API8)...")
        
        login_endpoints = ["/login", "/api/login", "/auth/login", "/api/auth/login"]
        
        for endpoint in login_endpoints:
            # First check if endpoint exists
            check = self._make_request("POST", endpoint, json={})
            if check is None:
                continue
            
            # Test SQL Injection in login
            for payload in SQL_INJECTION_PAYLOADS[:3]:  # Limit to avoid noise
                test_data = {
                    "username": payload,
                    "password": "test"
                }
                
                response = self._make_request("POST", endpoint, json=test_data)
                
                if response is None:
                    continue
                
                # Check for SQL error messages in response
                error_indicators = [
                    "sql", "syntax", "mysql", "sqlite", "postgresql",
                    "oracle", "database", "query", "select", "insert"
                ]
                
                response_lower = response.text.lower()
                for indicator in error_indicators:
                    if indicator in response_lower:
                        self._add_vulnerability(
                            owasp_key="API8",
                            title="SQL Injection Vulnerability",
                            description=(
                                f"Login endpoint may be vulnerable to SQL injection. "
                                f"Server returned database-related error message."
                            ),
                            endpoint=endpoint,
                            method="POST",
                            evidence={
                                "payload": payload,
                                "status_code": response.status_code,
                                "error_indicator": indicator,
                                "response_preview": response.text[:300]
                            },
                            remediation=(
                                "Use parameterized queries or prepared statements. "
                                "Never concatenate user input into SQL queries. "
                                "Implement input validation and sanitization."
                            ),
                            severity_override="critical"
                        )
                        break
                
                # Check for successful auth bypass via injection
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "token" in str(data).lower() or "session" in str(data).lower():
                            self._add_vulnerability(
                                owasp_key="API8",
                                title="SQL Injection Authentication Bypass",
                                description=(
                                    f"Login endpoint allows authentication bypass "
                                    f"via SQL injection."
                                ),
                                endpoint=endpoint,
                                method="POST",
                                evidence={
                                    "payload": payload,
                                    "status_code": response.status_code,
                                    "response_preview": str(data)[:200]
                                },
                                remediation=(
                                    "Use parameterized queries. Implement proper "
                                    "input validation and WAF rules."
                                ),
                                severity_override="critical"
                            )
                    except json.JSONDecodeError:
                        pass
            
            # Test weak credentials
            for username, password in WEAK_CREDENTIALS:
                response = self._make_request(
                    "POST",
                    endpoint,
                    json={"username": username, "password": password}
                )
                
                if response is None:
                    continue
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "token" in str(data).lower() or "success" in str(data).lower():
                            self._add_vulnerability(
                                owasp_key="API2",
                                title="Weak Credentials Accepted",
                                description=(
                                    f"Login endpoint accepts weak/default credentials "
                                    f"for user '{username}'."
                                ),
                                endpoint=endpoint,
                                method="POST",
                                evidence={
                                    "username": username,
                                    "password_hint": "***" + password[-2:] if len(password) > 2 else "***",
                                    "status_code": response.status_code
                                },
                                remediation=(
                                    "Enforce strong password policies. Change all "
                                    "default credentials. Implement account lockout. "
                                    "Add MFA for sensitive accounts."
                                ),
                                severity_override="high"
                            )
                            break  # Only report once per endpoint
                    except json.JSONDecodeError:
                        pass
    
    def _test_rate_limiting(self) -> None:
        """
        Test for Unrestricted Resource Consumption (API4).
        
        Sends 20 rapid requests to check if rate limiting is implemented.
        """
        logger.info("Testing for Rate Limiting (API4)...")
        
        test_endpoints = ["/login", "/api/login", "/", "/api"]
        
        for endpoint in test_endpoints:
            # First, verify endpoint exists
            initial_response = self._make_request("GET", endpoint)
            if initial_response is None:
                continue
            
            logger.info(f"Sending 20 rapid requests to {endpoint}...")
            
            # Send 20 rapid requests
            responses: List[Dict[str, Any]] = []
            start_time = time.time()
            
            for i in range(20):
                response = self._make_request("GET", endpoint)
                if response:
                    responses.append({
                        "iteration": i + 1,
                        "status_code": response.status_code,
                        "time": time.time() - start_time
                    })
            
            duration = time.time() - start_time
            
            # Check if rate limiting was triggered
            rate_limited = any(r["status_code"] == 429 for r in responses)
            successful_requests = [
                r for r in responses 
                if r["status_code"] in (200, 201, 204, 301, 302)
            ]
            
            if not rate_limited and len(successful_requests) >= 15:
                self._add_vulnerability(
                    owasp_key="API4",
                    title="No Rate Limiting Detected",
                    description=(
                        f"Endpoint {endpoint} allows unlimited requests without "
                        f"rate limiting. Completed {len(responses)} requests in "
                        f"{duration:.2f}s."
                    ),
                    endpoint=endpoint,
                    method="GET",
                    evidence={
                        "requests_sent": 20,
                        "requests_completed": len(responses),
                        "duration_seconds": round(duration, 2),
                        "requests_per_second": round(len(responses) / duration, 2),
                        "rate_limited": False,
                        "status_codes": list(set(r["status_code"] for r in responses))
                    },
                    remediation=(
                        "Implement rate limiting (e.g., 100 requests/minute). "
                        "Use API gateways, WAF, or middleware like nginx limit_req. "
                        "Return HTTP 429 when limits are exceeded."
                    )
                )
                break  # Only report once
    
    def _test_security_headers(self) -> None:
        """
        Test for Security Misconfiguration (API8).
        
        Checks for missing security headers and exposed server information.
        """
        logger.info("Testing for Security Headers (API8)...")
        
        response = self._make_request("GET", "/")
        
        if response is None:
            logger.warning("Could not reach target for header analysis")
            return
        
        headers = response.headers
        missing_headers: List[str] = []
        
        # Important security headers and their expected values
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY or SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "Cache-Control": "no-store",
        }
        
        for header in security_headers:
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing_headers.append(header)
        
        if missing_headers:
            self._add_vulnerability(
                owasp_key="API8",
                title="Missing Security Headers",
                description=(
                    f"API response is missing {len(missing_headers)} "
                    f"important security headers."
                ),
                endpoint="/",
                method="GET",
                evidence={
                    "missing_headers": missing_headers,
                    "present_headers": list(headers.keys())
                },
                remediation=(
                    f"Configure server to add security headers: "
                    f"{', '.join(missing_headers)}"
                ),
                severity_override="low"
            )
        
        # Check for sensitive information disclosure in headers
        sensitive_headers = ["server", "x-powered-by", "x-aspnet-version"]
        exposed: Dict[str, str] = {}
        
        for header in sensitive_headers:
            for resp_header in headers:
                if header.lower() == resp_header.lower():
                    exposed[header] = headers[resp_header]
        
        if exposed:
            self._add_vulnerability(
                owasp_key="API8",
                title="Server Information Disclosure",
                description=(
                    "API exposes server technology information in response headers."
                ),
                endpoint="/",
                method="GET",
                evidence={
                    "exposed_headers": exposed
                },
                remediation=(
                    "Remove or obfuscate server identification headers. "
                    "Configure web server to hide version information."
                ),
                severity_override="info"
            )
    
    def _test_bola(self, endpoints: List[str]) -> None:
        """
        Test for Broken Object Level Authorization (API1).
        
        Tests if changing object IDs allows access to other users' data.
        """
        logger.info("Testing for Broken Object Level Authorization (API1)...")
        
        # Endpoints with IDs to test
        id_endpoints = [ep for ep in endpoints if "/1" in ep or "/2" in ep]
        
        # Add common ID-based endpoints
        id_endpoints.extend([
            "/users/1",
            "/users/2",
            "/api/users/1",
            "/api/users/2",
        ])
        
        # Remove duplicates
        id_endpoints = list(set(id_endpoints))
        
        for endpoint in id_endpoints:
            response = self._make_request("GET", endpoint)
            
            if response is None or response.status_code != 200:
                continue
            
            # Try accessing other IDs
            if "/1" in endpoint:
                modified = endpoint.replace("/1", "/2")
            else:
                modified = endpoint.replace("/2", "/999")
            
            other_response = self._make_request("GET", modified)
            
            if other_response and other_response.status_code == 200:
                try:
                    data1 = response.json()
                    data2 = other_response.json()
                    
                    # Check if we got different data (BOLA/IDOR)
                    if data1 != data2 and len(str(data2)) > 10:
                        self._add_vulnerability(
                            owasp_key="API1",
                            title="Broken Object Level Authorization (BOLA/IDOR)",
                            description=(
                                "API allows accessing other users' data by "
                                "manipulating object IDs without authorization checks."
                            ),
                            endpoint=endpoint,
                            method="GET",
                            evidence={
                                "original_endpoint": endpoint,
                                "modified_endpoint": modified,
                                "both_accessible": True
                            },
                            remediation=(
                                "Implement proper authorization checks. Verify "
                                "the authenticated user owns the requested resource. "
                                "Use indirect object references or UUIDs."
                            )
                        )
                except json.JSONDecodeError:
                    pass
    
    def _test_error_handling(self) -> None:
        """
        Test for verbose error messages that may leak information.
        """
        logger.info("Testing error handling...")
        
        # Payloads designed to trigger errors
        error_triggers = [
            ("GET", "/api/users/undefined"),
            ("POST", "/api/users"),
            ("GET", "/nonexistent-endpoint-12345"),
            ("GET", "/%00"),
        ]
        
        for method, endpoint in error_triggers:
            kwargs: Dict[str, Any] = {}
            if method == "POST":
                kwargs["json"] = {"invalid": True}
            
            response = self._make_request(method, endpoint, **kwargs)
            
            if response is None:
                continue
            
            # Check for verbose error indicators
            error_indicators = [
                "traceback", "stacktrace", "exception", "error in",
                "file \"", "line ", "at 0x", "internal server error",
                "debug", "development"
            ]
            
            response_lower = response.text.lower()
            for indicator in error_indicators:
                if indicator in response_lower:
                    self._add_vulnerability(
                        owasp_key="API8",
                        title="Verbose Error Messages",
                        description=(
                            "API returns detailed error information that may "
                            "help attackers understand the application structure."
                        ),
                        endpoint=endpoint,
                        method=method,
                        evidence={
                            "status_code": response.status_code,
                            "error_indicator": indicator,
                            "response_preview": response.text[:500]
                        },
                        remediation=(
                            "Implement generic error responses for clients. "
                            "Log detailed errors server-side only. "
                            "Disable debug mode in production."
                        ),
                        severity_override="low"
                    )
                    return  # Only report once
    
    def generate_alert(self) -> Dict[str, Any]:
        """
        Generate JSON alert from scan results.
        
        Returns:
            Alert dictionary suitable for logging/alerting systems
        """
        # Determine overall severity based on findings
        if any(v.severity == "critical" for v in self.vulnerabilities):
            severity = "critical"
        elif any(v.severity == "high" for v in self.vulnerabilities):
            severity = "high"
        elif any(v.severity == "medium" for v in self.vulnerabilities):
            severity = "medium"
        else:
            severity = "low" if self.vulnerabilities else "info"
        
        alert: Dict[str, Any] = {
            "module": "api",
            "type": "security_scan",
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "target": self.target,
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "by_severity": {
                    "critical": sum(
                        1 for v in self.vulnerabilities if v.severity == "critical"
                    ),
                    "high": sum(
                        1 for v in self.vulnerabilities if v.severity == "high"
                    ),
                    "medium": sum(
                        1 for v in self.vulnerabilities if v.severity == "medium"
                    ),
                    "low": sum(
                        1 for v in self.vulnerabilities if v.severity == "low"
                    ),
                    "info": sum(
                        1 for v in self.vulnerabilities if v.severity == "info"
                    ),
                }
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }
        
        return alert


# =============================================================================
# CLI Interface
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for CLI interface."""
    parser = argparse.ArgumentParser(
        description="SecuriSphere API Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a target API
  python scanner.py --target http://victim-app:8000

  # Scan with custom endpoints
  python scanner.py --target http://localhost:8000 \\
      --endpoints /api/v1/users,/api/v1/admin

  # Output to file
  python scanner.py --target http://localhost:8000 --output vulns.json

  # Increase timeout for slow APIs
  python scanner.py --target http://api.example.com --timeout 30

Simulation (generate payloads from attacker):
  # Test unauthenticated access:
  curl http://victim-app:8000/users/admin

  # Test SQL injection:
  curl -X POST http://victim-app:8000/login \\
      -d '{"username":"admin'\\''--","password":"x"}'

  # Flood test (rate limiting):
  for i in $(seq 1 20); do curl -s http://victim-app:8000/ & done
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target API base URL (e.g., http://victim-app:8000)"
    )
    
    parser.add_argument(
        "--endpoints",
        help="Comma-separated list of endpoints to scan (uses defaults if not specified)"
    )
    
    parser.add_argument(
        "--output",
        help="Output file for results (JSON format)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify SSL certificates (disabled by default for testing)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging"
    )
    
    return parser


def main() -> None:
    """Main entry point for CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Parse endpoints if provided
    endpoints: Optional[List[str]] = None
    if args.endpoints:
        endpoints = [e.strip() for e in args.endpoints.split(",")]
        logger.info(f"Custom endpoints: {endpoints}")
    
    # Initialize scanner
    scanner = APISecurityScanner(
        target=args.target,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl
    )
    
    try:
        print(f"Scanning API: {args.target}")
        print("=" * 60)
        
        # Run scan
        result = scanner.scan(endpoints)
        
        # Generate alert
        alert = scanner.generate_alert()
        
        # Output results
        if args.output:
            try:
                with open(args.output, "w") as f:
                    json.dump(alert, f, indent=2)
                print(f"\nResults written to: {args.output}")
            except IOError as e:
                logger.error(f"Failed to write output file: {e}")
                print(f"Error writing file: {e}", file=sys.stderr)
        
        # Print summary
        print("\n" + "=" * 60)
        print("API SECURITY SCAN RESULTS")
        print("=" * 60)
        print(f"  Target:          {result.target}")
        print(f"  Endpoints:       {result.endpoints_scanned}")
        print(f"  Requests:        {result.requests_made}")
        print(f"  Duration:        {result.scan_duration_seconds}s")
        print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
        print("=" * 60)
        
        # Print by severity
        severity_counts = alert["summary"]["by_severity"]
        print(f"\n  Critical: {severity_counts['critical']}")
        print(f"  High:     {severity_counts['high']}")
        print(f"  Medium:   {severity_counts['medium']}")
        print(f"  Low:      {severity_counts['low']}")
        print(f"  Info:     {severity_counts['info']}")
        
        # Print vulnerabilities details
        if result.vulnerabilities:
            print("\n" + "-" * 60)
            print("VULNERABILITIES FOUND:")
            print("-" * 60)
            
            severity_icons = {
                "critical": "!!!",
                "high": "!! ",
                "medium": "!  ",
                "low": "   ",
                "info": "   "
            }
            
            for vuln in result.vulnerabilities:
                icon = severity_icons.get(vuln.severity, "   ")
                print(f"\n{icon} [{vuln.severity.upper()}] {vuln.title}")
                print(f"    OWASP: {vuln.owasp_id} - {vuln.owasp_name}")
                print(f"    Endpoint: {vuln.method} {vuln.endpoint}")
                
                if args.verbose:
                    print(f"    Description: {vuln.description}")
                    print(f"    Remediation: {vuln.remediation}")
        
        if not args.output:
            print("\n\nFull Results (JSON):")
            print(json.dumps(alert, indent=2))
        
        # Exit code based on findings
        if severity_counts["critical"] > 0:
            sys.exit(2)
        elif severity_counts["high"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        logger.exception("Scan failed")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# =============================================================================
# Demo Run
# =============================================================================

if __name__ == "__main__":
    main()
