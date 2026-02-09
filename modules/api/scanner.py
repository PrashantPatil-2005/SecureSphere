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
- Rate Limiting (API4): Test for unrestricted resource consumption
- Broken Authorization (API1): Test BOLA/IDOR vulnerabilities
- Security Misconfiguration (API7): Check headers, error handling

Usage:
    # Scan an API target
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException, Timeout

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# =============================================================================
# OWASP API Security Top 10 (2023)
# =============================================================================

OWASP_API_TOP_10 = {
    "API1": {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "description": "APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.",
        "severity": "critical"
    },
    "API2": {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
        "severity": "critical"
    },
    "API3": {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": "APIs fail to validate that an authenticated user has permission to access specific object properties.",
        "severity": "high"
    },
    "API4": {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": "APIs do not limit the amount of requests that can be made, leading to Denial of Service or increased costs.",
        "severity": "high"
    },
    "API5": {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "description": "Authorization flaws allow users to access administrative functionality.",
        "severity": "critical"
    },
    "API6": {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": "APIs are susceptible to excessive automated use of their business functionality.",
        "severity": "high"
    },
    "API7": {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "description": "APIs fetching remote resources without validating user-supplied URLs.",
        "severity": "high"
    },
    "API8": {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "description": "APIs often have insecure default configurations, missing security hardening, or misconfigured security controls.",
        "severity": "medium"
    },
    "API9": {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "description": "APIs expose more endpoints than intended or have outdated documentation.",
        "severity": "medium"
    },
    "API10": {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": "APIs consume data from third-party APIs without proper validation.",
        "severity": "medium"
    }
}

# Injection payloads for testing
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
    "admin'--",
    "1; SELECT * FROM users",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "`whoami`",
    "$(id)",
    "; ping -c 3 localhost",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
]

# Weak credentials for testing
WEAK_CREDENTIALS = [
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
# Vulnerability Data Classes
# =============================================================================

@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
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
        """Convert to dictionary."""
        return asdict(self)


@dataclass 
class ScanResult:
    """Results of an API security scan."""
    target: str
    scan_timestamp: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    endpoints_scanned: int = 0
    requests_made: int = 0
    scan_duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "scan_timestamp": self.scan_timestamp,
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "by_severity": {
                    "critical": sum(1 for v in self.vulnerabilities if v.severity == "critical"),
                    "high": sum(1 for v in self.vulnerabilities if v.severity == "high"),
                    "medium": sum(1 for v in self.vulnerabilities if v.severity == "medium"),
                    "low": sum(1 for v in self.vulnerabilities if v.severity == "low"),
                    "info": sum(1 for v in self.vulnerabilities if v.severity == "info"),
                },
                "by_owasp": {},
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
    - Injection attacks (API8)
    - Rate limiting (API4)
    - Broken Authorization (API1, API5)
    """
    
    # Default endpoints to test
    DEFAULT_ENDPOINTS = [
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
    ):
        """
        Initialize the scanner.
        
        Args:
            target: Base URL of the target API
            timeout: Request timeout in seconds
            max_workers: Maximum concurrent workers
            verify_ssl: Whether to verify SSL certificates
        """
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.request_count = 0
        self.vulnerabilities: List[Vulnerability] = []
        
    def scan(self, endpoints: Optional[List[str]] = None) -> ScanResult:
        """
        Run a full security scan.
        
        Args:
            endpoints: List of endpoints to scan (uses defaults if None)
            
        Returns:
            ScanResult with discovered vulnerabilities
        """
        start_time = time.time()
        logger.info(f"Starting API security scan: {self.target}")
        
        if endpoints is None:
            endpoints = self.DEFAULT_ENDPOINTS
        
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
        
        # Calculate OWASP distribution
        for vuln in self.vulnerabilities:
            owasp_id = vuln.owasp_id
            if owasp_id not in result.to_dict()["summary"]["by_owasp"]:
                result.to_dict()["summary"]["by_owasp"][owasp_id] = 0
            result.to_dict()["summary"]["by_owasp"][owasp_id] += 1
        
        logger.info(f"Scan complete: {len(self.vulnerabilities)} vulnerabilities found")
        return result
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """Make an HTTP request and track count."""
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
        """Add a discovered vulnerability."""
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
        logger.warning(f"[{vuln.severity.upper()}] {vuln.title}: {endpoint}")
    
    # =========================================================================
    # Security Tests
    # =========================================================================
    
    def _test_broken_auth(self, endpoints: List[str]) -> None:
        """
        Test for Broken Authentication (API2).
        
        Checks if protected endpoints are accessible without authentication.
        """
        logger.info("Testing for Broken Authentication (API2)...")
        
        # Endpoints that should typically require auth
        sensitive_endpoints = [
            "/users/admin",
            "/admin",
            "/api/admin",
            "/api/users",
            "/users",
            "/config",
            "/debug",
        ]
        
        for endpoint in endpoints:
            if any(sens in endpoint.lower() for sens in ["admin", "user", "config", "debug"]):
                response = self._make_request("GET", endpoint)
                
                if response is not None:
                    # Check if we got data without auth
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            # Check if response contains user data
                            if isinstance(data, (dict, list)) and len(str(data)) > 10:
                                self._add_vulnerability(
                                    owasp_key="API2",
                                    title="Unauthenticated Access to Sensitive Endpoint",
                                    description=f"Endpoint {endpoint} returns sensitive data without authentication.",
                                    endpoint=endpoint,
                                    method="GET",
                                    evidence={
                                        "status_code": response.status_code,
                                        "response_preview": str(data)[:200],
                                        "content_length": len(response.text)
                                    },
                                    remediation="Implement proper authentication checks for all sensitive endpoints."
                                )
                        except json.JSONDecodeError:
                            pass
                    
                    # Check for authentication bypass with common headers
                    bypass_headers = [
                        {"X-Original-URL": endpoint},
                        {"X-Rewrite-URL": endpoint},
                        {"X-Forwarded-For": "127.0.0.1"},
                    ]
                    
                    for headers in bypass_headers:
                        bypass_response = self._make_request("GET", endpoint, headers=headers)
                        if bypass_response and bypass_response.status_code == 200:
                            if response.status_code in (401, 403):
                                self._add_vulnerability(
                                    owasp_key="API2",
                                    title="Authentication Bypass via Header Manipulation",
                                    description=f"Authentication can be bypassed using special headers.",
                                    endpoint=endpoint,
                                    method="GET",
                                    evidence={
                                        "bypass_header": headers,
                                        "original_status": response.status_code,
                                        "bypass_status": bypass_response.status_code
                                    },
                                    remediation="Do not trust client-supplied headers for authentication decisions."
                                )
    
    def _test_injection(self) -> None:
        """
        Test for Injection vulnerabilities (API8).
        
        Tests login endpoint with SQL injection and weak credentials.
        """
        logger.info("Testing for Injection vulnerabilities (API8)...")
        
        login_endpoints = ["/login", "/api/login", "/auth/login", "/api/auth/login"]
        
        for endpoint in login_endpoints:
            # Test SQL Injection in login
            for payload in SQL_INJECTION_PAYLOADS[:3]:  # Limit payloads
                test_data = {
                    "username": payload,
                    "password": "test"
                }
                
                response = self._make_request("POST", endpoint, json=test_data)
                
                if response is not None:
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
                                description=f"Login endpoint may be vulnerable to SQL injection. Server returned database-related error.",
                                endpoint=endpoint,
                                method="POST",
                                evidence={
                                    "payload": payload,
                                    "status_code": response.status_code,
                                    "error_indicator": indicator,
                                    "response_preview": response.text[:300]
                                },
                                remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
                                severity_override="critical"
                            )
                            break
                    
                    # Check for successful login with injection
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if "token" in str(data).lower() or "session" in str(data).lower():
                                self._add_vulnerability(
                                    owasp_key="API8",
                                    title="SQL Injection Authentication Bypass",
                                    description=f"Login endpoint allows authentication bypass via SQL injection.",
                                    endpoint=endpoint,
                                    method="POST",
                                    evidence={
                                        "payload": payload,
                                        "status_code": response.status_code,
                                        "response_preview": str(data)[:200]
                                    },
                                    remediation="Use parameterized queries and implement proper input validation.",
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
                
                if response is not None and response.status_code == 200:
                    try:
                        data = response.json()
                        if "token" in str(data).lower() or "success" in str(data).lower():
                            self._add_vulnerability(
                                owasp_key="API2",
                                title="Weak Credentials Accepted",
                                description=f"Login endpoint accepts weak/default credentials.",
                                endpoint=endpoint,
                                method="POST",
                                evidence={
                                    "username": username,
                                    "password": "***" + password[-2:] if len(password) > 2 else "***",
                                    "status_code": response.status_code
                                },
                                remediation="Enforce strong password policies. Change all default credentials. Implement account lockout.",
                                severity_override="high"
                            )
                            break  # Only report once per endpoint
                    except json.JSONDecodeError:
                        pass
    
    def _test_rate_limiting(self) -> None:
        """
        Test for Unrestricted Resource Consumption (API4).
        
        Sends 20 rapid requests to check rate limiting.
        """
        logger.info("Testing for Rate Limiting (API4)...")
        
        test_endpoints = ["/login", "/api/login", "/", "/api"]
        
        for endpoint in test_endpoints:
            # First, verify endpoint exists
            initial_response = self._make_request("GET", endpoint)
            if initial_response is None:
                continue
            
            # Send 20 rapid requests
            responses = []
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
            
            # Check if rate limiting was applied
            rate_limited = any(r["status_code"] == 429 for r in responses)
            all_success = all(r["status_code"] in (200, 201, 204, 301, 302) for r in responses if r)
            
            if not rate_limited and all_success and len(responses) >= 15:
                self._add_vulnerability(
                    owasp_key="API4",
                    title="No Rate Limiting Detected",
                    description=f"Endpoint allows unlimited requests without rate limiting.",
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
                    remediation="Implement rate limiting (e.g., 100 requests/minute). Use API gateways or WAF."
                )
                break  # Only report once
    
    def _test_security_headers(self) -> None:
        """
        Test for Security Misconfiguration (API8).
        
        Checks for missing security headers.
        """
        logger.info("Testing for Security Headers (API8)...")
        
        response = self._make_request("GET", "/")
        
        if response is None:
            return
        
        headers = response.headers
        missing_headers = []
        
        # Important security headers
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY or SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "Cache-Control": "no-store",
        }
        
        for header, expected in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing_headers.append(header)
        
        if missing_headers:
            self._add_vulnerability(
                owasp_key="API8",
                title="Missing Security Headers",
                description=f"API response is missing important security headers.",
                endpoint="/",
                method="GET",
                evidence={
                    "missing_headers": missing_headers,
                    "present_headers": list(headers.keys())
                },
                remediation=f"Add security headers: {', '.join(missing_headers)}",
                severity_override="low"
            )
        
        # Check for sensitive information in headers
        sensitive_headers = ["server", "x-powered-by", "x-aspnet-version"]
        exposed = {}
        
        for header in sensitive_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                exposed[header] = headers.get(header, "")
        
        if exposed:
            self._add_vulnerability(
                owasp_key="API8",
                title="Server Information Disclosure",
                description="API exposes server technology information in headers.",
                endpoint="/",
                method="GET",
                evidence={
                    "exposed_headers": exposed
                },
                remediation="Remove or obfuscate server identification headers.",
                severity_override="info"
            )
    
    def _test_bola(self, endpoints: List[str]) -> None:
        """
        Test for Broken Object Level Authorization (API1).
        
        Tests if changing IDs allows access to other users' data.
        """
        logger.info("Testing for Broken Object Level Authorization (API1)...")
        
        # Find endpoints with IDs
        id_endpoints = [
            "/users/1",
            "/users/2",
            "/api/users/1",
            "/api/users/2",
            "/orders/1",
            "/api/orders/1",
        ]
        
        for endpoint in id_endpoints:
            response = self._make_request("GET", endpoint)
            
            if response is not None and response.status_code == 200:
                # Try accessing other IDs
                modified_endpoint = endpoint.replace("/1", "/2").replace("/2", "/999")
                other_response = self._make_request("GET", modified_endpoint)
                
                if other_response and other_response.status_code == 200:
                    try:
                        data1 = response.json()
                        data2 = other_response.json()
                        
                        # Check if we got different users' data
                        if data1 != data2 and len(str(data2)) > 10:
                            self._add_vulnerability(
                                owasp_key="API1",
                                title="Broken Object Level Authorization (BOLA/IDOR)",
                                description=f"API allows accessing other users' data by manipulating object IDs.",
                                endpoint=endpoint,
                                method="GET",
                                evidence={
                                    "original_endpoint": endpoint,
                                    "modified_endpoint": modified_endpoint,
                                    "both_accessible": True
                                },
                                remediation="Implement proper authorization checks. Verify user owns the requested resource."
                            )
                    except json.JSONDecodeError:
                        pass
    
    def _test_error_handling(self) -> None:
        """
        Test for verbose error messages.
        """
        logger.info("Testing error handling...")
        
        # Try to trigger errors
        error_triggers = [
            ("GET", "/api/users/undefined"),
            ("POST", "/api/users", {"invalid": True}),
            ("GET", "/nonexistent-endpoint-12345"),
            ("GET", "/%00"),
        ]
        
        for method, endpoint, *data in error_triggers:
            kwargs = {"json": data[0]} if data else {}
            response = self._make_request(method, endpoint, **kwargs)
            
            if response is not None:
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
                            description="API returns detailed error information that may help attackers.",
                            endpoint=endpoint,
                            method=method,
                            evidence={
                                "status_code": response.status_code,
                                "error_indicator": indicator,
                                "response_preview": response.text[:500]
                            },
                            remediation="Implement generic error responses. Log detailed errors server-side only.",
                            severity_override="low"
                        )
                        return  # Only report once
    
    def generate_alert(self) -> Dict[str, Any]:
        """
        Generate JSON alert from scan results.
        
        Returns:
            Alert dictionary
        """
        # Determine overall severity
        if any(v.severity == "critical" for v in self.vulnerabilities):
            severity = "critical"
        elif any(v.severity == "high" for v in self.vulnerabilities):
            severity = "high"
        elif any(v.severity == "medium" for v in self.vulnerabilities):
            severity = "medium"
        else:
            severity = "low"
        
        return {
            "module": "api",
            "type": "security_scan",
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "target": self.target,
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "by_severity": {
                    "critical": sum(1 for v in self.vulnerabilities if v.severity == "critical"),
                    "high": sum(1 for v in self.vulnerabilities if v.severity == "high"),
                    "medium": sum(1 for v in self.vulnerabilities if v.severity == "medium"),
                    "low": sum(1 for v in self.vulnerabilities if v.severity == "low"),
                    "info": sum(1 for v in self.vulnerabilities if v.severity == "info"),
                }
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]
        }


# =============================================================================
# CLI Interface
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for CLI."""
    parser = argparse.ArgumentParser(
        description="SecuriSphere API Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a target API
  python scanner.py --target http://victim-app:8000

  # Scan with custom endpoints
  python scanner.py --target http://localhost:8000 --endpoints /api/v1/users,/api/v1/admin

  # Output to file
  python scanner.py --target http://localhost:8000 --output vulns.json

  # Increase timeout for slow APIs
  python scanner.py --target http://api.example.com --timeout 30
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
    
    # Parse endpoints
    endpoints = None
    if args.endpoints:
        endpoints = [e.strip() for e in args.endpoints.split(",")]
    
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
            with open(args.output, "w") as f:
                json.dump(alert, f, indent=2)
            print(f"\nResults written to: {args.output}")
        
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
        
        # Print vulnerabilities
        if result.vulnerabilities:
            print("\n" + "-" * 60)
            print("VULNERABILITIES FOUND:")
            print("-" * 60)
            
            for vuln in result.vulnerabilities:
                severity_color = {
                    "critical": "!!!",
                    "high": "!! ",
                    "medium": "!  ",
                    "low": "   ",
                    "info": "   "
                }
                print(f"\n{severity_color.get(vuln.severity, '   ')} [{vuln.severity.upper()}] {vuln.title}")
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
        
    except Exception as e:
        logger.exception("Scan failed")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
