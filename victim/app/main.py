"""
=============================================================================
SecuriSphere - Intentionally Vulnerable FastAPI Application
=============================================================================

WARNING: This application contains INTENTIONAL security vulnerabilities
for educational and testing purposes only. DO NOT deploy in production!

Vulnerabilities included:
1. Broken Authentication - No auth on sensitive endpoints
2. Weak Password Policy - Accepts weak passwords
3. Information Disclosure - Exposes sensitive user data
4. Broken Access Control - IDOR vulnerability
5. Hardcoded Credentials - Admin backdoor
=============================================================================
"""

from fastapi import FastAPI, HTTPException, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from passlib.hash import sha256_crypt
import re

# =============================================================================
# APPLICATION SETUP
# =============================================================================

app = FastAPI(
    title="SecuriSphere Victim API",
    description="Intentionally vulnerable API for security testing",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS - Overly permissive (vulnerability)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# MOCK DATABASE (In-memory storage)
# =============================================================================

# Simulated user database with weak passwords
USERS_DB = {
    "admin": {
        "id": 1,
        "username": "admin",
        "email": "admin@securisphere.local",
        "password_hash": sha256_crypt.hash("admin123"),  # WEAK PASSWORD
        "role": "admin",
        "ssn": "123-45-6789",  # Sensitive PII
        "salary": 150000
    },
    "john_doe": {
        "id": 2,
        "username": "john_doe",
        "email": "john@securisphere.local",
        "password_hash": sha256_crypt.hash("password"),  # WEAK PASSWORD
        "role": "user",
        "ssn": "987-65-4321",
        "salary": 75000
    },
    "jane_smith": {
        "id": 3,
        "username": "jane_smith",
        "email": "jane@securisphere.local",
        "password_hash": sha256_crypt.hash("123456"),  # WEAK PASSWORD
        "role": "user",
        "ssn": "456-78-9012",
        "salary": 82000
    },
    "guest": {
        "id": 4,
        "username": "guest",
        "email": "guest@securisphere.local",
        "password_hash": sha256_crypt.hash("guest"),  # WEAK PASSWORD
        "role": "guest",
        "ssn": "000-00-0000",
        "salary": 0
    }
}

# Session tokens (weak implementation)
SESSIONS = {}

# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[dict] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    ssn: Optional[str] = None  # Should never expose this!
    salary: Optional[int] = None

class PasswordChangeRequest(BaseModel):
    username: str
    new_password: str

# =============================================================================
# HEALTH CHECK ENDPOINT
# =============================================================================

@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for container orchestration."""
    return {"status": "healthy", "service": "victim-api"}

# =============================================================================
# VULNERABILITY 1: BROKEN AUTHENTICATION
# No authentication required to access sensitive user data
# =============================================================================

@app.get("/users/{username}", response_model=UserResponse, tags=["Users"])
async def get_user(username: str):
    """
    VULNERABLE: Returns user data including sensitive PII without authentication.
    
    This endpoint demonstrates:
    - Broken Access Control (OWASP A01:2021)
    - Sensitive Data Exposure (OWASP A02:2021)
    """
    if username not in USERS_DB:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = USERS_DB[username]
    
    # VULNERABILITY: Exposing all user data including SSN and salary
    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        role=user["role"],
        ssn=user["ssn"],      # SENSITIVE DATA EXPOSURE!
        salary=user["salary"]  # SENSITIVE DATA EXPOSURE!
    )

@app.get("/users", tags=["Users"])
async def list_users():
    """
    VULNERABLE: Lists all users with sensitive information without auth.
    """
    return {
        "users": [
            {
                "id": u["id"],
                "username": u["username"],
                "email": u["email"],
                "role": u["role"]
            }
            for u in USERS_DB.values()
        ]
    }

# =============================================================================
# VULNERABILITY 2: WEAK PASSWORD POLICY
# Accepts passwords that don't meet security standards
# =============================================================================

def check_password_strength(password: str) -> dict:
    """
    INTENTIONALLY WEAK password policy checker.
    A real implementation should enforce much stricter rules.
    """
    issues = []
    strength = "strong"
    
    # Minimal checks (intentionally weak)
    if len(password) < 4:  # Should be 12+ in production
        issues.append("Password too short (min 4 chars)")
        strength = "weak"
    
    # Missing proper checks for:
    # - Uppercase letters
    # - Numbers
    # - Special characters
    # - Common password lists
    # - Password history
    
    return {
        "password": password,
        "strength": strength,
        "issues": issues,
        "passes_policy": len(issues) == 0
    }

@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
async def login(request: LoginRequest):
    """
    VULNERABLE: Weak authentication with poor password policy.
    
    This endpoint demonstrates:
    - Weak Password Requirements
    - Credential Stuffing vulnerability (no rate limiting)
    - Information disclosure in error messages
    """
    username = request.username
    password = request.password
    
    # VULNERABILITY: Hardcoded backdoor credentials
    if username == "backdoor" and password == "letmein":
        return LoginResponse(
            success=True,
            message="Backdoor access granted",
            token="BACKDOOR_TOKEN_12345",
            user={"username": "backdoor", "role": "superadmin"}
        )
    
    if username not in USERS_DB:
        # VULNERABILITY: Username enumeration
        raise HTTPException(
            status_code=401,
            detail=f"User '{username}' does not exist"  # Should be generic message
        )
    
    user = USERS_DB[username]
    
    if not sha256_crypt.verify(password, user["password_hash"]):
        # VULNERABILITY: Different error for wrong password
        raise HTTPException(
            status_code=401,
            detail="Incorrect password"  # Should be generic message
        )
    
    # Generate weak token (predictable)
    import hashlib
    token = hashlib.md5(f"{username}:{password}".encode()).hexdigest()
    SESSIONS[token] = username
    
    return LoginResponse(
        success=True,
        message="Login successful",
        token=token,
        user={
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    )

@app.post("/change-password", tags=["Authentication"])
async def change_password(request: PasswordChangeRequest):
    """
    VULNERABLE: Password change without proper auth or policy enforcement.
    
    This endpoint demonstrates:
    - Broken Access Control (anyone can change any password)
    - Weak Password Policy
    """
    username = request.username
    new_password = request.new_password
    
    if username not in USERS_DB:
        raise HTTPException(status_code=404, detail="User not found")
    
    # VULNERABILITY: Weak password policy check
    policy_result = check_password_strength(new_password)
    
    if not policy_result["passes_policy"]:
        return {
            "success": False,
            "message": "Password does not meet policy",
            "details": policy_result
        }
    
    # VULNERABILITY: No authentication - anyone can change any user's password!
    USERS_DB[username]["password_hash"] = sha256_crypt.hash(new_password)
    
    return {
        "success": True,
        "message": f"Password changed for user {username}",
        "policy_check": policy_result
    }

# =============================================================================
# VULNERABILITY 3: IDOR (Insecure Direct Object Reference)
# =============================================================================

@app.get("/api/user/{user_id}/profile", tags=["API"])
async def get_user_profile_by_id(user_id: int):
    """
    VULNERABLE: IDOR - Access any user's profile by changing the ID.
    """
    for user in USERS_DB.values():
        if user["id"] == user_id:
            return {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "ssn": user["ssn"],      # SENSITIVE!
                "salary": user["salary"]  # SENSITIVE!
            }
    
    raise HTTPException(status_code=404, detail="User not found")

# =============================================================================
# VULNERABILITY 4: DEBUG/ADMIN ENDPOINTS (Should be protected)
# =============================================================================

@app.get("/debug/config", tags=["Debug"])
async def get_debug_config():
    """
    VULNERABLE: Exposes internal configuration without authentication.
    """
    return {
        "debug_mode": True,
        "database_url": "sqlite:///./victim.db",
        "secret_key": "super_secret_key_12345",  # NEVER expose secrets!
        "admin_email": "admin@securisphere.local",
        "api_keys": {
            "internal": "int_key_abc123",
            "external": "ext_key_xyz789"
        }
    }

@app.get("/admin/users", tags=["Admin"])
async def admin_list_users():
    """
    VULNERABLE: Admin endpoint with no authentication.
    """
    return {
        "total_users": len(USERS_DB),
        "users": [
            {
                "id": u["id"],
                "username": u["username"],
                "email": u["email"],
                "password_hash": u["password_hash"],  # NEVER expose hashes!
                "role": u["role"],
                "ssn": u["ssn"],
                "salary": u["salary"]
            }
            for u in USERS_DB.values()
        ]
    }

# =============================================================================
# VULNERABILITY 5: SQL INJECTION SIMULATION
# =============================================================================

@app.get("/search", tags=["Search"])
async def search_users(q: str = Query(..., description="Search query")):
    """
    VULNERABLE: Simulates SQL injection behavior.
    In a real app with a database, this would be exploitable.
    """
    # Simulate SQL injection detection (for demo purposes)
    sql_patterns = ["'", '"', ";", "--", "OR", "AND", "UNION", "SELECT", "DROP"]
    
    injection_detected = any(pattern.lower() in q.lower() for pattern in sql_patterns)
    
    if injection_detected:
        # In a real vulnerable app, this might execute the SQL
        return {
            "warning": "INJECTION PATTERN DETECTED",
            "query": q,
            "simulated_response": "Query executed - data may be compromised",
            "affected_tables": ["users", "sessions", "audit_log"]
        }
    
    # Normal search behavior
    results = [
        {"username": u["username"], "email": u["email"]}
        for u in USERS_DB.values()
        if q.lower() in u["username"].lower() or q.lower() in u["email"].lower()
    ]
    
    return {"query": q, "results": results}

# =============================================================================
# API INFO ENDPOINT
# =============================================================================

@app.get("/", tags=["System"])
async def root():
    """API root - provides basic information about the vulnerable service."""
    return {
        "service": "SecuriSphere Victim API",
        "version": "1.0.0",
        "status": "running",
        "warning": "This is an intentionally vulnerable application!",
        "docs": "/docs",
        "endpoints": {
            "users": "/users/{username}",
            "login": "/login",
            "search": "/search?q=",
            "debug": "/debug/config",
            "admin": "/admin/users"
        }
    }

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
