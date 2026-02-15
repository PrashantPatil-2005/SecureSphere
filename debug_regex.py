
import re

sql_injection_patterns = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b)",
        r"(\b(UNION)\s+(ALL\s+)?SELECT\b)",
        r"(\b(OR|AND)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)",
        r"(\b(OR|AND)\s+[\'\"]?[a-zA-Z]+[\'\"]?\s*=\s*[\'\"]?[a-zA-Z]+)",
        r"([\'\"];?\s*--)",
        r"([\'\"];\s*(DROP|DELETE|INSERT|UPDATE))",
        r"(/\*.*\*/)",
        r"(\bEXEC\s+)",
        r"(\bxp_cmdshell\b)",
        r"(\bWAITFOR\s+DELAY\b)",
        r"(\bBENCHMARK\s*\()",
        r"(\bSLEEP\s*\()"
    ]
]

terms = ['laptop', 'phone', "q=' OR '1'='1"]

for term in terms:
    print(f"Testing term: {term}")
    matched = False
    for pattern in sql_injection_patterns:
        if pattern.search(term):
            print(f"  MATCH: {pattern.pattern}")
            matched = True
    if not matched:
        print("  No match")
