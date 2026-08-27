import httpx
from typing import List, Dict, Any
from app.core.models import Vulnerability, Severity

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "name": "Missing HSTS Header",
        "severity": Severity.HIGH,
        "description": "HTTP Strict Transport Security (HSTS) header is missing. This allows SSL stripping attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    },
    "content-security-policy": {
        "name": "Missing Content Security Policy",
        "severity": Severity.MEDIUM,
        "description": "CSP header is missing. This increases risk of XSS and data injection attacks.",
        "remediation": "Implement a strict Content-Security-Policy header."
    },
    "x-frame-options": {
        "name": "Missing X-Frame-Options",
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header is missing. Site may be vulnerable to clickjacking.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
    },
    "x-content-type-options": {
        "name": "Missing X-Content-Type-Options",
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options header is missing. Browser may MIME-sniff responses.",
        "remediation": "Add 'X-Content-Type-Options: nosniff'."
    },
    "referrer-policy": {
        "name": "Missing Referrer-Policy",
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing. Sensitive URL data may leak to third parties.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
    },
    "permissions-policy": {
        "name": "Missing Permissions-Policy",
        "severity": Severity.INFO,
        "description": "Permissions-Policy header is missing. Browser features are not restricted.",
        "remediation": "Add 'Permissions-Policy' to restrict unused browser features."
    }
}

DANGEROUS_HEADERS = {
    "server": {
        "name": "Server Version Disclosure",
        "severity": Severity.LOW,
        "description": "Server header reveals software/version information.",
        "remediation": "Remove or obfuscate the Server header."
    },
    "x-powered-by": {
        "name": "X-Powered-By Header Disclosure",
        "severity": Severity.LOW,
        "description": "X-Powered-By reveals backend technology stack.",
        "remediation": "Remove the X-Powered-By header in server configuration."
    }
}

async def scan(target: str, client: httpx.AsyncClient, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    try:
        resp = await client.get(target, follow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers
        for h_name, info in REQUIRED_HEADERS.items():
            if h_name not in headers:
                findings.append(Vulnerability(
                    id=f"header-missing-{h_name}",
                    name=info["name"],
                    severity=info["severity"],
                    category="Security Headers",
                    description=info["description"],
                    remediation=info["remediation"],
                    url=target,
                    cvss_score=7.5 if info["severity"] == Severity.HIGH else 5.3 if info["severity"] == Severity.MEDIUM else 3.7
                ))

        # Check dangerous headers
        for h_name, info in DANGEROUS_HEADERS.items():
            if h_name in headers:
                findings.append(Vulnerability(
                    id=f"header-disclosure-{h_name}",
                    name=info["name"],
                    severity=info["severity"],
                    category="Information Disclosure",
                    description=f"{info['description']} Value: {headers[h_name]}",
                    remediation=info["remediation"],
                    evidence=headers[h_name],
                    url=target,
                    cvss_score=3.7
                ))

        # Check for insecure cookies
        if "set-cookie" in headers:
            cookie = headers["set-cookie"]
            issues = []
            if "secure" not in cookie.lower():
                issues.append("Missing Secure flag")
            if "httponly" not in cookie.lower():
                issues.append("Missing HttpOnly flag")
            if "samesite" not in cookie.lower():
                issues.append("Missing SameSite attribute")
            if issues:
                findings.append(Vulnerability(
                    id="cookie-insecure",
                    name="Insecure Cookie Configuration",
                    severity=Severity.MEDIUM,
                    category="Session Management",
                    description=f"Cookies set without security flags: {', '.join(issues)}.",
                    evidence=cookie[:200],
                    remediation="Set Secure, HttpOnly, and SameSite=Strict on all cookies.",
                    url=target,
                    cvss_score=5.3
                ))

    except Exception as e:
        pass
    return findings
