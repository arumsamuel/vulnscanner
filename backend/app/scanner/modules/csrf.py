import httpx
from typing import List
from app.core.models import Vulnerability, Severity

async def scan(target: str, client: httpx.AsyncClient, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    try:
        resp = await client.get(target, follow_redirects=True, timeout=10)
        body = resp.text.lower()
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check for anti-CSRF tokens in forms
        has_csrf_token = any(token in body for token in [
            "csrf", "xsrf", "_token", "authenticity_token", 
            "__requestverificationtoken", "csrftoken"
        ])

        # Check SameSite cookies
        set_cookie = headers.get("set-cookie", "")
        samesite_present = "samesite" in set_cookie.lower()

        if not has_csrf_token and not samesite_present:
            findings.append(Vulnerability(
                id="csrf-missing-protection",
                name="Missing CSRF Protection",
                severity=Severity.HIGH,
                category="Session Management",
                description="No anti-CSRF tokens detected in forms and no SameSite cookie attribute set.",
                remediation="Implement CSRF tokens in all state-changing forms. Set SameSite=Strict on session cookies.",
                url=target,
                cvss_score=8.1
            ))
        elif not has_csrf_token:
            findings.append(Vulnerability(
                id="csrf-no-token",
                name="Missing CSRF Tokens",
                severity=Severity.MEDIUM,
                category="Session Management",
                description="No anti-CSRF tokens detected in forms. Relies solely on SameSite cookies.",
                remediation="Add CSRF tokens to all state-changing forms as defense in depth.",
                url=target,
                cvss_score=5.3
            ))

    except Exception:
        pass
    return findings
