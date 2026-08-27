import httpx
from typing import List
from app.core.models import Vulnerability, Severity

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    ""><script>alert(1)</script>",
    "'"><svg onload=alert(1)>",
    "javascript:alert(1)",
]

async def scan(target: str, client: httpx.AsyncClient, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(target)
    params = parse_qs(parsed.query)

    if not params:
        test_params = ["q", "search", "name", "email", "comment", "message", "url", "redirect"]
        params = {p: ["test"] for p in test_params}

    tested = set()

    for param_name, values in params.items():
        if param_name in tested:
            continue
        tested.add(param_name)

        for payload in XSS_PAYLOADS[:3]:
            try:
                new_params = {k: v[:] for k, v in params.items()}
                new_params[param_name] = [payload]
                query = urlencode(new_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

                resp = await client.get(test_url, follow_redirects=True, timeout=10)
                body = resp.text

                # Check if payload is reflected without encoding
                if payload in body:
                    findings.append(Vulnerability(
                        id=f"xss-reflected-{param_name}",
                        name="Reflected Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH,
                        category="XSS",
                        description=f"Parameter '{param_name}' reflects user input without proper sanitization.",
                        evidence=f"Payload reflected: {payload[:50]}",
                        remediation="Implement context-aware output encoding. Use CSP. Validate and sanitize all inputs.",
                        url=test_url,
                        parameter=param_name,
                        cvss_score=8.8
                    ))
                    return findings

            except Exception:
                continue

    return findings
