import httpx
from typing import List
from app.core.models import Vulnerability, Severity

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "" OR "1"="1",
    "' UNION SELECT NULL--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' OR 'x'='x",
    "'; DROP TABLE users;--",
    "1 AND 1=1",
    "1 AND 1=2",
]

ERROR_SIGNATURES = [
    "sql syntax", "mysql_fetch", "pg_query", "ora-", "sqlite_",
    "sqlstate", "odbc_exec", "mssql_query", "jdbc", "syntax error",
    "unclosed quotation", "quoted string not properly terminated",
    "you have an error in your sql syntax", "warning: mysql"
]

async def scan(target: str, client: httpx.AsyncClient, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(target)
    params = parse_qs(parsed.query)

    if not params:
        # Try common parameter names
        test_params = ["id", "page", "user", "product", "cat", "item", "search", "q"]
        params = {p: ["1"] for p in test_params}

    tested = set()

    for param_name, values in params.items():
        if param_name in tested:
            continue
        tested.add(param_name)

        for payload in SQLI_PAYLOADS[:5]:  # Limit for speed
            try:
                new_params = {k: v[:] for k, v in params.items()}
                new_params[param_name] = [payload]
                query = urlencode(new_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))

                resp = await client.get(test_url, follow_redirects=True, timeout=10)
                body = resp.text.lower()

                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        findings.append(Vulnerability(
                            id=f"sqli-error-{param_name}",
                            name="SQL Injection (Error-Based)",
                            severity=Severity.CRITICAL,
                            category="Injection",
                            description=f"Parameter '{param_name}' appears vulnerable to SQL injection. Database error detected.",
                            evidence=f"Payload: {payload} | Error signature: {sig}",
                            remediation="Use parameterized queries/prepared statements. Apply input validation and WAF rules.",
                            url=test_url,
                            parameter=param_name,
                            cvss_score=9.8
                        ))
                        return findings  # Found it, stop testing this param

            except Exception:
                continue

    return findings
