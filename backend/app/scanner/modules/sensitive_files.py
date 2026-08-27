import httpx
from typing import List
from app.core.models import Vulnerability, Severity

SENSITIVE_PATHS = [
    ("robots.txt", Severity.INFO, "Robots.txt exposes paths"),
    (".env", Severity.CRITICAL, "Environment file exposed"),
    (".git/config", Severity.CRITICAL, "Git repository exposed"),
    (".git/HEAD", Severity.CRITICAL, "Git repository exposed"),
    ("backup.zip", Severity.HIGH, "Backup archive exposed"),
    ("backup.sql", Severity.HIGH, "Database backup exposed"),
    ("wp-config.php.bak", Severity.CRITICAL, "WordPress config backup exposed"),
    ("config.php.bak", Severity.HIGH, "Config backup exposed"),
    (".htaccess", Severity.MEDIUM, "Apache config exposed"),
    ("crossdomain.xml", Severity.LOW, "Cross-domain policy exposed"),
    ("sitemap.xml", Severity.INFO, "Sitemap exposed"),
    ("phpinfo.php", Severity.HIGH, "PHP info page exposed"),
    (".DS_Store", Severity.LOW, "macOS metadata exposed"),
    ("admin/", Severity.MEDIUM, "Admin panel exposed"),
    ("login/", Severity.INFO, "Login page discovered"),
    ("api/", Severity.INFO, "API endpoint discovered"),
    ("swagger.json", Severity.MEDIUM, "API documentation exposed"),
    ("openapi.json", Severity.MEDIUM, "API documentation exposed"),
]

async def scan(target: str, client: httpx.AsyncClient, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    from urllib.parse import urlparse
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path, severity, desc in SENSITIVE_PATHS:
        try:
            url = f"{base}/{path}"
            resp = await client.get(url, follow_redirects=False, timeout=8)

            if resp.status_code == 200:
                content_length = len(resp.text)
                if content_length > 0 and "not found" not in resp.text.lower()[:100]:
                    findings.append(Vulnerability(
                        id=f"sensitive-file-{path.replace('/', '-').replace('.', '-')}",
                        name=f"Sensitive File Exposed: /{path}",
                        severity=severity,
                        category="Information Disclosure",
                        description=desc,
                        evidence=f"HTTP 200 | Length: {content_length} bytes",
                        remediation=f"Remove or restrict access to /{path}. Return 404/403.",
                        url=url,
                        cvss_score=7.5 if severity == Severity.CRITICAL else 5.3 if severity == Severity.HIGH else 3.7
                    ))
        except Exception:
            continue
    return findings
