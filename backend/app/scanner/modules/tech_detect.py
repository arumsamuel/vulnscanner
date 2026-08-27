import httpx
from typing import List, Dict
from app.core.models import Vulnerability, Severity

TECH_SIGNATURES: Dict[str, Dict] = {
    "wordpress": {"headers": [], "body": ["/wp-content/", "wp-json"], "severity": Severity.INFO},
    "drupal": {"headers": [], "body": ["drupal", "sites/default"], "severity": Severity.INFO},
    "jquery": {"headers": [], "body": ["jquery"], "severity": Severity.INFO},
    "react": {"headers": [], "body": ["react", "__REACT__"], "severity": Severity.INFO},
    "php": {"headers": ["x-powered-by: php"], "body": [".php"], "severity": Severity.LOW},
    "apache": {"headers": ["server: apache"], "body": [], "severity": Severity.LOW},
    "nginx": {"headers": ["server: nginx"], "body": [], "severity": Severity.LOW},
    "iis": {"headers": ["server: microsoft-iis"], "body": [], "severity": Severity.LOW},
    "aws": {"headers": ["x-amz"], "body": [], "severity": Severity.INFO},
    "cloudflare": {"headers": ["cf-ray"], "body": [], "severity": Severity.INFO},
}

async def scan(target: str, client: httpx.AsyncClient, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    try:
        resp = await client.get(target, follow_redirects=True, timeout=10)
        body = resp.text.lower()
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        detected = []

        for tech, sigs in TECH_SIGNATURES.items():
            found = False
            for h_sig in sigs["headers"]:
                h_name, h_val = h_sig.split(": ") if ": " in h_sig else (h_sig, "")
                if h_name in headers:
                    if not h_val or h_val in headers[h_name]:
                        found = True
                        break
            for b_sig in sigs["body"]:
                if b_sig in body:
                    found = True
                    break
            if found:
                detected.append(tech)

        if detected:
            findings.append(Vulnerability(
                id="tech-detected",
                name="Technology Stack Detected",
                severity=Severity.INFO,
                category="Reconnaissance",
                description=f"Detected technologies: {', '.join(detected)}.",
                evidence=f"Technologies: {', '.join(detected)}",
                remediation="Minimize information leakage via headers and response content.",
                url=target,
                cvss_score=0.0
            ))

    except Exception:
        pass
    return findings
