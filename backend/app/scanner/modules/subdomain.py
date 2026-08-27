import asyncio
import socket
from typing import List
from app.core.models import Vulnerability, Severity

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns4",
    "www1", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www3", "stat", "portal", "host",
    "video", "www4", "cdn", "api", "staging", "www5", "mx1", "www6", "ns5",
    "whois", "mx2", "www7", "www8", "www9", "web2", "pay", "www10", "www11",
    "www12", "www13", "www14", "www15", "www16", "www17", "www18", "www19",
    "www20", "office", "ipv4", "ipv6", "sip", "git", "jenkins", "grafana",
    "prometheus", "kibana", "elastic", "redis", "mongo", "db", "backup",
    "assets", "static1", "static2", "files", "upload", "downloads",
]

async def resolve_subdomain(subdomain: str, host: str) -> str | None:
    try:
        full = f"{subdomain}.{host}"
        await asyncio.get_event_loop().getaddrinfo(full, None)
        return full
    except Exception:
        return None

async def scan(target: str, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return findings

    # Remove www prefix for base domain
    base_host = host.replace("www.", "")

    tasks = [resolve_subdomain(sub, base_host) for sub in DEFAULT_WORDLIST]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    found = [r for r in results if isinstance(r, str)]

    if len(found) > 10:
        findings.append(Vulnerability(
            id="subdomain-enumeration",
            name="Subdomain Enumeration",
            severity=Severity.INFO,
            category="Reconnaissance",
            description=f"Discovered {len(found)} subdomains. Large attack surface.",
            evidence=f"Sample subdomains: {', '.join(found[:5])}",
            remediation="Remove unused subdomains. Implement wildcard DNS carefully.",
            url=target,
            cvss_score=0.0
        ))

    # Check for common dev/staging exposure
    sensitive = [s for s in found if any(x in s for x in ["dev.", "test.", "staging.", "beta.", "admin.", "backup."])]
    if sensitive:
        findings.append(Vulnerability(
            id="subdomain-sensitive",
            name="Sensitive Subdomain Exposed",
            severity=Severity.MEDIUM,
            category="Reconnaissance",
            description=f"Potentially sensitive subdomains discovered: {', '.join(sensitive[:3])}",
            evidence=f"Subdomains: {', '.join(sensitive[:5])}",
            remediation="Restrict access to dev/staging environments. Use VPN or IP whitelisting.",
            url=target,
            cvss_score=5.3
        ))

    return findings
