import ssl
import socket
import certifi
from typing import List
from datetime import datetime
from app.core.models import Vulnerability, Severity

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"
]

async def scan(target: str, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    try:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        hostname = parsed.hostname
        port = parsed.port or 443

        if parsed.scheme != "https":
            findings.append(Vulnerability(
                id="ssl-not-used",
                name="HTTPS Not Enforced",
                severity=Severity.HIGH,
                category="SSL/TLS",
                description="Target does not use HTTPS. All traffic is transmitted in plaintext.",
                remediation="Enable HTTPS and redirect all HTTP traffic to HTTPS.",
                url=target,
                cvss_score=7.5
            ))
            return findings

        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                # Check TLS version
                if version in ("TLSv1", "TLSv1.1"):
                    findings.append(Vulnerability(
                        id="ssl-weak-tls",
                        name=f"Weak TLS Version ({version})",
                        severity=Severity.HIGH,
                        category="SSL/TLS",
                        description=f"Server supports deprecated {version} which has known vulnerabilities.",
                        remediation="Disable TLS 1.0/1.1. Enforce TLS 1.2 minimum.",
                        url=target,
                        cvss_score=7.5
                    ))

                # Check certificate expiration
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_until = (expiry - datetime.utcnow()).days
                    if days_until < 0:
                        findings.append(Vulnerability(
                            id="ssl-cert-expired",
                            name="Expired SSL Certificate",
                            severity=Severity.CRITICAL,
                            category="SSL/TLS",
                            description=f"SSL certificate expired {abs(days_until)} days ago.",
                            remediation="Renew and install a valid SSL certificate immediately.",
                            url=target,
                            cvss_score=9.1
                        ))
                    elif days_until < 30:
                        findings.append(Vulnerability(
                            id="ssl-cert-expiring",
                            name="SSL Certificate Expiring Soon",
                            severity=Severity.MEDIUM,
                            category="SSL/TLS",
                            description=f"SSL certificate expires in {days_until} days.",
                            remediation="Renew the SSL certificate before expiration.",
                            url=target,
                            cvss_score=5.3
                        ))

                # Check weak ciphers
                if cipher:
                    cipher_name = cipher[0]
                    for weak in WEAK_CIPHERS:
                        if weak.upper() in cipher_name.upper():
                            findings.append(Vulnerability(
                                id="ssl-weak-cipher",
                                name="Weak Cipher Suite",
                                severity=Severity.HIGH,
                                category="SSL/TLS",
                                description=f"Server supports weak cipher: {cipher_name}",
                                evidence=cipher_name,
                                remediation="Disable weak ciphers. Use only AES-GCM or ChaCha20-Poly1305.",
                                url=target,
                                cvss_score=7.4
                            ))
                            break

    except ssl.SSLError as e:
        findings.append(Vulnerability(
            id="ssl-error",
            name="SSL/TLS Handshake Error",
            severity=Severity.HIGH,
            category="SSL/TLS",
            description=f"SSL handshake failed: {str(e)}",
            remediation="Check SSL certificate configuration and supported protocols.",
            url=target,
            cvss_score=7.5
        ))
    except Exception as e:
        pass
    return findings
