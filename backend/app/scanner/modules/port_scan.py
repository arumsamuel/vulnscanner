import asyncio
from typing import List
from app.core.models import Vulnerability, Severity

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017]

async def scan_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def scan(target: str, **kwargs) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return findings

    open_ports = []
    tasks = [scan_port(host, port) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for port, is_open in zip(COMMON_PORTS, results):
        if is_open is True:
            open_ports.append(port)

    dangerous_ports = {
        21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 
        5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"
    }

    for port in open_ports:
        if port in dangerous_ports:
            findings.append(Vulnerability(
                id=f"port-open-{port}",
                name=f"Open Port: {port} ({dangerous_ports[port]})",
                severity=Severity.MEDIUM if port in [3306, 5432, 27017] else Severity.HIGH,
                category="Network",
                description=f"Port {port} ({dangerous_ports[port]}) is open and accessible.",
                remediation=f"Close port {port} if not required. Restrict via firewall rules.",
                url=f"{target}:{port}",
                cvss_score=6.5
            ))

    if len(open_ports) > 5:
        findings.append(Vulnerability(
            id="port-exposure",
            name="Excessive Open Ports",
            severity=Severity.LOW,
            category="Network",
            description=f"{len(open_ports)} ports are open. Reduce attack surface by closing unnecessary services.",
            remediation="Audit open ports and disable unnecessary services.",
            url=target,
            cvss_score=4.3
        ))

    return findings
