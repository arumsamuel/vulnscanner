from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Literal
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Vulnerability(BaseModel):
    id: str
    name: str
    severity: Severity
    category: str
    description: str
    evidence: Optional[str] = None
    remediation: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0, le=10)

class ScanModule(str, Enum):
    HEADERS = "headers"
    SSL_TLS = "ssl_tls"
    SQLI = "sqli"
    XSS = "xss"
    CSRF = "csrf"
    SENSITIVE_FILES = "sensitive_files"
    TECH_DETECT = "tech_detect"
    PORT_SCAN = "port_scan"
    SUBDOMAIN = "subdomain"

class ScanConfig(BaseModel):
    target: HttpUrl
    modules: List[ScanModule] = Field(default_factory=lambda: list(ScanModule))
    depth: int = Field(default=1, ge=1, le=3)
    timeout: int = Field(default=10, ge=1, le=60)
    max_concurrent: int = Field(default=20, ge=1, le=100)
    follow_redirects: bool = True
    user_agent: str = "AegisScan/1.0 Security Scanner"

class ScanResult(BaseModel):
    scan_id: str
    target: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    config: ScanConfig
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)
    error_message: Optional[str] = None

class ScanProgress(BaseModel):
    scan_id: str
    status: ScanStatus
    current_module: Optional[str] = None
    progress_percent: int = Field(0, ge=0, le=100)
    message: str
    vulnerabilities_found: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
