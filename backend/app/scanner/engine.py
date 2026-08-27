import asyncio
import uuid
import time
from datetime import datetime
from typing import Dict, List, Callable
import httpx

from app.core.models import ScanResult, ScanConfig, ScanProgress, ScanStatus, Vulnerability, ScanModule
from app.core.config import get_settings

# Import modules
from app.scanner.modules import headers, ssl_tls, sqli, xss, csrf, sensitive_files, tech_detect, port_scan, subdomain

MODULE_MAP: Dict[ScanModule, Callable] = {
    ScanModule.HEADERS: headers.scan,
    ScanModule.SSL_TLS: ssl_tls.scan,
    ScanModule.SQLI: sqli.scan,
    ScanModule.XSS: xss.scan,
    ScanModule.CSRF: csrf.scan,
    ScanModule.SENSITIVE_FILES: sensitive_files.scan,
    ScanModule.TECH_DETECT: tech_detect.scan,
    ScanModule.PORT_SCAN: port_scan.scan,
    ScanModule.SUBDOMAIN: subdomain.scan,
}

class ScanEngine:
    def __init__(self):
        self.active_scans: Dict[str, ScanResult] = {}
        self.progress_callbacks: Dict[str, List[Callable]] = {}

    async def run_scan(self, config: ScanConfig, scan_id: str, progress_callback: Callable = None):
        result = ScanResult(
            scan_id=scan_id,
            target=str(config.target),
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
            config=config,
            vulnerabilities=[],
            stats={"modules_total": len(config.modules), "modules_completed": 0}
        )
        self.active_scans[scan_id] = result

        if progress_callback:
            if scan_id not in self.progress_callbacks:
                self.progress_callbacks[scan_id] = []
            self.progress_callbacks[scan_id].append(progress_callback)

        try:
            limits = httpx.Limits(max_keepalive_connections=10, max_connections=config.max_concurrent)
            timeout = httpx.Timeout(config.timeout)
            headers_dict = {"User-Agent": config.user_agent}

            async with httpx.AsyncClient(limits=limits, timeout=timeout, headers=headers_dict, verify=True) as client:
                total_modules = len(config.modules)

                for idx, module_name in enumerate(config.modules):
                    module_func = MODULE_MAP.get(module_name)
                    if not module_func:
                        continue

                    progress = ScanProgress(
                        scan_id=scan_id,
                        status=ScanStatus.RUNNING,
                        current_module=module_name.value,
                        progress_percent=int((idx / total_modules) * 100),
                        message=f"Running {module_name.value} module...",
                        vulnerabilities_found=len(result.vulnerabilities)
                    )
                    await self._emit_progress(scan_id, progress)

                    # Run module
                    try:
                        if module_name in (ScanModule.SSL_TLS, ScanModule.PORT_SCAN, ScanModule.SUBDOMAIN):
                            # These don't need the shared client
                            findings = await asyncio.wait_for(
                                module_func(str(config.target)),
                                timeout=60
                            )
                        else:
                            findings = await asyncio.wait_for(
                                module_func(str(config.target), client),
                                timeout=60
                            )

                        # Deduplicate by ID
                        existing_ids = {v.id for v in result.vulnerabilities}
                        for vuln in findings:
                            if vuln.id not in existing_ids:
                                result.vulnerabilities.append(vuln)
                                existing_ids.add(vuln.id)

                    except asyncio.TimeoutError:
                        pass
                    except Exception:
                        pass

                    result.stats["modules_completed"] = idx + 1
                    await asyncio.sleep(0.1)  # Rate limiting

                result.status = ScanStatus.COMPLETED
                result.completed_at = datetime.utcnow()
                result.stats["total_vulnerabilities"] = len(result.vulnerabilities)
                result.stats["critical"] = sum(1 for v in result.vulnerabilities if v.severity.value == "critical")
                result.stats["high"] = sum(1 for v in result.vulnerabilities if v.severity.value == "high")
                result.stats["medium"] = sum(1 for v in result.vulnerabilities if v.severity.value == "medium")
                result.stats["low"] = sum(1 for v in result.vulnerabilities if v.severity.value == "low")
                result.stats["info"] = sum(1 for v in result.vulnerabilities if v.severity.value == "info")

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error_message = str(e)

        final_progress = ScanProgress(
            scan_id=scan_id,
            status=result.status,
            progress_percent=100,
            message="Scan completed" if result.status == ScanStatus.COMPLETED else f"Scan failed: {result.error_message}",
            vulnerabilities_found=len(result.vulnerabilities)
        )
        await self._emit_progress(scan_id, final_progress)

        return result

    async def _emit_progress(self, scan_id: str, progress: ScanProgress):
        callbacks = self.progress_callbacks.get(scan_id, [])
        for cb in callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(progress)
                else:
                    cb(progress)
            except Exception:
                pass

    def get_result(self, scan_id: str) -> ScanResult | None:
        return self.active_scans.get(scan_id)

    def get_history(self) -> List[ScanResult]:
        return list(self.active_scans.values())

scan_engine = ScanEngine()
