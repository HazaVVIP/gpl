from __future__ import annotations

from typing import Optional

from .checks import BUILTIN_CHECKS
from .models import ScanContext, ScanResult
from .schema import fetch_schema
from .transport import TransportConfig, build_auth_headers


def run_scan(
    url: str,
    mode: str = "blackbox",
    safe_mode: bool = True,
    token: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_header: str = "X-API-Key",
    cookie: Optional[str] = None,
    ca_file: Optional[str] = None,
    verify_tls: bool = True,
    retries: int = 1,
    delay: float = 0.0,
) -> ScanResult:
    ctx = ScanContext(url=url, mode=mode, safe_mode=safe_mode)
    tcfg = TransportConfig(verify_tls=verify_tls, ca_file=ca_file, retries=max(0, retries))
    headers = build_auth_headers(
        token=token,
        api_key=api_key,
        api_key_header=api_key_header,
        cookie=cookie,
    )

    schema = fetch_schema(url=url, headers=headers, config=tcfg, delay=delay)
    findings = []
    for check in BUILTIN_CHECKS:
        findings.extend(check(ctx, schema))

    metadata = {
        "schema_available": bool(schema),
        "check_count": len(BUILTIN_CHECKS),
        "safe_mode": safe_mode,
        "transport": {
            "verify_tls": verify_tls,
            "retries": retries,
            "ca_file": bool(ca_file),
        },
    }
    return ScanResult(target=url, mode=mode, safe_mode=safe_mode, findings=findings, metadata=metadata)
