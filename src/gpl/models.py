from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Evidence:
    query: Optional[str] = None
    response_excerpt: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "response_excerpt": self.response_excerpt,
            "note": self.note,
        }


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    operation: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "operation": self.operation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "tags": self.tags,
            "evidence": [ev.to_dict() for ev in self.evidence],
        }


@dataclass
class ScanContext:
    url: str
    mode: str = "blackbox"
    safe_mode: bool = True


@dataclass
class ScanResult:
    target: str
    mode: str
    safe_mode: bool
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "safe_mode": self.safe_mode,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

    def max_severity(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    def fails_policy(self, threshold: str) -> bool:
        wanted = SEVERITY_ORDER.get((threshold or "none").lower(), 0)
        if wanted <= 0:
            return False
        highest = SEVERITY_ORDER.get(self.max_severity(), 0)
        return highest >= wanted
