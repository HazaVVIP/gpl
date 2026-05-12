from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "none": "none",
}


def write_json_report(result: ScanResult, output_path: str) -> str:
    path = Path(output_path)
    path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def to_sarif(result: ScanResult) -> dict:
    rules = []
    seen = set()
    sarif_results = []
    for f in result.findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append(
                {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "properties": {
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "tags": f.tags,
                        "cwe": f.cwe,
                        "owasp": f.owasp,
                    },
                }
            )
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": result.target},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "operation": f.operation,
                    "confidence": f.confidence,
                    "severity": f.severity,
                },
            }
        )

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gpl",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/HazaVVIP/gpl",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif_report(result: ScanResult, output_path: str) -> str:
    path = Path(output_path)
    path.write_text(json.dumps(to_sarif(result), indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)
