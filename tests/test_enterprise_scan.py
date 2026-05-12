import json
from pathlib import Path

from gpl.cli import cmd_scan
from gpl.engine import run_scan
from gpl.models import Evidence, Finding, ScanResult
from gpl.reporting import to_sarif, write_json_report, write_sarif_report


def _sample_schema() -> dict:
    return {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "name": "Query",
                "kind": "OBJECT",
                "fields": [
                    {
                        "name": "users",
                        "args": [],
                        "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}},
                    }
                ],
            },
            {
                "name": "Mutation",
                "kind": "OBJECT",
                "fields": [
                    {
                        "name": "deleteUser",
                        "args": [{"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}],
                        "type": {"kind": "OBJECT", "name": "User"},
                    }
                ],
            },
            {
                "name": "User",
                "kind": "OBJECT",
                "fields": [
                    {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}},
                    {"name": "password", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                ],
            },
        ],
    }


def test_run_scan_emits_expected_findings(monkeypatch) -> None:
    monkeypatch.setattr("gpl.engine.fetch_schema", lambda **_: _sample_schema())
    result = run_scan(url="https://example.com/graphql", mode="authenticated", safe_mode=True)
    ids = {f.rule_id for f in result.findings}
    assert "GPL-RECON-002" in ids
    assert "GPL-AUTHZ-001" in ids
    assert "GPL-EXPO-001" in ids
    assert "GPL-DOS-001" in ids
    assert result.mode == "authenticated"
    assert result.safe_mode is True


def test_scan_result_policy_gate() -> None:
    result = ScanResult(
        target="https://example.com/graphql",
        mode="blackbox",
        safe_mode=True,
        findings=[
            Finding(
                rule_id="X-1",
                title="High finding",
                severity="high",
                confidence="high",
                description="desc",
            )
        ],
    )
    assert result.fails_policy("high") is True
    assert result.fails_policy("critical") is False


def test_reporting_json_and_sarif(tmp_path: Path) -> None:
    result = ScanResult(
        target="https://example.com/graphql",
        mode="blackbox",
        safe_mode=True,
        findings=[
            Finding(
                rule_id="X-1",
                title="Example",
                severity="medium",
                confidence="high",
                description="Example finding",
                evidence=[Evidence(note="sample")],
            )
        ],
    )

    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"

    write_json_report(result, str(json_path))
    write_sarif_report(result, str(sarif_path))

    data = json.loads(json_path.read_text())
    assert data["finding_count"] == 1

    sarif = json.loads(sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "X-1"
    assert to_sarif(result)["runs"][0]["tool"]["driver"]["name"] == "gpl"


def test_cmd_scan_policy_exit(monkeypatch) -> None:
    mock = ScanResult(
        target="https://example.com/graphql",
        mode="blackbox",
        safe_mode=True,
        findings=[
            Finding(
                rule_id="X-1",
                title="High finding",
                severity="high",
                confidence="high",
                description="desc",
            )
        ],
    )
    monkeypatch.setattr("gpl.cli.run_scan", lambda **_: mock)
    rc = cmd_scan(url="https://example.com/graphql", fail_on="high")
    assert rc == 2
