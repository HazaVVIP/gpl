import subprocess
import sys
from pathlib import Path

from gpl.cli import resolve_type, type_to_bundle


def test_resolve_type_nested_non_null_list() -> None:
    schema_type = {
        "kind": "NON_NULL",
        "ofType": {
            "kind": "LIST",
            "ofType": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}},
        },
    }
    assert resolve_type(schema_type) == "[String!]!"


def test_type_to_bundle_converts_camel_case() -> None:
    assert type_to_bundle("NodeErrdOrganization") == "errd_organization"


def test_cli_help_smoke() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, str(repo_root / "main.py"), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "GraphQL Data Dump Tool" in proc.stdout
    assert "--url <endpoint>" in proc.stdout
