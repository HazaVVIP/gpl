import subprocess
import sys
from pathlib import Path

from gpl.cli import SchemaIndex, build_count_companions, resolve_type, type_to_bundle


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
    assert type_to_bundle("NodeUserOrganization") == "user_organization"


def test_schema_index_and_count_companion_mapping() -> None:
    schema = {
        "queryType": {"name": "Query"},
        "types": [
            {
                "name": "Query",
                "kind": "OBJECT",
                "fields": [
                    {
                        "name": "entries",
                        "args": [],
                        "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Entry"}},
                    },
                    {"name": "entryCount", "args": [], "type": {"kind": "SCALAR", "name": "Int"}},
                ],
            },
            {
                "name": "Entry",
                "kind": "OBJECT",
                "fields": [
                    {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}},
                    {"name": "title", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                ],
            },
        ],
    }
    idx = SchemaIndex(schema)
    assert [f["name"] for f in idx.query_fields()] == ["entries", "entryCount"]
    assert [f["name"] for f in idx.scalar_fields_of("Entry")] == ["id", "title"]
    assert build_count_companions(idx).get("entries") == "entryCount"


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


def test_module_entrypoint_help_smoke() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "gpl", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "GraphQL Data Dump Tool" in proc.stdout
