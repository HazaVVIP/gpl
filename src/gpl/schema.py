from __future__ import annotations

import re
from typing import Optional

from .transport import TransportConfig, post_graphql

INTRO_QUERY = """{ __schema {
  queryType { name } mutationType { name } subscriptionType { name }
  types {
    name kind description
    fields(includeDeprecated:true) {
      name isDeprecated description
      args { name description defaultValue
             type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
      type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
    }
    inputFields { name description defaultValue
      type { name kind ofType { name kind ofType { name kind } } } }
    enumValues(includeDeprecated:true) { name isDeprecated description }
    possibleTypes { name kind }
  }
} }"""

DANGEROUS_MUTATION_KEYWORDS = {
    "delete",
    "remove",
    "drop",
    "destroy",
    "exec",
    "create",
    "update",
    "modify",
    "reset",
    "disable",
    "enable",
    "grant",
    "revoke",
    "upload",
    "import",
    "export",
    "change",
    "set",
    "flush",
    "purge",
}

SENSITIVE_FIELD_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[-_]?key|private[-_]?key|ssn|credit|card|auth)",
    re.IGNORECASE,
)


def fetch_schema(
    url: str,
    headers: Optional[dict[str, str]] = None,
    config: Optional[TransportConfig] = None,
    delay: float = 0.0,
) -> Optional[dict]:
    response = post_graphql(url=url, query=INTRO_QUERY, headers=headers, config=config, delay=delay)
    if not response or "data" not in response:
        return None
    data = response.get("data") or {}
    return data.get("__schema")


def query_type_name(schema: dict) -> Optional[str]:
    q = schema.get("queryType") or {}
    return q.get("name")


def mutation_type_name(schema: dict) -> Optional[str]:
    m = schema.get("mutationType") or {}
    return m.get("name")


def fields_of(schema: dict, type_name: str) -> list[dict]:
    for t in schema.get("types") or []:
        if t.get("name") == type_name:
            return t.get("fields") or []
    return []


def query_fields(schema: dict) -> list[dict]:
    name = query_type_name(schema)
    return fields_of(schema, name) if name else []


def mutation_fields(schema: dict) -> list[dict]:
    name = mutation_type_name(schema)
    return fields_of(schema, name) if name else []


def dangerous_mutations(schema: dict) -> list[str]:
    out: list[str] = []
    for field in mutation_fields(schema):
        n = field.get("name", "")
        if any(k in n.lower() for k in DANGEROUS_MUTATION_KEYWORDS):
            out.append(n)
    return sorted(set(out))


def sensitive_fields(schema: dict) -> dict[str, list[str]]:
    risky: dict[str, list[str]] = {}
    for t in schema.get("types") or []:
        if t.get("kind") != "OBJECT" or str(t.get("name", "")).startswith("__"):
            continue
        names = []
        for f in t.get("fields") or []:
            fn = f.get("name", "")
            if SENSITIVE_FIELD_PATTERN.search(fn):
                names.append(fn)
        if names:
            risky[t.get("name")] = sorted(set(names))
    return risky


def unbounded_list_queries(schema: dict) -> list[str]:
    risky: list[str] = []
    for q in query_fields(schema):
        t = q.get("type") or {}
        while t.get("kind") == "NON_NULL":
            t = t.get("ofType") or {}
        is_list = t.get("kind") == "LIST"
        if not is_list:
            continue
        arg_names = {a.get("name") for a in (q.get("args") or [])}
        if "limit" not in arg_names and "first" not in arg_names and "last" not in arg_names:
            risky.append(q.get("name", ""))
    return sorted({r for r in risky if r})
