#!/usr/bin/env python3
# HAZLER — gql.py (Enhanced)
# Phase      : 1-Recon / 2-Weaponize / 3-Access (PoC)
# ATT&CK     : Discovery   — T1590 — Gather Victim Network Information
#              Collection  — T1213 — Data from Information Repositories
#              Execution   — T1106 — Native API (mutation abuse)
#              Credential  — T1552 — Unsecured Credentials (auth bypass PoC)
# Objective  : Full GraphQL schema recon + mutation PoC / proof-of-impact
# Depends on : Network access to GraphQL endpoint
# Run        : python gql.py --url https://target.com/graphql [OPTIONS]

"""
gql.py — GraphQL Security Tool (v3 — PoC Edition)
Usage: python gql.py --url https://target.com/graphql [OPTIONS]

v1 → v2:
  - Rate limiting (--delay), nested --generate, batching detection,
    alias bypass, --dbs schema dump, infinite loop guard

v2 → v3:
  - --poc-mutation  : 3-tier mutation authorization test
      Tier 1  Auth probe       — no-args fire, classify auth vs logic error
      Tier 2  Info disclosure  — stack traces, DB hints in error messages
      Tier 3  Dry-run (aggro)  — dummy payloads on dangerous mutations
  - Namespace mutation resolution (users→UserMutation→createUser…)
  - _snippet() evidence capture for report JSON
"""

import argparse
import json
import re
import ssl
import sys
import time
import urllib.request
import urllib.error
from typing import Optional

# ── ANSI ──────────────────────────────────────────────────────────────────────
R   = "\033[91m"
Y   = "\033[93m"
G   = "\033[92m"
B   = "\033[94m"
C   = "\033[96m"
M   = "\033[95m"
W   = "\033[97m"
DIM = "\033[2m"
BO  = "\033[1m"
RST = "\033[0m"

BANNER = f"""{C}{BO}
   ██████  ██████  ██
  ██       ██   ██ ██
  ██   ███ ██████  ██
  ██    ██ ██      ██
   ██████  ██      ███████ {RST}{DIM}  GraphQL Security Tool v3  |  Responsible Use Only{RST}
"""

SENSITIVE_PATTERNS = {
    "AUTH":      ["token","jwt","secret","password","passwd","apikey","api_key",
                  "auth","session","oauth","credential","bearer","refresh_token",
                  "access_token","private_key","signing_key"],
    "PII":       ["email","phone","mobile","address","ssn","dob","birthdate",
                  "firstname","lastname","fullname","personal","zipcode","postal",
                  "national_id","passport","gender","race","religion"],
    "FINANCIAL": ["salary","credit","card","bank","account","payment","billing",
                  "invoice","transaction","tax","ein","iban","routing"],
    "PRIVILEGE": ["role","permission","admin","superuser","isadmin","staff",
                  "privilege","acl","scope","grant","isstaff","isroot"],
    "INTERNAL":  ["debug","config","internal","environment","env","flag",
                  "feature","private","secret","webhook","cron","schedule"],
}

DANGER_MUTATIONS = ["delete","remove","drop","destroy","purge","exec","create",
                    "update","modify","reset","disable","enable","grant","revoke",
                    "upload","import","export","change","set"]

# ── HTTP ───────────────────────────────────────────────────────────────────────
def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c

def gql(url: str, query, token: str = None, timeout: int = 20,
        delay: float = 0.0) -> Optional[dict]:
    """Send a GraphQL request. `query` can be str or list (for batching)."""
    if delay:
        time.sleep(delay)
    headers = {
        "Content-Type": "application/json",
        "Accept":       "application/json",
        "User-Agent":   "Mozilla/5.0 (GQL-Tool/2.0)",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload = (
        [{"query": q} for q in query]
        if isinstance(query, list)
        else {"query": query}
    )
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=_ctx(), timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"_err": e.code}
    except Exception as e:
        return {"_err": str(e)}

# ── Introspection queries ──────────────────────────────────────────────────────
FULL_INTRO = """
{
  __schema {
    queryType    { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name isDeprecated description
        args { name description defaultValue
               type { name kind ofType { name kind ofType { name kind ofType { name kind } } } } }
        type { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
      }
      inputFields {
        name description defaultValue
        type { name kind ofType { name kind ofType { name kind } } }
      }
      enumValues(includeDeprecated: true) { name isDeprecated description }
      possibleTypes { name kind }
    }
    directives {
      name description locations
      args { name description defaultValue
             type { name kind ofType { name kind } } }
    }
  }
}
"""

# Alias-based introspection bypass — works when __schema is blocked but __type is not
ALIAS_BYPASS_TEMPLATE = """
{{
  {alias}: __type(name: "{type_name}") {{
    name
    kind
    fields(includeDeprecated: true) {{
      name
      isDeprecated
      type {{ name kind ofType {{ name kind ofType {{ name kind }} }} }}
      args {{ name type {{ name kind ofType {{ name kind }} }} }}
    }}
    inputFields {{
      name
      type {{ name kind ofType {{ name kind }} }}
    }}
    enumValues(includeDeprecated: true) {{ name }}
    possibleTypes {{ name }}
  }}
}}
"""

# Minimal type probe using alias (won't trigger simple __schema blocks)
TYPENAME_QUERY    = "{ __typename }"
ROOT_TYPE_QUERY   = "{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"

def fetch_schema(url: str, token: str = None, delay: float = 0.0) -> Optional[dict]:
    resp = gql(url, FULL_INTRO, token, delay=delay)
    if not resp or "data" not in resp or not resp["data"]:
        return None
    return resp["data"].get("__schema")

def alias_bypass_probe(url: str, type_name: str, token: str = None,
                       delay: float = 0.0) -> Optional[dict]:
    """Probe a single type via alias when __schema is blocked."""
    alias = f"t_{type_name.lower()}"
    q = ALIAS_BYPASS_TEMPLATE.format(alias=alias, type_name=type_name)
    resp = gql(url, q, token, delay=delay)
    if not resp or "data" not in resp:
        return None
    return resp["data"].get(alias)

def resolve_type(t: dict, _depth: int = 0) -> str:
    """Unwrap nested type wrappers to get final type name (loop-safe)."""
    if not t or _depth > 10:
        return "Unknown"
    kind  = t.get("kind", "")
    name  = t.get("name")
    inner = t.get("ofType")
    if kind == "NON_NULL":
        return f"{resolve_type(inner, _depth+1)}!"
    if kind == "LIST":
        return f"[{resolve_type(inner, _depth+1)}]"
    return name or "Unknown"

def user_types(schema: dict) -> list:
    return [t for t in (schema.get("types") or [])
            if not t["name"].startswith("__")]

def get_type_fields(schema: dict, type_name: str) -> list:
    for t in user_types(schema):
        if t["name"] == type_name:
            return t.get("fields") or []
    return []

# ── Display helpers ────────────────────────────────────────────────────────────
def hdr(title: str):
    print(f"\n{B}{'━'*64}{RST}")
    print(f"{BO}{W}  {title}{RST}")
    print(f"{B}{'━'*64}{RST}\n")

def row(label: str, val: str, color: str = C):
    print(f"  {DIM}{label:<28}{RST}{color}{val}{RST}")

# ── --introspect ───────────────────────────────────────────────────────────────
def cmd_introspect(url: str, token: str = None, delay: float = 0.0):
    hdr("Introspection Test")
    print(f"  {DIM}Target :{RST} {C}{url}{RST}\n")

    # Basic probe
    resp = gql(url, TYPENAME_QUERY, token, delay=delay)
    if not resp or "_err" in resp:
        err = (resp or {}).get("_err", "unreachable")
        print(f"  {R}[✗]{RST} Host unreachable — {err}")
        return False

    if "data" not in resp and "errors" not in resp:
        print(f"  {Y}[~]{RST} Response received but not GraphQL format")
        return False

    print(f"  {G}[✓]{RST} GraphQL endpoint responding")
    typename = (resp.get("data") or {}).get("__typename", "")
    if typename:
        print(f"  {G}[✓]{RST} __typename: {C}{typename}{RST}")

    # Full introspection
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"\n  {G}[✓]{RST} {BO}Introspection DISABLED{RST} {DIM}(schema not returned){RST}")
        print(f"  {DIM}  Security posture: GOOD — introspection correctly blocked{RST}")

        # ── Alias bypass attempt ─────────────────────────────────────────────
        print(f"\n  {Y}[~]{RST} Attempting alias-based introspection bypass…")
        root_resp = gql(url, ROOT_TYPE_QUERY, token, delay=delay)
        root_schema = (root_resp or {}).get("data", {}).get("__schema") if root_resp else None
        if root_schema:
            qt = root_schema.get("queryType", {}) or {}
            print(f"  {R}[!]{RST} {BO}Partial schema leaked via __schema subfield!{RST}")
            print(f"       QueryType: {C}{qt.get('name','?')}{RST}")
            qt_name = qt.get("name")
            if qt_name:
                leaked = alias_bypass_probe(url, qt_name, token, delay=delay)
                if leaked:
                    fields = leaked.get("fields") or []
                    print(f"  {R}[!]{RST} {BO}{len(fields)} query field(s) leaked via __type alias{RST}")
                    for f in fields[:10]:
                        print(f"    {R}{f['name']}{RST}")
                    if len(fields) > 10:
                        print(f"    {DIM}... +{len(fields)-10} more{RST}")
                    return "bypass"
        else:
            print(f"  {G}[✓]{RST} Alias bypass blocked — endpoint is well-hardened")
        return False

    types  = user_types(schema)
    qt     = schema.get("queryType")
    mt     = schema.get("mutationType")
    st     = schema.get("subscriptionType")
    qcount = len(get_type_fields(schema, qt["name"])) if qt else 0
    mcount = len(get_type_fields(schema, mt["name"])) if mt else 0

    print(f"\n  {R}[✗]{RST} {BO}Introspection ENABLED{RST} {R}← vulnerable{RST}\n")
    row("Types exposed",    str(len(types)))
    row("Query operations", str(qcount))
    row("Mutations",        str(mcount),  R if mcount else G)
    row("Subscriptions",    "YES" if st else "no", Y if st else DIM)
    row("Auth required",    "NO  ← anyone can dump schema" if not token else "YES (token provided)", R if not token else G)

    # ── Batching attack test ─────────────────────────────────────────────────
    print(f"\n  {Y}[~]{RST} Testing GraphQL batching attack vector…")
    batch_resp = gql(url, ["{ __typename }", "{ __typename }"], token, delay=delay)
    if isinstance(batch_resp, list):
        print(f"  {R}[!]{RST} {BO}Batching ENABLED{RST} — brute-force / DoS amplification possible")
        print(f"       Server returned {len(batch_resp)} results for 2 batched queries")
    elif isinstance(batch_resp, dict) and "errors" in batch_resp:
        print(f"  {G}[✓]{RST} Batching rejected by server")
    else:
        print(f"  {Y}[~]{RST} Batching response ambiguous — manual verification recommended")

    print(f"\n  {Y}Recommendation:{RST}")
    print(f"  {DIM}  Disable introspection in production.{RST}")
    print(f"  {DIM}  Disable query batching unless explicitly required.{RST}")
    print(f"  {DIM}  Apollo: introspection: false{RST}")
    print(f"  {DIM}  Hasura: HASURA_GRAPHQL_ENABLE_INTROSPECTION=false{RST}")
    return True

# ── --queries ──────────────────────────────────────────────────────────────────
def _render_query_list(query_type_name: str, fields: list):
    """Render available query operations for a query type."""
    print(f"  {DIM}QueryType: {query_type_name}  |  {len(fields)} operation(s){RST}\n")

    for f in fields:
        ret  = resolve_type(f.get("type", {}))
        args = f.get("args") or []
        dep  = f" {Y}[deprecated]{RST}" if f.get("isDeprecated") else ""
        print(f"  {G}{BO}{f['name']}{RST}{dep}")
        print(f"    {DIM}returns : {C}{ret}{RST}")
        for a in args:
            atype   = resolve_type(a.get("type", {}))
            default = f"  {DIM}= {a['defaultValue']}{RST}" if a.get("defaultValue") else ""
            print(f"    {DIM}arg     : {M}{a['name']}{RST}: {atype}{default}")
        if f.get("description"):
            print(f"    {DIM}desc    : {f['description']}{RST}")
        print()


def cmd_queries(url: str, token: str = None, limit: int = 0, delay: float = 0.0):
    hdr("Available Queries")
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"  {R}[✗]{RST} Introspection unavailable")
        return

    qt = schema.get("queryType")
    if not qt:
        print(f"  {DIM}No queryType defined in schema{RST}")
        return

    fields = get_type_fields(schema, qt["name"])
    if limit:
        fields = fields[:limit]

    _render_query_list(qt["name"], fields)

# ── --mutations ────────────────────────────────────────────────────────────────
def cmd_mutations(url: str, token: str = None, limit: int = 0, delay: float = 0.0):
    hdr("Available Mutations")
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"  {R}[✗]{RST} Introspection unavailable")
        return

    mt = schema.get("mutationType")
    if not mt:
        print(f"  {G}[✓]{RST} No mutationType defined — schema is read-only")
        return

    fields = get_type_fields(schema, mt["name"])
    if limit:
        fields = fields[:limit]

    print(f"  {DIM}MutationType: {mt['name']}  |  {len(fields)} mutation(s){RST}\n")

    for f in fields:
        ret        = resolve_type(f.get("type", {}))
        args       = f.get("args") or []
        is_danger  = any(k in f["name"].lower() for k in DANGER_MUTATIONS)
        color      = R if is_danger else W
        icon       = f" {R}⚠ dangerous{RST}" if is_danger else ""
        dep        = f" {Y}[deprecated]{RST}" if f.get("isDeprecated") else ""

        print(f"  {color}{BO}{f['name']}{RST}{icon}{dep}")
        print(f"    {DIM}returns : {C}{ret}{RST}")
        for a in args:
            atype   = resolve_type(a.get("type", {}))
            default = f"  {DIM}= {a['defaultValue']}{RST}" if a.get("defaultValue") else ""
            req     = f" {R}*required{RST}" if "!" in atype else ""
            print(f"    {DIM}arg     : {M}{a['name']}{RST}: {atype}{default}{req}")
        if f.get("description"):
            print(f"    {DIM}desc    : {f['description']}{RST}")
        print()

# ── --types ────────────────────────────────────────────────────────────────────
def cmd_types(url: str, token: str = None, limit: int = 0, delay: float = 0.0):
    hdr("Schema Types")
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"  {R}[✗]{RST} Introspection unavailable")
        return

    types = user_types(schema)
    if limit:
        types = types[:limit]

    kind_color = {
        "OBJECT":       G,
        "INPUT_OBJECT": M,
        "ENUM":         Y,
        "INTERFACE":    C,
        "UNION":        B,
        "SCALAR":       DIM,
    }
    grouped = {}
    for t in types:
        k = t.get("kind", "OTHER")
        grouped.setdefault(k, []).append(t)

    for kind, items in sorted(grouped.items()):
        col = kind_color.get(kind, W)
        print(f"  {col}{BO}{kind}{RST}  {DIM}({len(items)}){RST}")
        for t in items:
            fields = t.get("fields") or t.get("inputFields") or []
            enums  = t.get("enumValues") or []
            fcount = f"{DIM}  {len(fields)} fields{RST}" if fields else ""
            ecount = f"{DIM}  {len(enums)} values{RST}" if enums else ""
            print(f"    {col}{t['name']}{RST}{fcount}{ecount}")
        print()

# ── --sensitive ────────────────────────────────────────────────────────────────
def cmd_sensitive(url: str, token: str = None, limit: int = 0, delay: float = 0.0):
    hdr("Sensitive Field Scan")
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"  {R}[✗]{RST} Introspection unavailable")
        return

    results = {}
    for t in user_types(schema):
        all_fields = (t.get("fields") or []) + (t.get("inputFields") or [])
        for f in all_fields:
            fname = (f.get("name") or "").lower()
            ftype = resolve_type(f.get("type", {}))
            for cat, kws in SENSITIVE_PATTERNS.items():
                for kw in kws:
                    if kw in fname:
                        results.setdefault(cat, []).append(
                            (t["name"], f["name"], ftype)
                        )
                        break

    if not results:
        print(f"  {G}[✓]{RST} No sensitive field patterns detected")
        return

    cat_sev = {
        "AUTH":      (R, "CRITICAL"),
        "PII":       (R, "HIGH"),
        "FINANCIAL": (R, "HIGH"),
        "PRIVILEGE": (Y, "HIGH"),
        "INTERNAL":  (Y, "MEDIUM"),
    }
    total = sum(len(v) for v in results.values())
    print(f"  {R}[!]{RST} {BO}{total} sensitive field(s) found across {len(results)} category(s){RST}\n")

    for cat, hits in results.items():
        col, sev = cat_sev.get(cat, (W, "INFO"))
        displayed = hits[:limit] if limit else hits
        print(f"  {col}{BO}[{sev}] {cat}{RST}  {DIM}({len(hits)} match(es)){RST}")
        for type_name, field_name, field_type in displayed:
            print(f"    {DIM}{type_name}.{RST}{col}{BO}{field_name}{RST}  {DIM}: {field_type}{RST}")
        if limit and len(hits) > limit:
            print(f"    {DIM}... +{len(hits)-limit} more (increase -l to show){RST}")
        print()

    return results

# ── --generate ─────────────────────────────────────────────────────────────────
def _build_query_body(schema: dict, fields: list, depth: int = 1,
                      max_depth: int = 3, _visited: set = None) -> str:
    """
    Recursively build selection set.
    Resolves nested OBJECT types up to max_depth.
    Avoids circular references via _visited set.
    """
    if _visited is None:
        _visited = set()
    if depth > max_depth:
        return ""

    lines   = []
    indent  = "  " * (depth + 1)
    scalar_kinds = {"SCALAR", "ENUM", None}

    for f in fields:
        ft    = f.get("type", {})
        # Unwrap NON_NULL / LIST
        inner = ft
        while inner.get("kind") in ("NON_NULL", "LIST"):
            inner = inner.get("ofType") or {}
        inner_kind = inner.get("kind")
        inner_name = inner.get("name", "")

        if inner_kind in scalar_kinds or inner_kind is None:
            lines.append(f"{indent}{f['name']}")
        elif inner_kind == "OBJECT" and inner_name and inner_name not in _visited:
            sub_fields = get_type_fields(schema, inner_name)
            if sub_fields:
                _visited.add(inner_name)
                body = _build_query_body(schema, sub_fields, depth+1, max_depth, _visited)
                _visited.discard(inner_name)
                if body:
                    lines.append(f"{indent}{f['name']} {{")
                    lines.append(body)
                    lines.append(f"{indent}}}")
                else:
                    lines.append(f"{indent}{f['name']} {{ __typename }}")
            else:
                lines.append(f"{indent}{f['name']} {{ __typename }}")
        # INTERFACE / UNION — emit __typename for inline fragments
        elif inner_kind in ("INTERFACE", "UNION"):
            lines.append(f"{indent}{f['name']} {{ __typename }}")

    return "\n".join(lines)


def cmd_generate(url: str, token: str = None, limit: int = 0,
                 delay: float = 0.0, max_depth: int = 3) -> list:
    hdr("Auto-Generated Queries & Mutations")
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"  {R}[✗]{RST} Introspection unavailable")
        return []

    generated = []

    # ── Queries ────────────────────────────────────────────────────────────────
    qt = schema.get("queryType")
    if qt:
        qfields = get_type_fields(schema, qt["name"])
        if limit:
            qfields = qfields[:limit]
        print(f"  {G}{BO}# QUERIES  ({len(qfields)}){RST}\n")
        for f in qfields:
            args    = f.get("args") or []
            arg_def, arg_use = _build_args(args)

            inner = f.get("type", {})
            while inner.get("kind") in ("NON_NULL", "LIST"):
                inner = inner.get("ofType") or {}
            sub_fields = get_type_fields(schema, inner.get("name", ""))
            body = _build_query_body(schema, sub_fields, max_depth=max_depth) \
                   if sub_fields else "    id\n    __typename"

            gql_str = (
                f"query {f['name']}{arg_def} {{\n"
                f"  {f['name']}{arg_use} {{\n"
                f"{body}\n"
                f"  }}\n"
                f"}}"
            )
            generated.append({"type": "query", "name": f["name"], "query": gql_str})
            print(f"{C}{gql_str}{RST}\n")

    # ── Mutations ──────────────────────────────────────────────────────────────
    mt = schema.get("mutationType")
    if mt:
        mfields = get_type_fields(schema, mt["name"])
        if limit:
            mfields = mfields[:limit]
        print(f"\n  {R}{BO}# MUTATIONS  ({len(mfields)}){RST}\n")
        for f in mfields:
            args    = f.get("args") or []
            arg_def, arg_use = _build_args(args)

            inner = f.get("type", {})
            while inner.get("kind") in ("NON_NULL", "LIST"):
                inner = inner.get("ofType") or {}
            sub_fields = get_type_fields(schema, inner.get("name", ""))
            body = _build_query_body(schema, sub_fields, max_depth=max_depth) \
                   if sub_fields else "    id\n    __typename"

            gql_str = (
                f"mutation {f['name']}{arg_def} {{\n"
                f"  {f['name']}{arg_use} {{\n"
                f"{body}\n"
                f"  }}\n"
                f"}}"
            )
            generated.append({"type": "mutation", "name": f["name"], "query": gql_str})
            print(f"{R}{gql_str}{RST}\n")

    return generated


def _build_args(args: list):
    """Return (arg_def_str, arg_use_str) for a list of GraphQL args."""
    if not args:
        return "", ""
    defs, uses = [], []
    for a in args:
        atype = resolve_type(a.get("type", {}))
        defs.append(f"${a['name']}: {atype}")
        uses.append(f"{a['name']}: ${a['name']}")
    return f"({', '.join(defs)})", f"({', '.join(uses)})"


# ── --dbs ──────────────────────────────────────────────────────────────────────
def _type_to_sdl(t: dict) -> str:
    """Render a single type as SDL string."""
    kind   = t.get("kind", "")
    name   = t.get("name", "")
    desc   = t.get("description", "")
    lines  = []

    if desc:
        lines.append(f'"""{desc}"""')

    if kind == "OBJECT":
        fields = t.get("fields") or []
        possible = t.get("possibleTypes") or []
        lines.append(f"type {name} {{")
        for f in fields:
            dep  = " @deprecated" if f.get("isDeprecated") else ""
            ftype = resolve_type(f.get("type", {}))
            args  = f.get("args") or []
            arg_str = ""
            if args:
                aparts = [f"{a['name']}: {resolve_type(a.get('type',{}))}" for a in args]
                arg_str = f"({', '.join(aparts)})"
            lines.append(f"  {f['name']}{arg_str}: {ftype}{dep}")
        lines.append("}")

    elif kind == "INPUT_OBJECT":
        fields = t.get("inputFields") or []
        lines.append(f"input {name} {{")
        for f in fields:
            ftype   = resolve_type(f.get("type", {}))
            default = f" = {f['defaultValue']}" if f.get("defaultValue") else ""
            lines.append(f"  {f['name']}: {ftype}{default}")
        lines.append("}")

    elif kind == "ENUM":
        enums = t.get("enumValues") or []
        lines.append(f"enum {name} {{")
        for e in enums:
            dep = " @deprecated" if e.get("isDeprecated") else ""
            lines.append(f"  {e['name']}{dep}")
        lines.append("}")

    elif kind == "INTERFACE":
        fields = t.get("fields") or []
        lines.append(f"interface {name} {{")
        for f in fields:
            ftype = resolve_type(f.get("type", {}))
            lines.append(f"  {f['name']}: {ftype}")
        lines.append("}")

    elif kind == "UNION":
        possible = t.get("possibleTypes") or []
        members  = " | ".join(p["name"] for p in possible)
        lines.append(f"union {name} = {members}")

    elif kind == "SCALAR":
        lines.append(f"scalar {name}")

    return "\n".join(lines)


def schema_to_sdl(schema: dict) -> str:
    """Convert full __schema to SDL."""
    parts = []

    # schema block
    qt = schema.get("queryType")
    mt = schema.get("mutationType")
    st = schema.get("subscriptionType")
    if qt or mt or st:
        block = ["schema {"]
        if qt: block.append(f"  query: {qt['name']}")
        if mt: block.append(f"  mutation: {mt['name']}")
        if st: block.append(f"  subscription: {st['name']}")
        block.append("}")
        parts.append("\n".join(block))

    for t in user_types(schema):
        sdl = _type_to_sdl(t)
        if sdl.strip():
            parts.append(sdl)

    return "\n\n".join(parts)


def _build_query_template(schema: dict, field: dict, max_depth: int = 3) -> str:
    """Build a GraphQL query template for a single query field."""
    args = field.get("args") or []
    arg_def, arg_use = _build_args(args)

    inner = field.get("type", {})
    while inner.get("kind") in ("NON_NULL", "LIST"):
        inner = inner.get("ofType") or {}
    sub_fields = get_type_fields(schema, inner.get("name", ""))
    body = _build_query_body(schema, sub_fields, max_depth=max_depth) \
           if sub_fields else "    id\n    __typename"

    return (
        f"query {field['name']}{arg_def} {{\n"
        f"  {field['name']}{arg_use} {{\n"
        f"{body}\n"
        f"  }}\n"
        f"}}"
    )


def cmd_query_wizard(url: str, token: str = None, limit: int = 0,
                     delay: float = 0.0) -> dict:
    """Interactive wizard to dump selected query templates."""
    hdr("Available Queries")
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"  {R}[✗]{RST} Introspection unavailable — cannot start wizard")
        return {}

    qt = schema.get("queryType")
    if not qt:
        print(f"  {DIM}No queryType defined in schema{RST}")
        return {}

    fields = get_type_fields(schema, qt["name"])
    if limit:
        fields = fields[:limit]

    _render_query_list(qt["name"], fields)
    dumps = []

    if not fields:
        return {"query_type": qt["name"], "queries_dumped": dumps}

    print(f"  {DIM}Enter query name to dump (list, exit){RST}")
    while True:
        try:
            choice = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not choice:
            continue

        choice_lower = choice.lower()
        if choice_lower in {"exit", "quit", "q"}:
            break
        if choice_lower in {"list", "ls"}:
            _render_query_list(qt["name"], fields)
            continue

        field = next((f for f in fields if f["name"] == choice), None)
        if not field:
            print(f"  {Y}[~]{RST} Unknown query: {choice}")
            continue

        query_str = _build_query_template(schema, field)
        print(f"\n  {G}{BO}# DUMP: {field['name']}{RST}\n")
        print(f"{C}{query_str}{RST}\n")
        dumps.append({"name": field["name"], "query": query_str})

    return {
        "query_type": qt["name"],
        "query_count": len(fields),
        "queries_dumped": dumps,
    }


def cmd_dbs(url: str, token: str = None, limit: int = 0,
            delay: float = 0.0) -> dict:
    """Backward-compatible entrypoint for --dbs wizard mode."""
    return cmd_query_wizard(url, token, limit, delay=delay)


# ── --poc-mutation ─────────────────────────────────────────────────────────────
#
# Three-tier mutation PoC strategy:
#
#   Tier 1 — AUTH PROBE (zero side-effects)
#             Fire every leaf mutation with NO arguments.
#             Verdict logic:
#               "not authorized" / "unauthorized" / "forbidden"
#                 → BLOCKED  — auth wall hit first ✓
#               "required" / "must not be null" / "variable" / "argument"
#                 → AUTH_BYPASS — server reached business logic without authn ✗
#               data key present and not null
#                 → FULL_BYPASS — mutation executed without credentials ✗✗
#
#   Tier 2 — INFO DISCLOSURE
#             Parse error messages for stack traces, internal paths,
#             DB engine hints, version strings, internal type names.
#
#   Tier 3 — DRY-RUN EXECUTION  (--poc-aggro flag)
#             For DANGER mutations, inject type-valid dummy payloads
#             (UUIDs that cannot exist, pentest.invalid emails, etc.)
#             and capture whether server truly executes or rejects.
#
# Nested namespace pattern is fully resolved:
#   users (returns UserMutation) → createUser / deleteUser / updateUser …
# ──────────────────────────────────────────────────────────────────────────────

# Auth-related keywords that indicate the server hit the auth wall (GOOD)
_AUTH_BLOCK_KW = [
    "not authorized", "unauthorized", "unauthenticated", "forbidden",
    "access denied", "permission denied", "not allowed", "must be logged",
    "authentication required", "invalid token", "token expired",
    "you don't have", "you do not have", "requires authentication",
    "jwt", "bearer", "login required",
]

# Keywords indicating server reached business logic (BAD — auth bypass)
_LOGIC_REACH_KW = [
    "required", "must not be null", "cannot be null", "variable",
    "argument", "field of type", "expected type", "invalid value",
    "coercion", "scalar", "enum value", "does not exist",
    "not found", "no such", "unique constraint", "duplicate",
    "already exists", "validation",
]

# Stack trace / info disclosure keywords
_LEAK_KW = [
    "traceback", "stack trace", "exception", "at line",
    "file \"", ".py:", ".js:", ".ts:", ".rb:", ".java:",
    "null pointer", "nullpointerexception", "undefined is not",
    "syntax error at", "pg:", "mysql", "sqlite", "mongodb",
    "sequelize", "prisma", "typeorm", "knex",
    "internal server error",
]

# Dummy payload generator — produces type-valid but non-existent values
def _dummy(type_str: str) -> str:
    """Return a JSON-safe dummy value string for a given GraphQL type."""
    t = type_str.replace("!", "").replace("[", "").replace("]", "").strip().lower()
    if t in ("int", "long"):        return "0"
    if t in ("float", "decimal"):   return "0.0"
    if t in ("boolean", "bool"):    return "false"
    if t == "id":                   return '"00000000-0000-0000-0000-000000000000"'
    if "email" in t:                return '"poc-probe@pentest.invalid"'
    if "url" in t:                  return '"https://pentest.invalid"'
    if "date" in t or "time" in t:  return '"1970-01-01T00:00:00Z"'
    if "json" in t or "object" in t: return '"{}"'
    if "upload" in t:               return "null"
    return '"__poc_probe__"'

def _classify(resp: dict, query_sent: str) -> tuple:
    """
    Returns (verdict, detail, is_info_leak).
    verdict: FULL_BYPASS | AUTH_BYPASS | BLOCKED | ERROR | UNKNOWN
    """
    if not resp:
        return "ERROR", "No response", False

    if "_err" in resp:
        return "ERROR", str(resp["_err"]), False

    # data present and meaningful → full execution without auth
    data = resp.get("data")
    if data:
        # Check if every value is None/null (mutation returned null fields)
        vals = list(data.values()) if isinstance(data, dict) else []
        non_null = [v for v in vals if v is not None]
        if non_null:
            return "FULL_BYPASS", "Mutation returned data without credentials", False
        # All null but data key present = still reached business logic
        return "AUTH_BYPASS", "Mutation executed (all fields null) — reached business logic", False

    errors = resp.get("errors") or []
    if not errors:
        return "UNKNOWN", "No data and no errors in response", False

    # Concatenate all error messages for analysis
    all_msgs = " ".join(
        (e.get("message") or "")
        for e in errors
    ).lower()

    # Info disclosure check (independent of auth verdict)
    is_leak = any(kw in all_msgs for kw in _LEAK_KW)
    leak_evidence = ""
    if is_leak:
        # Grab first raw error message for the report
        leak_evidence = (errors[0].get("message") or "")[:200]

    # Auth verdict
    if any(kw in all_msgs for kw in _AUTH_BLOCK_KW):
        detail = "Auth wall reached — " + (errors[0].get("message") or "")[:120]
        return "BLOCKED", detail, is_leak

    if any(kw in all_msgs for kw in _LOGIC_REACH_KW):
        detail = "Business logic reached (no auth error) — " + (errors[0].get("message") or "")[:120]
        return "AUTH_BYPASS", detail, is_leak

    # Fallback: we got errors but can't classify
    detail = (errors[0].get("message") or "")[:120]
    return "UNKNOWN", detail, is_leak


def _resolve_mutation_tree(schema: dict, mt_name: str) -> list:
    """
    Walk the mutation namespace tree and return a flat list of:
      { "path": ["users","createUser"], "field": <field_dict>, "namespace": "UserMutation" }

    Handles both:
      - Flat:   Mutation.createUser(args) → scalar/object  (depth 1)
      - Nested: Mutation.users → UserMutation.createUser   (depth 2)

    A top-level mutation is considered a NAMESPACE if it has:
      - No required args (or zero args), AND
      - Returns an OBJECT type whose name ends with "Mutation" or contains "Mutation"
    """
    results = []
    top_fields = get_type_fields(schema, mt_name)

    for top in top_fields:
        # Unwrap the return type
        ret = top.get("type", {})
        inner = ret
        while inner.get("kind") in ("NON_NULL", "LIST"):
            inner = inner.get("ofType") or {}
        inner_name = inner.get("name", "")
        inner_kind = inner.get("kind", "")

        is_namespace = (
            inner_kind == "OBJECT"
            and "mutation" in inner_name.lower()
            and not (top.get("args") or [])
        )

        if is_namespace:
            # Recurse one level into the namespace object
            sub_fields = get_type_fields(schema, inner_name)
            if sub_fields:
                for sf in sub_fields:
                    results.append({
                        "path":      [top["name"], sf["name"]],
                        "field":     sf,
                        "namespace": inner_name,
                    })
            else:
                # Namespace type has no fields — treat top-level as leaf
                results.append({
                    "path":      [top["name"]],
                    "field":     top,
                    "namespace": None,
                })
        else:
            # Flat mutation — leaf at depth 1
            results.append({
                "path":      [top["name"]],
                "field":     top,
                "namespace": None,
            })

    return results


def _build_poc_mutation(schema: dict, entry: dict,
                        use_dummy: bool = False) -> str:
    """
    Build a GraphQL mutation string for a resolved mutation tree entry.
    If use_dummy=True, injects type-valid dummy values for required args.
    """
    field   = entry["field"]
    path    = entry["path"]     # e.g. ["users","createUser"] or ["createUser"]
    args    = field.get("args") or []

    # Build variable definitions and usages
    var_defs, var_uses = [], []
    if use_dummy:
        # Inline dummy values directly (no variables needed for dry-run)
        for a in args:
            atype = resolve_type(a.get("type", {}))
            if "!" in atype:   # required
                val = _dummy(atype)
                var_uses.append(f"{a['name']}: {val}")
            # optional args omitted
    else:
        for a in args:
            atype = resolve_type(a.get("type", {}))
            var_defs.append(f"${a['name']}: {atype}")
            var_uses.append(f"{a['name']}: ${a['name']}")

    arg_def = f"({', '.join(var_defs)})" if var_defs else ""
    arg_use = f"({', '.join(var_uses)})" if var_uses else ""

    # Build return body
    inner = field.get("type", {})
    while inner.get("kind") in ("NON_NULL", "LIST"):
        inner = inner.get("ofType") or {}
    sub_fields = get_type_fields(schema, inner.get("name", ""))
    body = _build_query_body(schema, sub_fields, max_depth=2) \
           if sub_fields else "    id\n    __typename"

    # Compose nested or flat mutation
    op_name = "".join(p.capitalize() for p in path) + "Poc"

    if len(path) == 2:
        ns, leaf = path
        lines = [
            f"mutation {op_name}{arg_def} {{",
            f"  {ns} {{",
            f"    {leaf}{arg_use} {{",
            body,
            "    }",
            "  }",
            "}",
        ]
    else:
        leaf = path[0]
        lines = [
            f"mutation {op_name}{arg_def} {{",
            f"  {leaf}{arg_use} {{",
            body,
            "  }",
            "}",
        ]
    return "\n".join(lines)


def cmd_poc_mutation(url: str, token: str = None, limit: int = 0,
                     delay: float = 0.0, aggro: bool = False) -> list:
    hdr("PoC — Mutation Authorization Test")
    schema = fetch_schema(url, token, delay=delay)
    if not schema:
        print(f"  {R}[✗]{RST} Introspection unavailable — cannot enumerate mutations")
        return []

    mt = schema.get("mutationType")
    if not mt:
        print(f"  {G}[✓]{RST} No mutationType — schema is read-only")
        return []

    tree = _resolve_mutation_tree(schema, mt["name"])
    if limit:
        tree = tree[:limit]

    total = len(tree)
    print(f"  {DIM}Resolved {total} leaf mutation(s) across all namespaces{RST}")
    print(f"  {DIM}Tier 1 : Auth probe (no args){RST}")
    if aggro:
        print(f"  {R}{BO}Tier 3 : Dry-run active (--poc-aggro) — dummy payloads will be sent{RST}")
    print()

    findings = []

    VERDICT_STYLE = {
        "FULL_BYPASS":  (R, "CRITICAL", "✗✗"),
        "AUTH_BYPASS":  (R, "HIGH",     "✗"),
        "BLOCKED":      (G, "OK",       "✓"),
        "ERROR":        (Y, "ERROR",    "~"),
        "UNKNOWN":      (Y, "UNKNOWN",  "?"),
    }

    # Group output by namespace for readability
    by_ns: dict = {}
    for entry in tree:
        ns_key = entry["path"][0] if len(entry["path"]) > 1 else "_root"
        by_ns.setdefault(ns_key, []).append(entry)

    for ns_key, entries in by_ns.items():
        ns_label = ns_key if ns_key != "_root" else "root"
        print(f"  {B}{BO}[namespace: {ns_label}]{RST}")

        for entry in entries:
            field     = entry["field"]
            path_str  = " → ".join(entry["path"])
            is_danger = any(k in field["name"].lower() for k in DANGER_MUTATIONS)

            # ── Tier 1: No-args auth probe ────────────────────────────────────
            q_noargs = _build_poc_mutation(schema, entry, use_dummy=False)
            resp1    = gql(url, q_noargs, token=None, delay=delay)
            v1, d1, leak1 = _classify(resp1, q_noargs)

            col, sev, icon = VERDICT_STYLE.get(v1, (W, "?", "?"))
            danger_tag = f" {R}⚠{RST}" if is_danger else ""
            print(f"    {col}[{icon}]{RST} {BO}{path_str}{RST}{danger_tag}  "
                  f"{col}{sev}{RST}")
            print(f"        {DIM}{d1[:100]}{RST}")

            if leak1:
                raw_err = ((resp1 or {}).get("errors") or [{}])[0].get("message","")[:200]
                print(f"        {Y}[INFO DISCLOSURE]{RST} {DIM}{raw_err}{RST}")

            # ── Tier 3: Dry-run (aggro mode, dangerous mutations only) ────────
            dryrun_result = None
            if aggro and is_danger and v1 != "BLOCKED":
                q_dummy = _build_poc_mutation(schema, entry, use_dummy=True)
                resp3   = gql(url, q_dummy, token=None, delay=delay)
                v3, d3, leak3 = _classify(resp3, q_dummy)
                col3, sev3, icon3 = VERDICT_STYLE.get(v3, (W, "?", "?"))
                print(f"        {Y}[DRY-RUN]{RST} dummy payload → "
                      f"{col3}{sev3}{RST}  {DIM}{d3[:80]}{RST}")
                dryrun_result = {
                    "query":   q_dummy,
                    "verdict": v3,
                    "detail":  d3,
                    "response_snippet": _snippet(resp3),
                }

            findings.append({
                "path":         path_str,
                "namespace":    entry.get("namespace"),
                "is_dangerous": is_danger,
                "tier1": {
                    "query":            q_noargs,
                    "verdict":          v1,
                    "detail":           d1,
                    "info_disclosure":  leak1,
                    "response_snippet": _snippet(resp1),
                },
                "tier3": dryrun_result,
            })

        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    hdr("PoC — Summary")
    counts = {}
    for f in findings:
        v = f["tier1"]["verdict"]
        counts[v] = counts.get(v, 0) + 1

    row("Total mutations tested", str(total))
    if counts.get("FULL_BYPASS"):
        row("FULL_BYPASS  (critical)", str(counts["FULL_BYPASS"]), R)
    if counts.get("AUTH_BYPASS"):
        row("AUTH_BYPASS  (high)",     str(counts["AUTH_BYPASS"]), R)
    if counts.get("BLOCKED"):
        row("BLOCKED      (ok)",       str(counts["BLOCKED"]),     G)
    if counts.get("UNKNOWN"):
        row("UNKNOWN",                 str(counts["UNKNOWN"]),     Y)
    if counts.get("ERROR"):
        row("ERROR",                   str(counts["ERROR"]),       Y)

    # Surface actionable findings
    critical = [f for f in findings if f["tier1"]["verdict"] in ("FULL_BYPASS","AUTH_BYPASS")]
    if critical:
        print(f"\n  {R}{BO}[!] Actionable findings — include in report:{RST}\n")
        for f in critical:
            v = f["tier1"]["verdict"]
            col = R
            print(f"  {col}  {v}{RST}  {BO}{f['path']}{RST}")
            print(f"         {DIM}{f['tier1']['detail'][:120]}{RST}")
            if f["tier1"]["info_disclosure"]:
                print(f"         {Y}+ info disclosure in error response{RST}")
            print(f"         Proof query:\n")
            for line in f["tier1"]["query"].split("\n"):
                print(f"           {C}{line}{RST}")
            print()
    else:
        print(f"\n  {G}[✓]{RST} No auth bypass findings — all mutations properly gated")

    return findings


def _snippet(resp: dict, max_len: int = 300) -> str:
    """Return a trimmed JSON string of the response for evidence."""
    if not resp:
        return ""
    try:
        s = json.dumps(resp)
        return s[:max_len] + ("…" if len(s) > max_len else "")
    except Exception:
        return str(resp)[:max_len]


# ── --output ───────────────────────────────────────────────────────────────────
def save_output(data: dict, path: str):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"\n  {G}[✓]{RST} Output saved → {C}{path}{RST}")


# ── Help ───────────────────────────────────────────────────────────────────────
HELP_TEXT = f"""
{C}{BO}gql.py v2 — GraphQL Security Tool{RST}

{BO}USAGE:{RST}
  python gql.py --url <endpoint> [OPTIONS]

{BO}CORE OPTIONS:{RST}
  {G}    --introspect{RST}              Test introspection + alias bypass + batching
  {G}-q, --queries{RST}                 List all queries
  {G}-m, --mutations{RST}               List all mutations
  {G}-t, --types{RST}                   List all types grouped by kind
  {G}-s, --sensitive{RST}               Grep for sensitive fields
  {G}-g, --generate{RST}                Auto-generate queries/mutations (nested-aware)
  {G}    --dbs{RST}                     Wizard mode: list queries and dump selected query templates

{BO}MODIFIERS:{RST}
  {G}    --url <endpoint>{RST}          GraphQL endpoint (required)
  {G}    --token <bearer_token>{RST}    Bearer token for auth
  {G}    --output <file>{RST}           Save results to JSON file
  {G}-l, --limit <N>{RST}              Limit results per command
  {G}    --depth <N>{RST}              Max nesting depth for --generate (default: 3)
  {G}    --delay <seconds>{RST}        Delay between requests (WAF evasion, default: 0)

{BO}EXAMPLES:{RST}
  {DIM}# Full recon: introspection + batching + alias bypass{RST}
  python gql.py --url https://target.com/graphql --introspect

  {DIM}# Interactive query dump wizard{RST}
  python gql.py --url https://target.com/graphql --dbs

  {DIM}# Scan sensitive fields with auth token{RST}
  python gql.py --url https://target.com/graphql -s --token eyJ...

  {DIM}# Generate deep nested queries (depth 5){RST}
  python gql.py --url https://target.com/graphql -g --depth 5

  {DIM}# Full pipeline with WAF evasion delay{RST}
  python gql.py --url https://target.com/graphql --introspect -q -m -t -s --delay 1.5 --output report.json

  {DIM}# Then launch interactive query dump wizard{RST}
  python gql.py --url https://target.com/graphql --dbs

{BO}SENSITIVE CATEGORIES:{RST}
  {R}CRITICAL{RST}  AUTH      — token, jwt, password, secret, apikey
  {R}HIGH{RST}      PII       — email, phone, ssn, address, birthdate
  {R}HIGH{RST}      FINANCIAL — salary, credit, bank, payment, invoice
  {Y}HIGH{RST}      PRIVILEGE — role, permission, admin, acl, scope
  {Y}MEDIUM{RST}    INTERNAL  — debug, config, env, flag, private

{BO}POC MODULE:{RST}
  {R}    --poc-mutation{RST}            Mutation authorization PoC
  {R}    --poc-aggro{RST}               Enable Tier 3 dry-run (dummy payloads on dangerous mutations)

  {DIM}Tier 1 — Auth probe  : every mutation fired with no args, no token{RST}
  {DIM}            FULL_BYPASS  → mutation executed, data returned       (CRITICAL){RST}
  {DIM}            AUTH_BYPASS  → server reached business logic, no auth wall  (HIGH){RST}
  {DIM}            BLOCKED      → auth error returned first              (OK){RST}
  {DIM}Tier 2 — Info leak   : error messages parsed for stack traces, DB hints{RST}
  {DIM}Tier 3 — Dry-run     : type-valid dummy payloads on dangerous mutations  (--poc-aggro){RST}

  {DIM}Namespace pattern fully supported:{RST}
  {DIM}  users → UserMutation → createUser / deleteUser / updateUser …{RST}

{BO}NEW IN v2:{RST}
  {C}•{RST} Rate limiting via --delay
  {C}•{RST} Nested field resolution in --generate (--depth control)
  {C}•{RST} GraphQL batching attack detection
  {C}•{RST} Alias-based introspection bypass attempt
  {C}•{RST} --dbs query dump wizard (interactive)
  {C}•{RST} --poc-mutation with namespace resolution + 3-tier testing
  {C}•{RST} Fixed resolve_type infinite loop guard
  {C}•{RST} Generated queries captured in --output JSON
"""


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--url",         default=None)
    parser.add_argument("--token",       default=None)
    parser.add_argument("--output",      default=None)
    parser.add_argument("-l","--limit",  type=int,   default=0)
    parser.add_argument("--depth",       type=int,   default=3)
    parser.add_argument("--delay",       type=float, default=0.0)
    parser.add_argument("-m","--mutations",   action="store_true")
    parser.add_argument("-q","--queries",     action="store_true")
    parser.add_argument("-t","--types",       action="store_true")
    parser.add_argument("-s","--sensitive",   action="store_true")
    parser.add_argument("-g","--generate",    action="store_true")
    parser.add_argument("--poc-mutation",    action="store_true")
    parser.add_argument("--poc-aggro",       action="store_true")
    parser.add_argument("--introspect",       action="store_true")
    parser.add_argument("--dbs",              action="store_true")
    parser.add_argument("--help",             action="store_true")
    args = parser.parse_args()

    if args.help or len(sys.argv) == 1:
        print(BANNER)
        print(HELP_TEXT)
        sys.exit(0)

    if not args.url:
        print(f"\n  {R}[✗]{RST} --url is required\n")
        print(f"  {DIM}Usage: python gql.py --url https://target.com/graphql --help{RST}\n")
        sys.exit(1)

    print(BANNER)
    print(f"  {BO}Target :{RST} {C}{args.url}{RST}")
    print(f"  {BO}Auth   :{RST} {'Bearer token provided' if args.token else f'{DIM}none{RST}'}")
    if args.delay:
        print(f"  {BO}Delay  :{RST} {Y}{args.delay}s between requests{RST}")
    print(f"  {BO}Time   :{RST} {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    output_data = {
        "target":    args.url,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    any_flag = any([args.introspect, args.mutations, args.queries,
                    args.types, args.sensitive, args.generate,
                    args.dbs, args.poc_mutation])

    if not any_flag:
        args.introspect = True

    if args.introspect:
        result = cmd_introspect(args.url, args.token, delay=args.delay)
        output_data["introspection_enabled"] = result

    if args.queries:
        cmd_queries(args.url, args.token, args.limit, delay=args.delay)

    if args.mutations:
        cmd_mutations(args.url, args.token, args.limit, delay=args.delay)

    if args.types:
        cmd_types(args.url, args.token, args.limit, delay=args.delay)

    if args.sensitive:
        sensitive_results = cmd_sensitive(args.url, args.token, args.limit, delay=args.delay)
        if sensitive_results:
            output_data["sensitive_fields"] = {
                cat: [{"type": t, "field": f, "field_type": ft}
                      for t, f, ft in hits]
                for cat, hits in sensitive_results.items()
            }

    if args.generate:
        gen = cmd_generate(args.url, args.token, args.limit,
                           delay=args.delay, max_depth=args.depth)
        output_data["generated"] = gen

    if args.dbs:
        dbs_data = cmd_dbs(args.url, args.token, args.limit, delay=args.delay)
        output_data["dbs_wizard"] = dbs_data

    if args.poc_mutation:
        poc_results = cmd_poc_mutation(
            args.url, args.token,
            limit=args.limit,
            delay=args.delay,
            aggro=args.poc_aggro,
        )
        output_data["poc_mutation"] = poc_results

    if args.output:
        save_output(output_data, args.output)


if __name__ == "__main__":
    main()
