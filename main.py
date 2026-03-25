#!/usr/bin/env python3
"""
gql.py — GraphQL Data Dump Tool  (async edition)
Usage: python gql.py --url <endpoint> [OPTIONS]

Performance stack (stdlib only, no pip required):
  • concurrent.futures.ThreadPoolExecutor  — parallel count scan
  • asyncio + run_in_executor             — async orchestration
  • http.client keep-alive pool           — persistent connections
  • dict-indexed schema cache             — O(1) type lookup
"""

import argparse, asyncio, json, os, re, ssl, sys, time
import http.client, urllib.parse, threading
import concurrent.futures
from typing import Optional

# ── ANSI ────────────────────────────────────────────────────────────────────────
R,Y,G,B,C,M,W,DIM,BO,RST = (
    "\033[91m","\033[93m","\033[92m","\033[94m","\033[96m",
    "\033[95m","\033[97m","\033[2m","\033[1m","\033[0m"
)
BANNER = (f"{C}{BO}\n"
    "   \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588\n"
    "  \u2588\u2588       \u2588\u2588   \u2588\u2588 \u2588\u2588\n"
    "  \u2588\u2588   \u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588\n"
    "  \u2588\u2588    \u2588\u2588 \u2588\u2588      \u2588\u2588\n"
    f"   \u2588\u2588\u2588\u2588\u2588\u2588  \u2588\u2588      \u2588\u2588\u2588\u2588\u2588\u2588\u2588"
    f"{RST}{DIM}  GraphQL Data Dump Tool  |  Authorized Use Only{RST}\n")
ENUM_LITERAL_RE = re.compile(r"^[_A-Za-z][_0-9A-Za-z]*$")

# ── Connection pool ──────────────────────────────────────────────────────────────
# One persistent HTTPS connection per thread — avoids TCP handshake overhead
_pool_lock  = threading.Lock()
_conn_pool: dict[str, http.client.HTTPSConnection] = {}   # key = thread_id:host

def _get_conn(host: str, use_ssl: bool) -> http.client.HTTPSConnection:
    key = f"{threading.get_ident()}:{host}"
    with _pool_lock:
        conn = _conn_pool.get(key)
        if conn is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn = (http.client.HTTPSConnection(host, context=ctx, timeout=25)
                    if use_ssl else http.client.HTTPConnection(host, timeout=25))
            _conn_pool[key] = conn
    return conn

def _gql_raw(url: str, query: str, token: Optional[str] = None,
              delay: float = 0.0) -> Optional[dict]:
    """
    Low-level GraphQL POST using persistent http.client connection.
    Falls back to a fresh connection on BrokenPipe / RemoteDisconnected.
    """
    if delay:
        time.sleep(delay)
    parsed  = urllib.parse.urlparse(url)
    host    = parsed.netloc
    path    = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    body    = json.dumps({"query": query}).encode()
    headers = {
        "Content-Type":   "application/json",
        "Accept":         "application/json",
        "User-Agent":     "Mozilla/5.0 (GQL-Tool/4.0)",
        "Content-Length": str(len(body)),
        "Connection":     "keep-alive",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(2):
        try:
            conn = _get_conn(host, use_ssl)
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            raw  = resp.read()
            return json.loads(raw.decode())
        except (http.client.RemoteDisconnected,
                http.client.CannotSendRequest,
                ConnectionResetError,
                BrokenPipeError):
            # Stale connection — close, remove from pool, retry once
            key = f"{threading.get_ident()}:{host}"
            with _pool_lock:
                old = _conn_pool.pop(key, None)
                if old:
                    try: old.close()
                    except: pass
            if attempt == 1:
                return {"_err": "connection failed after retry"}
        except Exception as e:
            return {"_err": str(e)}
    return {"_err": "unreachable"}

def gql(url: str, query: str, token: Optional[str] = None,
        delay: float = 0.0) -> Optional[dict]:
    return _gql_raw(url, query, token, delay)

# ── Introspection ────────────────────────────────────────────────────────────────
INTRO = """{ __schema {
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

def fetch_schema(url: str, token: Optional[str] = None,
                 delay: float = 0.0) -> Optional[dict]:
    r = gql(url, INTRO, token, delay=delay)
    if not r or "data" not in r or not r["data"]: return None
    return r["data"].get("__schema")

# ── Schema index (O(1) lookup) ───────────────────────────────────────────────────
class SchemaIndex:
    """
    Wraps the raw __schema dict and provides O(1) type access via
    a pre-built dict index instead of linear list scans.
    """
    def __init__(self, schema: dict):
        self._raw = schema
        self._idx: dict[str, dict] = {
            t["name"]: t
            for t in (schema.get("types") or [])
            if not t["name"].startswith("__")
        }

    # ── accessors ────────────────────────────────────────────────────────────────
    @property
    def raw(self) -> dict:          return self._raw
    def get(self, name: str) -> dict: return self._idx.get(name, {})
    def all_types(self) -> list:    return list(self._idx.values())

    def query_fields(self) -> list:
        qt = self._raw.get("queryType")
        return self.fields_of(qt["name"]) if qt else []

    def mutation_fields(self) -> list:
        mt = self._raw.get("mutationType")
        return self.fields_of(mt["name"]) if mt else []

    def fields_of(self, type_name: str) -> list:
        return self._idx.get(type_name, {}).get("fields") or []

    def concrete_types_of(self, type_name: str) -> list:
        t = self._idx.get(type_name, {})
        k = t.get("kind","")
        if k in ("UNION","INTERFACE"):
            return [p["name"] for p in (t.get("possibleTypes") or [])]
        if k == "OBJECT":
            return [type_name]
        return []

    def scalar_fields_of(self, type_name: str) -> list:
        t = self._idx.get(type_name, {})
        out = []
        for f in (t.get("fields") or []):
            # Skip fields that require arguments — they cannot be queried bare
            if any("!" in resolve_type(a.get("type",{}))
                   for a in (f.get("args") or [])):
                continue
            base = resolve_type(f.get("type",{})).replace("!","").replace("[","").replace("]","").strip()
            bt   = self._idx.get(base, {})
            kind = bt.get("kind","SCALAR") if bt else "SCALAR"
            if kind in ("SCALAR","ENUM") or not bt:
                out.append({"name": f["name"],
                             "gql_type": resolve_type(f.get("type",{}))})
        return out

    def resolve_return(self, field: dict) -> tuple:
        """Returns (wrapper_name, entity_name, pattern)
        pattern: 'drupal' | 'union' | 'object' | 'scalar'"""
        inner = field.get("type",{})
        while inner.get("kind") in ("NON_NULL","LIST"):
            inner = inner.get("ofType") or {}
        ret = inner.get("name","")
        t   = self._idx.get(ret, {})
        k   = t.get("kind","")
        if k in ("UNION","INTERFACE"):
            return ret, ret, "union"
        if k == "OBJECT":
            sub = self.fields_of(ret)
            if any(f["name"]=="entities" for f in sub):
                ef = next(f for f in sub if f["name"]=="entities")
                ei = ef.get("type",{})
                while ei.get("kind") in ("NON_NULL","LIST"):
                    ei = ei.get("ofType") or {}
                return ret, ei.get("name",ret), "drupal"
            return ret, ret, "object"
        return ret, ret, "scalar"

# ── Type helpers ─────────────────────────────────────────────────────────────────
def resolve_type(t: dict, _d: int = 0) -> str:
    if not t or _d > 10: return "Unknown"
    k, n, i = t.get("kind",""), t.get("name"), t.get("ofType")
    if k == "NON_NULL": return f"{resolve_type(i,_d+1)}!"
    if k == "LIST":     return f"[{resolve_type(i,_d+1)}]"
    return n or "Unknown"

def type_to_bundle(ctype: str) -> str:
    """NodeErrdOrganization → errd_organization"""
    name = ctype
    for pfx in ("Node","TaxonomyTerm","BlockContent","Comment","ContactMessage",
                "WebformSubmission","FeedsFeed","MenuLinkContent","Shortcut",
                "User","File"):
        if name.startswith(pfx): name = name[len(pfx):]; break
    return re.sub(r'(?<!^)(?=[A-Z])','_', name).lower()

def best_type(idx: SchemaIndex, qfield: dict, concretes: list) -> Optional[str]:
    if not concretes:         return None
    if len(concretes) == 1:   return concretes[0]
    qname = qfield["name"].lower()
    for pfx in ("Node","User","File","Comment","TaxonomyTerm","BlockContent",
                "ContactMessage","WebformSubmission","FeedsFeed","MenuLinkContent",
                "Shortcut","PathAlias","SearchApiTask","ContentModerationState"):
        if qname.startswith(pfx.lower()):
            m = [ct for ct in concretes if ct.startswith(pfx)]
            if m: return max(m, key=lambda ct: len(idx.scalar_fields_of(ct)))
    return max(concretes, key=lambda ct: len(idx.scalar_fields_of(ct)))

# ── Companion count map ──────────────────────────────────────────────────────────
def build_count_companions(idx: SchemaIndex) -> dict[str, str]:
    """
    Build a map {list_query_name → count_query_name} by scanning for queries
    that return a bare Int scalar (likely count companions).

    Matching heuristic (order of priority):
      1. Exact: fname + "Count"           entries     → entryCount   (no match)
      2. Strip trailing 's': fname[:-1] + "Count"     entries → entryCount ✓
      3. Strip trailing 'ies'+'y': fname[:-3]+'y'+"Count"  categories → categoryCount ✓
      4. Prefix match: if count query starts with fname[:4]
    """
    all_fields = idx.query_fields()
    # Collect all Int-returning, no-required-arg query names
    count_queries: set[str] = set()
    for f in all_fields:
        if any("!" in resolve_type(a.get("type",{})) for a in (f.get("args") or [])):
            continue
        ret = resolve_type(f.get("type",{})).replace("!","").replace("[","").replace("]","").strip()
        t   = idx.get(ret)
        # Bare scalar Int return
        if (not t or t.get("kind","") == "SCALAR") and ret in ("Int","Float","Number"):
            count_queries.add(f["name"])
        # Also catch any name ending in "Count" or "count" that returns scalar
        if f["name"].lower().endswith("count") and (not t or t.get("kind","SCALAR") == "SCALAR"):
            count_queries.add(f["name"])

    def _is_list_field(f):
        t = f.get("type", {})
        while t.get("kind") == "NON_NULL":
            t = t.get("ofType") or {}
        return t.get("kind") == "LIST"

    result: dict[str, str] = {}
    for f in all_fields:
        fname = f["name"]
        if fname in count_queries:
            continue
        # Only list-returning queries get a companion — skip singular queries
        if not _is_list_field(f):
            continue
        # Try to find a matching count query
        candidates = [
            fname + "Count",
            fname.rstrip("s") + "Count",
            (fname[:-3] + "y" + "Count") if fname.endswith("ies") else None,
            (fname[:-1] + "Count") if fname.endswith("s") else None,
        ]
        for c in candidates:
            if c and c in count_queries:
                result[fname] = c
                break

    return result


# ── Async count scan ─────────────────────────────────────────────────────────────
def _count_one(args: tuple) -> tuple[str, Optional[int | str]]:
    """
    Worker: fire a single count query. Returns (fname, count).

    Priority:
      1. Companion count query   e.g. entryCount, userCount
      2. Drupal wrapper count    { query { count } }
      3. totalCount field        { query { totalCount } }
      4. No-limit list probe     { query(limit:9999) { __typename } } → len
      5. Fallback: ?
    """
    url, field, idx, token, delay, companions = args
    fname     = field["name"]
    has_limit = any(a["name"]=="limit" for a in (field.get("args") or []))
    _, _, pat = idx.resolve_return(field)

    # ── 1. Companion count query ──────────────────────────────────────────────────
    companion = companions.get(fname)
    if companion:
        r = gql(url, f"{{ {companion} }}", token, delay=delay)
        if r and "_err" not in r:
            d = (r.get("data") or {}).get(companion)
            if isinstance(d, int):   return fname, d
            if isinstance(d, float): return fname, int(d)

    # ── 2. Drupal wrapper { count } ───────────────────────────────────────────────
    if pat == "drupal":
        arg_s = "(limit: 1)" if has_limit else ""
        r = gql(url, f"{{ {fname}{arg_s} {{ count }} }}", token, delay=delay)
        if r and "_err" not in r:
            d = (r.get("data") or {}).get(fname)
            if isinstance(d, dict) and "count" in d:
                return fname, d["count"]

    # ── 3. totalCount field ───────────────────────────────────────────────────────
    arg_s = "(limit: 1)" if has_limit else ""
    r = gql(url, f"{{ {fname}{arg_s} {{ totalCount }} }}", token, delay=delay)
    if r and "_err" not in r:
        d = (r.get("data") or {}).get(fname)
        if isinstance(d, dict) and "totalCount" in d:
            return fname, d["totalCount"]

    # ── 4. No-limit list probe (accurate but heavier) ─────────────────────────────
    # Only use if query supports limit arg — fire with high limit to get real count
    if has_limit:
        # First try a big limit to count actual records
        r = gql(url, f"{{ {fname}(limit: 10000) {{ __typename }} }}", token, delay=delay)
        if r and "_err" not in r:
            d = (r.get("data") or {}).get(fname)
            if isinstance(d, list):
                return fname, len(d)

    # ── 5. Probe without limit ────────────────────────────────────────────────────
    r = gql(url, f"{{ {fname} {{ __typename }} }}", token, delay=delay)
    if r and "_err" not in r:
        d = (r.get("data") or {}).get(fname)
        if isinstance(d, list):  return fname, len(d)
        if isinstance(d, dict):  return fname, "?"
        if d is not None:        return fname, "?"

    return fname, None

async def async_scan_counts(url: str, fields: list, idx: SchemaIndex,
                            token: Optional[str], delay: float,
                            concurrency: int = 8) -> dict:
    """
    Fire all count queries in parallel using a ThreadPoolExecutor.
    Companion count queries (entryCount, userCount …) are used automatically
    for accurate totals on non-Drupal list endpoints.
    """
    companions = build_count_companions(idx)
    total  = len(fields)
    done   = 0
    results: dict = {}

    def _progress(fname: str, cnt):
        nonlocal done
        done += 1
        bar_w  = 24
        filled = int(bar_w * done / total)
        bar    = f"{G}{'█'*filled}{DIM}{'░'*(bar_w-filled)}{RST}"
        cnt_s  = f"{G}{cnt:,}{RST}" if isinstance(cnt, int) and cnt else f"{DIM}—{RST}"
        sys.stdout.write(
            f"\r  {bar} {DIM}[{done}/{total}]{RST}  "
            f"{DIM}{fname[:28]:<28}{RST}  {cnt_s}   "
        )
        sys.stdout.flush()

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        tasks = [
            loop.run_in_executor(
                pool, _count_one,
                (url, f, idx, token, delay, companions)
            )
            for f in fields
        ]
        for coro in asyncio.as_completed(tasks):
            fname, cnt = await coro
            results[fname] = cnt
            _progress(fname, cnt)

    sys.stdout.write("\r" + " "*80 + "\r")
    sys.stdout.flush()
    return results

# ── Display helpers ──────────────────────────────────────────────────────────────
def hdr(title: str):
    print(f"\n{B}{'━'*64}{RST}\n{BO}{W}  {title}{RST}\n{B}{'━'*64}{RST}\n")

def save_output(data: dict, path: str):
    with open(path,"w") as f: json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\n  {G}[✓]{RST} Saved → {C}{path}{RST}")

# ── -q ───────────────────────────────────────────────────────────────────────────
def cmd_queries(url: str, token: Optional[str] = None, delay: float = 0.0):
    hdr("Available Queries")
    raw = fetch_schema(url, token, delay=delay)
    if not raw: print(f"  {R}[✗]{RST} Introspection unavailable"); return
    idx    = SchemaIndex(raw)
    fields = idx.query_fields()
    qt     = raw.get("queryType",{})
    print(f"  {DIM}QueryType: {qt.get('name','?')}  |  {len(fields)} operation(s){RST}\n")
    for f in fields:
        dep = f" {Y}[deprecated]{RST}" if f.get("isDeprecated") else ""
        print(f"  {G}{BO}{f['name']}{RST}{dep}")
        print(f"    {DIM}returns : {C}{resolve_type(f.get('type',{}))}{RST}")
        for a in (f.get("args") or []):
            print(f"    {DIM}arg     : {M}{a['name']}{RST}: {resolve_type(a.get('type',{}))}")
        if f.get("description"): print(f"    {DIM}desc    : {f['description']}{RST}")
        print()

# ── -m ───────────────────────────────────────────────────────────────────────────
def cmd_mutations(url: str, token: Optional[str] = None, delay: float = 0.0):
    hdr("Available Mutations")
    raw = fetch_schema(url, token, delay=delay)
    if not raw: print(f"  {R}[✗]{RST} Introspection unavailable"); return
    idx    = SchemaIndex(raw)
    fields = idx.mutation_fields()
    if not fields: print(f"  {G}[✓]{RST} No mutations — read-only schema"); return
    DANGER = {"delete","remove","drop","destroy","exec","create","update","modify",
              "reset","disable","enable","grant","revoke","upload","import","export",
              "change","set","flush","purge"}
    mt = raw.get("mutationType",{})
    print(f"  {DIM}MutationType: {mt.get('name','?')}  |  {len(fields)} mutation(s){RST}\n")
    for f in fields:
        dep = f" {Y}[deprecated]{RST}" if f.get("isDeprecated") else ""
        bad = any(k in f["name"].lower() for k in DANGER)
        col, ico = (R, f" {R}⚠{RST}") if bad else (W, "")
        print(f"  {col}{BO}{f['name']}{RST}{ico}{dep}")
        print(f"    {DIM}returns : {C}{resolve_type(f.get('type',{}))}{RST}")
        for a in (f.get("args") or []):
            at = resolve_type(a.get("type",{}))
            print(f"    {DIM}arg     : {M}{a['name']}{RST}: {at}{f' {R}*{RST}' if '!' in at else ''}")
        if f.get("description"): print(f"    {DIM}desc    : {f['description']}{RST}")
        print()

# ── -t ───────────────────────────────────────────────────────────────────────────
def cmd_types(url: str, token: Optional[str] = None, delay: float = 0.0):
    hdr("Schema Types")
    raw = fetch_schema(url, token, delay=delay)
    if not raw: print(f"  {R}[✗]{RST} Introspection unavailable"); return
    idx = SchemaIndex(raw)
    KC  = {"OBJECT":G,"INPUT_OBJECT":M,"ENUM":Y,"INTERFACE":C,"UNION":B,"SCALAR":DIM}
    grouped: dict = {}
    for t in idx.all_types(): grouped.setdefault(t.get("kind","?"),[]).append(t)
    for kind, items in sorted(grouped.items()):
        col = KC.get(kind, W)
        print(f"  {col}{BO}{kind}{RST}  {DIM}({len(items)}){RST}")
        for t in items:
            fc = f"  {DIM}{len(t.get('fields') or t.get('inputFields') or [])} fields{RST}"
            ec = f"  {DIM}{len(t.get('enumValues') or [])} values{RST}" if t.get("enumValues") else ""
            print(f"    {col}{t['name']}{RST}{fc}{ec}")
        print()

# ── --dbs wizard ─────────────────────────────────────────────────────────────────
async def _dbs_async(url: str, token: Optional[str], delay: float,
                     output_path: Optional[str], concurrency: int) -> dict:
    """
    Full async dump wizard.
    - Schema fetch         : single HTTP call
    - Count scan (Step 1)  : all queries fired in parallel (ThreadPoolExecutor)
    - Final dump query     : single HTTP call
    - Wizard loop          : synchronous (stdin)
    """

    # ── startup ───────────────────────────────────────────────────────────────────
    hdr("Data Dump Wizard  (--dbs)")
    t0 = time.perf_counter()
    sys.stdout.write(f"  {DIM}Fetching schema …{RST}"); sys.stdout.flush()

    loop = asyncio.get_event_loop()
    raw  = await loop.run_in_executor(None, fetch_schema, url, token, delay)
    sys.stdout.write("\r" + " "*40 + "\r"); sys.stdout.flush()

    if not raw:
        print(f"  {R}[✗]{RST} Introspection unavailable"); return {}

    idx    = SchemaIndex(raw)
    qfields = idx.query_fields()
    if not qfields:
        print(f"  {R}[✗]{RST} No queryType"); return {}

    countable = [f for f in qfields
                 if not any("!" in resolve_type(a.get("type",{}))
                            for a in (f.get("args") or []))]
    manual    = [f for f in qfields if f not in countable]
    all_q     = countable + manual

    # ── Step 1: parallel count scan ───────────────────────────────────────────────
    print(f"  {DIM}Scanning {len(countable)} queries in parallel (concurrency={concurrency}) …{RST}\n")
    counts = await async_scan_counts(url, countable, idx, token, delay, concurrency)
    elapsed = time.perf_counter() - t0
    print(f"  {G}[✓]{RST} Scan complete — {elapsed:.1f}s\n")

    # ── Step 2: query table ───────────────────────────────────────────────────────
    hdr("Select a Query")
    cw = max(len(f["name"]) for f in all_q) + 2
    print(f"  {DIM}{'':4}  {'Query':<{cw}}  Count{RST}\n")
    for i, f in enumerate(all_q, 1):
        fn = f["name"]; is_m = f in manual; cnt = counts.get(fn)
        if is_m:          cs = f"{DIM}needs args{RST}"
        elif cnt is None: cs = f"{DIM}—{RST}"
        elif cnt == 0:    cs = f"{DIM}0{RST}"
        elif cnt == "?":  cs = f"{DIM}?{RST}"
        else:             cs = f"{G}{cnt:,}{RST}"
        hi = cnt and cnt not in (0,"?") and not is_m
        nm = f"{C}{BO}{fn}{RST}" if hi else f"{DIM}{fn}{RST}"
        print(f"  {DIM}[{i:>3}]{RST}  {nm:<{cw+20}}  {cs}")

    print(f"\n  {DIM}Enter number or name.  "
          f"{Y}ls{RST}{DIM}=list  {Y}save <f>{RST}{DIM}=export  {Y}exit{RST}{DIM}=quit{RST}")

    all_results: dict = {}

    # ── wizard loop ───────────────────────────────────────────────────────────────
    while True:
        try:    raw_in = input(f"\n  {B}{BO}dbs>{RST} ").strip()
        except (EOFError, KeyboardInterrupt): print(); break
        if not raw_in: continue
        cl = raw_in.lower()

        if cl in ("exit","quit","q"): print(f"\n  {G}[✓]{RST} Done.\n"); break
        if cl == "clear": os.system("clear" if os.name != "nt" else "cls"); continue

        if cl in ("ls","list"):
            print(f"\n  {DIM}{'':4}  {'Query':<{cw}}  Count{RST}\n")
            for i, f in enumerate(all_q, 1):
                fn = f["name"]; cnt = counts.get(fn); is_m = f in manual
                cs = (f"{Y}needs args{RST}" if is_m
                      else f"{G}{cnt:,}{RST}" if cnt and cnt not in (0,"?")
                      else f"{DIM}{cnt if cnt is not None else '—'}{RST}")
                print(f"  {DIM}[{i:>3}]{RST}  {fn:<{cw}}  {cs}")
            continue

        if cl.startswith("save "):
            p = raw_in.split(None,1)
            if len(p)<2: print(f"  {Y}Usage: save <file.json>{RST}"); continue
            save_output({"target":url, "timestamp":time.strftime("%Y-%m-%dT%H:%M:%S"),
                         "results":all_results}, p[1].strip()); continue

        # ── resolve query ──────────────────────────────────────────────────────────
        tgt = None
        if raw_in.isdigit():
            ix = int(raw_in)-1
            if 0<=ix<len(all_q): tgt = all_q[ix]
            else: print(f"  {Y}Pick 1–{len(all_q)}.{RST}"); continue
        else:
            m = [f for f in all_q if raw_in.lower() in f["name"].lower()]
            if len(m)==1:   tgt = m[0]
            elif len(m)>1:  print(f"  {Y}Ambiguous: {', '.join(f['name'] for f in m[:5])}{RST}"); continue
            else:           print(f"  {Y}No match. Type ls to list.{RST}"); continue

        fn = tgt["name"]
        print(f"\n  {G}[✓]{RST}  {C}{BO}{fn}{RST}")
        if tgt.get("description"): print(f"       {DIM}{tgt['description']}{RST}")

        # ── arguments ──────────────────────────────────────────────────────────────
        arg_vals: dict = {}
        # Track args that should be emitted as raw GraphQL literals (enums, lists, input objects)
        raw_args: set[str] = set()
        cancelled = False
        all_args = tgt.get("args") or []
        req_args = [a for a in all_args if "!" in resolve_type(a.get("type",{}))]
        # limit handled via dedicated prompt
        opt_args = [a for a in all_args if a not in req_args and a.get("name") != "limit"]

        def collect_arg(a: dict, required: bool) -> None:
            """Nested helper that fills arg_vals/raw_args and may set cancelled.

            Args:
                a: GraphQL argument definition dict from introspection.
                required: Whether the argument must be provided.
            """
            nonlocal cancelled
            at   = resolve_type(a.get("type",{}))
            base = at.replace("!","").replace("[","").replace("]","").strip()
            bt   = idx.get(base)
            kind = bt.get("kind","SCALAR") if bt else "SCALAR"
            listy = at.strip().startswith("[")
            req_m = f"  {R}*{RST}" if required else ""
            default_value = a.get("defaultValue")
            default_value_str = (f"  {DIM}default={default_value}{RST}"
                                 if default_value not in (None, "") else "")
            print(f"  {G}{a['name']}{RST}  {DIM}({at}){RST}{req_m}{default_value_str}")
            enum_values = [e["name"] for e in (bt.get("enumValues") or [])] if kind == "ENUM" else []
            if kind == "ENUM":
                for ei, ev in enumerate(enum_values, 1):
                    print(f"    {DIM}[{ei}]{RST} {Y}{ev}{RST}")
            if listy:
                print(f"    {DIM}Use list literal, e.g., [...] {RST}")
            elif kind == "INPUT_OBJECT":
                print(f"    {DIM}Use input literal, e.g., {{...}} {RST}")
            while True:
                try:    v = input(f"  {DIM}>{RST} ").strip()
                except (EOFError,KeyboardInterrupt): cancelled = True; return
                if v.lower() == "cancel": cancelled = True; return
                if not v:
                    if required: print(f"  {Y}Required.{RST}"); continue
                    return
                if listy:
                    if v.startswith("[") and v.endswith("]"):
                        arg_vals[a["name"]] = v
                        raw_args.add(a["name"])
                        return
                    print(f"  {Y}Use [...] for list values.{RST}"); continue
                if kind == "INPUT_OBJECT":
                    if v.startswith("{") and v.endswith("}"):
                        arg_vals[a["name"]] = v
                        raw_args.add(a["name"])
                        return
                    print(f"  {Y}Use {{...}} for input object values.{RST}"); continue
                if kind == "ENUM":
                    if v.isdigit():
                        selected_index = int(v) - 1
                        if 0 <= selected_index < len(enum_values):
                            arg_vals[a["name"]] = enum_values[selected_index]
                            raw_args.add(a["name"])
                            return
                        print(f"  {Y}Pick 1–{len(enum_values)}{RST}"); continue
                    if not enum_values:
                        if not ENUM_LITERAL_RE.match(v):
                            print(f"  {Y}Enum literal required (e.g., VALUE_NAME).{RST}"); continue
                        arg_vals[a["name"]] = v
                        raw_args.add(a["name"])
                        return
                    if v not in enum_values:
                        print(f"  {Y}Pick one of: {', '.join(enum_values)}{RST}"); continue
                    arg_vals[a["name"]] = v
                    raw_args.add(a["name"])
                    return
                try:
                    bl = base.lower()
                    if bl in ("int","long"):          arg_vals[a["name"]] = int(v);   return
                    if bl == "float":                  arg_vals[a["name"]] = float(v); return
                    if bl in ("boolean","bool"):
                        if v.lower() in ("true","1"):  arg_vals[a["name"]] = True;  return
                        if v.lower() in ("false","0"): arg_vals[a["name"]] = False; return
                        print(f"  {Y}true or false{RST}"); continue
                except ValueError: pass
                arg_vals[a["name"]] = v
                return

        if req_args:
            print(f"\n  {B}━━━ Required Arguments ━━━{RST}")
            for a in req_args:
                collect_arg(a, True)
                if cancelled: break
        if cancelled: print(f"  {DIM}Cancelled.{RST}"); continue

        if opt_args:
            print(f"\n  {B}━━━ Optional Arguments ━━━{RST}")
            print(f"  {DIM}Enter to skip. Type {Y}cancel{RST}{DIM} to go back.{RST}")
            for a in opt_args:
                collect_arg(a, False)
                if cancelled: break
        if cancelled: print(f"  {DIM}Cancelled.{RST}"); continue

        # ── resolve return + auto pick type ───────────────────────────────────────
        _, entity, pat = idx.resolve_return(tgt)

        # Detect whether query returns a list or a single item
        ret_type_raw = tgt.get("type",{})
        def _is_list_return(t):
            if not t: return False
            if t.get("kind") == "LIST": return True
            inner = t.get("ofType")
            return _is_list_return(inner) if inner else False
        is_list_query = _is_list_return(ret_type_raw)

        concretes = idx.concrete_types_of(entity) if entity else []
        chosen    = best_type(idx, tgt, concretes)

        if chosen and len(concretes) > 1:
            print(f"\n  {DIM}Auto-selected: {C}{chosen}{RST}  "
                  f"{DIM}({len(concretes)} types){RST}")
            for i,ct in enumerate(concretes,1):
                mk = f" {G}←{RST}" if ct==chosen else ""
                print(f"    {DIM}[{i}]{RST} {DIM}{ct}{RST}{mk}")
            try:
                ov = input(f"\n  {DIM}Enter to confirm, or a number to switch: {RST}").strip()
                if ov.isdigit():
                    i2=int(ov)-1
                    if 0<=i2<len(concretes):
                        chosen=concretes[i2]
                        print(f"  {G}[✓]{RST} Switched to {C}{chosen}{RST}")
            except (EOFError,KeyboardInterrupt): pass

        # ── field list — Enter = all ───────────────────────────────────────────────
        fl = idx.scalar_fields_of(chosen) if chosen else []
        if not fl: print(f"  {Y}No introspectable fields.{RST}"); continue
        cfw = max(len(f["name"]) for f in fl)+2
        print(f"\n  {B}━━━ Fields — {C}{chosen}{RST}  {B}({len(fl)} available) ━━━{RST}\n")
        for i,f in enumerate(fl,1):
            print(f"  {DIM}[{i:>3}]{RST}  {G}{f['name']:<{cfw}}{RST}  {DIM}{f['gql_type']}{RST}")
        print(f"\n  {DIM}Numbers, names, or {Y}all{RST}{DIM}.  Enter = all.  cancel = back.{RST}")

        sel: Optional[list] = None
        while True:
            try: r2 = input(f"  {B}fields [{G}all{RST}]>{B} {RST}").strip()
            except (EOFError,KeyboardInterrupt): break
            # Empty → default all
            if not r2 or r2.lower()=="all":
                sel=[f["name"] for f in fl]
                print(f"  {G}[✓]{RST} All {len(sel)} fields selected")
                break
            if r2.lower()=="cancel": break
            toks=r2.split(); picked=[]; bad=[]
            nm={f["name"].lower():f["name"] for f in fl}
            for tok in toks:
                if tok.isdigit():
                    i2=int(tok)-1
                    if 0<=i2<len(fl):
                        n=fl[i2]["name"]
                        if n not in picked: picked.append(n)
                    else: bad.append(tok)
                else:
                    mx=[k for k in nm if tok.lower() in k]
                    if len(mx)==1:
                        n=nm[mx[0]]; picked.append(n) if n not in picked else None
                    elif len(mx)>1: print(f"  {Y}Ambiguous '{tok}'{RST}"); bad.append(tok)
                    else: bad.append(tok)
            if bad:    print(f"  {Y}Not found: {', '.join(bad)}{RST}"); continue
            if not picked: print(f"  {Y}No fields selected.{RST}"); continue
            sel=picked
            print(f"  {G}[✓]{RST} {len(picked)} field(s): "
                  f"{DIM}{', '.join(picked[:8])}{'…' if len(picked)>8 else ''}{RST}")
            break
        if not sel: print(f"  {DIM}Cancelled.{RST}"); continue

        # ── limit — skip for singular queries, default=all for list ───────────────
        tc = counts.get(fn)
        has_limit_arg = any(a["name"]=="limit" for a in (tgt.get("args") or []))

        if not is_list_query:
            # Singular query — no limit concept, just fire
            limit: int | str = "single"
            print(f"\n  {DIM}Singular query — fetching one record.{RST}")
        else:
            print(f"\n  {B}━━━ How many records? ━━━{RST}")
            if tc and tc not in ("?",0):
                print(f"  {DIM}Total available: {G}{tc:,}{RST}")
            print(f"  {DIM}Number or {Y}all{RST}{DIM}. Enter = all.{RST}")
            limit = "all"
            while True:
                try: r3 = input(f"  {B}limit [{G}all{RST}]>{B} {RST}").strip()
                except (EOFError,KeyboardInterrupt): limit=None; break
                if r3==""               : limit="all"; break
                if r3.lower()=="cancel" : limit=None;  break
                if r3.lower()=="all"    : limit="all"; break
                if r3.isdigit() and int(r3)>0: limit=int(r3); break
                print(f"  {Y}Positive number or 'all'.{RST}")
            if limit is None: print(f"  {DIM}Cancelled.{RST}"); continue

        # ── build & fire ───────────────────────────────────────────────────────────
        parts = []
        for a in (tgt.get("args") or []):
            arg_name = a["name"]
            if arg_name == "limit":
                if limit not in ("all","single"): parts.append(f"limit: {limit}")
            elif arg_name == "filter" and pat == "drupal" and chosen and arg_name not in arg_vals:
                b = type_to_bundle(chosen)
                if b: parts.append(f'filter: {{conditions: [{{field: "type", value: ["{b}"]}}]}}')
            elif arg_name in arg_vals:
                if arg_name in raw_args:
                    parts.append(f"{arg_name}: {arg_vals[arg_name]}")
                else:
                    parts.append(f"{arg_name}: {json.dumps(arg_vals[arg_name])}")
        arg_s = f"({', '.join(parts)})" if parts else ""

        field_lines = "\n".join(f"        {n}" for n in sel)
        if pat=="drupal":
            wrapper = idx.resolve_return(tgt)[0]
            sub_    = idx.fields_of(wrapper)
            cl_     = "    count\n" if any(f["name"]=="count" for f in sub_) else ""
            frag    = f"    ... on {chosen} {{\n{field_lines}\n    }}" if chosen else field_lines
            body    = f"{cl_}    entities {{\n{frag}\n    }}"
        elif pat in ("union","object") and chosen:
            body = f"  ... on {chosen} {{\n{field_lines}\n  }}"
        else:
            body = "\n".join(f"  {n}" for n in sel)
        q_str = f"{{\n  {fn}{arg_s} {{\n{body}\n  }}\n}}"

        lim_s = "1 (singular)" if limit=="single" else ("all" if limit=="all" else f"{limit:,}")
        print(f"\n  {DIM}Querying {lim_s} record(s) …{RST}")
        t1   = time.perf_counter()
        resp = await loop.run_in_executor(None, gql, url, q_str, token, delay)
        rt   = time.perf_counter() - t1

        errors = (resp or {}).get("errors")
        data   = (resp or {}).get("data") or {}
        result = data.get(fn)

        print(f"\n{B}{'━'*64}{RST}\n{BO}{W}  Result — {C}{fn}{RST}  "
              f"{DIM}({chosen})  {rt:.2f}s{RST}\n{B}{'━'*64}{RST}\n")

        if errors:
            print(f"  {Y}[!] Errors:{RST}")
            for e in errors: print(f"    {R}•{RST} {e.get('message','')}")
            print()

        if result is not None:
            pretty = json.dumps(result, indent=2, ensure_ascii=False)
            for line in pretty.split("\n"):
                if ":" in line.lstrip():
                    k,_,v = line.partition(":")
                    print(f"{C}{k}{RST}:{W}{v}{RST}")
                else: print(f"{DIM}{line}{RST}")
            all_results[fn] = result
        elif not errors:
            print(f"  {DIM}(null — server returned no data){RST}")

        print(f"\n  {DIM}─── Query sent ───{RST}")
        for line in q_str.split("\n"): print(f"  {DIM}{line}{RST}")
        print(f"\n  {DIM}Continue with number/name, or '{Y}save <file>{RST}{DIM}' to export.{RST}")

    if output_path and all_results:
        save_output({"target":url,"timestamp":time.strftime("%Y-%m-%dT%H:%M:%S"),
                     "results":all_results}, output_path)
    return {"target":url,"timestamp":time.strftime("%Y-%m-%dT%H:%M:%S"),
            "results":all_results}

def cmd_dbs(url: str, token: Optional[str] = None, delay: float = 0.0,
            output_path: Optional[str] = None, concurrency: int = 8) -> dict:
    return asyncio.run(_dbs_async(url, token, delay, output_path, concurrency))

# ── Main ─────────────────────────────────────────────────────────────────────────
HELP = f"""
{C}{BO}gql.py — GraphQL Data Dump Tool{RST}

{BO}Usage:{RST}  python gql.py --url <endpoint> [OPTIONS]

{BO}Options:{RST}
  {G}-q, --queries{RST}          List all queries
  {G}-m, --mutations{RST}        List all mutations
  {G}-t, --types{RST}            List schema types
  {G}    --dbs{RST}              Interactive data dump wizard

  {G}    --url <endpoint>{RST}        Target GraphQL endpoint  (required)
  {G}    --token <token>{RST}         Bearer auth token
  {G}    --delay <secs>{RST}          Delay between requests  (default: 0)
  {G}    --concurrency <n>{RST}       Parallel count queries  (default: 8)
  {G}    --output <file>{RST}         Save session results to JSON

{BO}Examples:{RST}
  python gql.py --url https://target.com/graphql -q
  python gql.py --url https://target.com/graphql --dbs
  python gql.py --url https://target.com/graphql --dbs --concurrency 16 --output dump.json
"""

def main():
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--url");  p.add_argument("--token"); p.add_argument("--output")
    p.add_argument("--delay",       type=float, default=0.0)
    p.add_argument("--concurrency", type=int,   default=8)
    p.add_argument("-q","--queries",   action="store_true")
    p.add_argument("-m","--mutations", action="store_true")
    p.add_argument("-t","--types",     action="store_true")
    p.add_argument("--dbs",            action="store_true")
    p.add_argument("--help",           action="store_true")
    a = p.parse_args()

    if a.help or len(sys.argv)==1:
        print(BANNER); print(HELP); sys.exit(0)
    if not a.url:
        print(f"\n  {R}[✗]{RST} --url is required\n"); sys.exit(1)

    print(BANNER)
    print(f"  {BO}Target :{RST} {C}{a.url}{RST}")
    print(f"  {BO}Auth   :{RST} {'Bearer token provided' if a.token else f'{DIM}none{RST}'}")
    if a.delay:       print(f"  {BO}Delay  :{RST} {Y}{a.delay}s{RST}")
    if a.concurrency != 8: print(f"  {BO}Workers:{RST} {Y}{a.concurrency}{RST}")
    print(f"  {BO}Time   :{RST} {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    if a.queries:   cmd_queries(a.url, a.token, delay=a.delay)
    if a.mutations: cmd_mutations(a.url, a.token, delay=a.delay)
    if a.types:     cmd_types(a.url, a.token, delay=a.delay)
    if a.dbs:       cmd_dbs(a.url, a.token, delay=a.delay,
                            output_path=a.output, concurrency=a.concurrency)

if __name__ == "__main__":
    main()
