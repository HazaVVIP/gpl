from __future__ import annotations

import http.client
import json
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional


@dataclass
class TransportConfig:
    verify_tls: bool = True
    ca_file: Optional[str] = None
    timeout: int = 25
    retries: int = 1
    backoff_seconds: float = 0.25
    user_agent: str = "GPL-Tool/Enterprise-0.1"


class TransportError(RuntimeError):
    pass


def build_auth_headers(
    token: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_header: str = "X-API-Key",
    cookie: Optional[str] = None,
    extra_headers: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if api_key:
        headers[api_key_header] = api_key
    if cookie:
        headers["Cookie"] = cookie
    if extra_headers:
        headers.update(extra_headers)
    return headers


def _ssl_context(config: TransportConfig) -> ssl.SSLContext:
    if config.verify_tls:
        ctx = ssl.create_default_context(cafile=config.ca_file)
    else:
        ctx = ssl._create_unverified_context()
    return ctx


def post_graphql(
    url: str,
    query: str,
    headers: Optional[dict[str, str]] = None,
    config: Optional[TransportConfig] = None,
    delay: float = 0.0,
) -> dict:
    cfg = config or TransportConfig()
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    payload = json.dumps({"query": query}).encode("utf-8")
    req_headers = {
        "User-Agent": cfg.user_agent,
        "Connection": "close",
        "Content-Length": str(len(payload)),
    }
    if headers:
        req_headers.update(headers)

    if delay > 0:
        time.sleep(delay)

    last_error: Optional[Exception] = None
    for attempt in range(cfg.retries + 1):
        conn = None
        try:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(host, timeout=cfg.timeout, context=_ssl_context(cfg))
            else:
                conn = http.client.HTTPConnection(host, timeout=cfg.timeout)
            conn.request("POST", path, body=payload, headers=req_headers)
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="replace")
            if not body:
                return {"_err": "empty response"}
            return json.loads(body)
        except Exception as exc:  # pragma: no cover - branch tested via monkeypatch
            last_error = exc
            if attempt < cfg.retries:
                time.sleep(cfg.backoff_seconds * (attempt + 1))
                continue
            raise TransportError(str(last_error)) from last_error
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    raise TransportError("request failed")
