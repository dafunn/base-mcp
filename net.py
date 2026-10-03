"""HTTP fetch, confined to an explicit host allowlist.

Deny-by-default and enforced here rather than in the tool arguments, so the
model cannot widen the scope by asking. Every redirect hop is re-checked: an
allow-listed host that redirects to an internal address is the ordinary shape of
an SSRF.

GET and HEAD are always available; every other method needs the shared write
gate, `config.EXPOSE_WRITE`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

import config
from config import csv_env, flag
from content import is_binary

NET_ALLOW_HOSTS = csv_env("NET_ALLOW_HOSTS")
NET_MAX_BYTES = int(os.getenv("NET_MAX_BYTES", "200000"))
NET_TIMEOUT = float(os.getenv("NET_TIMEOUT_SECONDS", "30"))
NET_MAX_REDIRECTS = int(os.getenv("NET_MAX_REDIRECTS", "3"))
# Off by default: otherwise any hostname resolving to an internal address or the
# cloud metadata endpoint is reachable. Turn on only when the allow-listed hosts
# are deliberately internal.
NET_ALLOW_PRIVATE_ADDRS = flag("NET_ALLOW_PRIVATE_ADDRS", False)
# Connect to the address the policy check validated rather than resolving the
# name a second time.
NET_PIN_ADDRESS = flag("NET_PIN_ADDRESS", True)

# Credentials the server holds and the model never sees: a request to a host in
# NET_AUTH_HOSTS gets the header attached on the way out. The token is read at
# call time, so a rotated secret file takes effect without a restart.
NET_AUTH_HOSTS = csv_env("NET_AUTH_HOSTS")
NET_AUTH_HEADER = os.getenv("NET_AUTH_HEADER", "Authorization").strip()
NET_AUTH_SCHEME = os.getenv("NET_AUTH_SCHEME", "Bearer").strip()

_SAFE_METHODS = frozenset({"GET", "HEAD"})
_KNOWN_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


_client = httpx.AsyncClient(timeout=NET_TIMEOUT, follow_redirects=False)


def _host_matches(host: str, entries: tuple[str, ...]) -> bool:
    """Exact match, or a leading-dot entry matching that domain and its subdomains.

    `example.com` matches only that host; `.example.com` matches it and anything
    under it.
    """
    h = host.lower().rstrip(".")
    for entry in entries:
        e = entry.lower().rstrip(".")
        if e.startswith("."):
            if h == e[1:] or h.endswith(e):
                return True
        elif h == e:
            return True
    return False


def _host_allowed(host: str) -> bool:
    return _host_matches(host, NET_ALLOW_HOSTS)


def _net_token() -> str:
    """Read the injected credential: mounted file first, env fallback, empty allowed."""
    p = Path(os.getenv("NET_AUTH_TOKEN_FILE", "/run/secrets/net-auth-token"))
    if p.exists():
        return p.read_text().strip()
    return os.getenv("NET_AUTH_TOKEN", "").strip()


def _auth_header_for(host: str) -> dict[str, str]:
    """The credential header for this host, or nothing.

    Computed per hop: a redirect to a host outside NET_AUTH_HOSTS drops the
    credential instead of forwarding it.
    """
    if not NET_AUTH_HOSTS or not _host_matches(host, NET_AUTH_HOSTS):
        return {}
    tok = _net_token()
    if not tok:
        return {}
    return {NET_AUTH_HEADER: f"{NET_AUTH_SCHEME} {tok}".strip() if NET_AUTH_SCHEME else tok}


async def _addresses(host: str) -> list[str]:
    infos = await asyncio.to_thread(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


async def _check_url(url: str) -> tuple[str, str]:
    """Validate a URL against the host allowlist and the address policy.

    Returns the URL and the address it validated, so the caller connects to
    that exact address rather than resolving a second time. Every redirect hop
    passes through here as well.
    """
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise ValueError(f"scheme '{parts.scheme}' is not supported (http/https only)")
    host = parts.hostname or ""
    if not host:
        raise ValueError(f"no host in url '{url}'")
    if not NET_ALLOW_HOSTS:
        raise ValueError("no hosts are allow-listed (NET_ALLOW_HOSTS is empty, which denies everything)")
    if not _host_allowed(host):
        raise ValueError(f"host '{host}' is not allow-listed")

    addr = ""
    if NET_PIN_ADDRESS or not NET_ALLOW_PRIVATE_ADDRS:
        try:
            addrs = await _addresses(host)
        except socket.gaierror as exc:
            raise ValueError(f"cannot resolve '{host}': {exc}") from exc
        if not addrs:
            raise ValueError(f"cannot resolve '{host}': no addresses")
        if not NET_ALLOW_PRIVATE_ADDRS:
            for a in addrs:
                ip = ipaddress.ip_address(a)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                    raise ValueError(
                        f"host '{host}' resolves to non-public address {a} "
                        "(set NET_ALLOW_PRIVATE_ADDRS=true only if that is intended)"
                    )
        # First address only: the rest are unvalidated, so a pinned request
        # gets no failover.
        addr = addrs[0]
    return url, addr


def _pin(url: str, addr: str) -> tuple[str, str]:
    """Rewrite the request URL to the validated address, keeping the name in play.

    The Host header and the TLS SNI still carry the real hostname, so virtual
    hosting and certificate verification are unaffected - only the address the
    socket goes to is fixed. Returns (request_url, host_header); an empty
    host_header means pinning is off and the client resolves normally.
    """
    if not NET_PIN_ADDRESS or not addr:
        return url, ""
    parts = urlsplit(url)
    literal = f"[{addr}]" if ":" in addr else addr
    netloc = f"{literal}:{parts.port}" if parts.port else literal
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, "")), parts.netloc


async def _h_net_fetch(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str = "",
    max_bytes: int = 0,
) -> str:
    m = (method or "GET").strip().upper()
    if m not in _KNOWN_METHODS:
        raise ValueError(f"method '{m}' is not supported")
    if m not in _SAFE_METHODS and not config.EXPOSE_WRITE:
        raise ValueError(f"method '{m}' is disabled (EXPOSE_WRITE=false); GET and HEAD are available")
    cap = max_bytes if 0 < max_bytes <= NET_MAX_BYTES else NET_MAX_BYTES

    chain: list[str] = []
    target = url  # the logical URL: what policy, redirects and output are about
    request_headers = {str(k): str(v) for k, v in (headers or {}).items()}
    if NET_AUTH_HEADER and any(k.lower() == NET_AUTH_HEADER.lower() for k in request_headers):
        # Refused rather than silently dropped.
        raise ValueError(
            f"header '{NET_AUTH_HEADER}' cannot be set by the caller; the server attaches credentials itself"
        )
    resp: httpx.Response | None = None
    for _hop in range(NET_MAX_REDIRECTS + 1):
        target, addr = await _check_url(target)
        hop_host = urlsplit(target).hostname or ""
        request_url, host_header = _pin(target, addr)
        hop_headers = {**request_headers, **_auth_header_for(hop_host)}
        if host_header:
            hop_headers["Host"] = host_header
        resp = await _client.request(
            m, request_url,
            headers=hop_headers,
            content=body.encode("utf-8") if body else None,
            extensions={"sni_hostname": hop_host} if host_header else {},
        )
        if resp.is_redirect and resp.headers.get("location"):
            # Joined against the logical URL, never resp.url: with a pinned
            # address resp.url carries the literal address, and a relative
            # Location would resolve against it.
            target = urljoin(target, resp.headers["location"])
            chain.append(f"-> {resp.status_code} {target}")
            continue
        break
    else:
        raise ValueError(f"more than {NET_MAX_REDIRECTS} redirects (NET_MAX_REDIRECTS)")

    assert resp is not None
    ctype = resp.headers.get("content-type", "")
    out = [f"{m} {target} -> {resp.status_code} {resp.reason_phrase}".rstrip()]
    out += chain
    out.append(f"content-type: {ctype or '(none)'}")
    raw = resp.content
    if m == "HEAD" or not raw:
        out.append(f"content-length: {resp.headers.get('content-length', len(raw))}")
        return "\n".join(out)
    if is_binary(raw[:8192]):
        out.append(f"\n<binary body, {len(raw)} bytes>")
        return "\n".join(out)
    text = raw[:cap].decode("utf-8", "replace")
    out.append("")
    out.append(text)
    if len(raw) > cap:
        out.append(f"... truncated at {cap} bytes (NET_MAX_BYTES)")
    return "\n".join(out)
