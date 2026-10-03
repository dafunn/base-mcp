"""Network policy: the host allowlist, address checks, redirects,
credential injection, and address pinning. No real network; the HTTP
client and the resolver are stubbed."""
from __future__ import annotations

import asyncio

import httpx
import pytest

import config
import net


def _run(coro):
    return asyncio.run(coro)


# -- network policy ---------------------------------------------------
_ADDR = "93.184.216.34"


def _pinned(path: str) -> str:
    return f"https://{_ADDR}{path}"


@pytest.fixture
def net_policy(monkeypatch):
    monkeypatch.setattr(net, "NET_ALLOW_HOSTS", ("example.com", ".sub.example.org"))
    monkeypatch.setattr(config, "EXPOSE_WRITE", False)

    async def _public(_host):
        return [_ADDR]

    monkeypatch.setattr(net, "_addresses", _public)
    return monkeypatch


def test_host_allowlist_forms(net_policy):
    assert net._host_allowed("example.com")
    assert not net._host_allowed("notexample.com")  # a suffix match would wrongly allow this
    assert not net._host_allowed("api.example.com")  # bare entries are exact
    assert net._host_allowed("sub.example.org") and net._host_allowed("a.sub.example.org")


def test_check_url_denies_unlisted_host_and_empty_allowlist(net_policy):
    with pytest.raises(ValueError, match="not allow-listed"):
        _run(net._check_url("https://elsewhere.test/x"))
    net_policy.setattr(net, "NET_ALLOW_HOSTS", ())
    with pytest.raises(ValueError, match="no hosts are allow-listed"):
        _run(net._check_url("https://example.com/x"))


def test_check_url_rejects_other_schemes(net_policy):
    with pytest.raises(ValueError, match="not supported"):
        _run(net._check_url("file:///etc/passwd"))


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1"])
def test_check_url_rejects_non_public_addresses(net_policy, addr):
    async def _internal(_host):
        return [addr]

    net_policy.setattr(net, "_addresses", _internal)
    with pytest.raises(ValueError, match="non-public address"):
        _run(net._check_url("https://example.com/x"))


def test_private_addresses_allowed_when_opted_in(net_policy):
    async def _internal(_host):
        return ["10.1.2.3"]

    net_policy.setattr(net, "_addresses", _internal)
    net_policy.setattr(net, "NET_ALLOW_PRIVATE_ADDRS", True)
    assert _run(net._check_url("https://example.com/x"))[0] == "https://example.com/x"


class _StubClient:
    """Serves queued responses and records the URLs actually requested."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.seen: list[str] = []
        self.headers: list[dict] = []

    async def request(self, method, url, headers=None, **_kwargs):
        self.seen.append(url)
        self.headers.append(dict(headers or {}))
        resp = self._responses.pop(0)
        resp.request = httpx.Request(method, url)
        return resp


def test_net_fetch_returns_body(net_policy, monkeypatch):
    monkeypatch.setattr(
        net, "_client",
        _StubClient(httpx.Response(200, headers={"content-type": "text/plain"}, content=b"hello there")),
    )
    out = _run(net._h_net_fetch("https://example.com/x"))
    assert "200" in out and "hello there" in out and "content-type: text/plain" in out


def test_net_fetch_truncates_body(net_policy, monkeypatch):
    monkeypatch.setattr(net, "NET_MAX_BYTES", 4)
    monkeypatch.setattr(net, "_client", _StubClient(httpx.Response(200, content=b"much too long")))
    out = _run(net._h_net_fetch("https://example.com/x"))
    assert "truncated at 4 bytes" in out


def test_net_fetch_revalidates_redirects(net_policy, monkeypatch):
    """An allow-listed host redirecting inward is the ordinary shape of an SSRF."""
    stub = _StubClient(httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}))
    monkeypatch.setattr(net, "_client", stub)
    with pytest.raises(ValueError, match="not allow-listed"):
        _run(net._h_net_fetch("https://example.com/x"))
    assert stub.seen == [_pinned("/x")]  # the second hop was never requested


def test_net_fetch_follows_allowed_redirect(net_policy, monkeypatch):
    stub = _StubClient(
        httpx.Response(302, headers={"location": "https://sub.example.org/y"}),
        httpx.Response(200, content=b"landed"),
    )
    monkeypatch.setattr(net, "_client", stub)
    out = _run(net._h_net_fetch("https://example.com/x"))
    assert "landed" in out
    assert stub.seen == [_pinned("/x"), _pinned("/y")]
    assert [h["Host"] for h in stub.headers] == ["example.com", "sub.example.org"]


def test_net_fetch_caps_redirect_chain(net_policy, monkeypatch):
    monkeypatch.setattr(net, "NET_MAX_REDIRECTS", 1)
    def hop():
        return httpx.Response(302, headers={"location": "https://example.com/loop"})

    monkeypatch.setattr(net, "_client", _StubClient(hop(), hop()))
    with pytest.raises(ValueError, match="more than 1 redirects"):
        _run(net._h_net_fetch("https://example.com/x"))


def test_mutating_methods_need_the_write_gate(net_policy, monkeypatch):
    stub = _StubClient(httpx.Response(201, content=b"created"))
    monkeypatch.setattr(net, "_client", stub)
    with pytest.raises(ValueError, match="disabled"):
        _run(net._h_net_fetch("https://example.com/x", method="POST", body="{}"))
    assert stub.seen == []  # refused before any request left the process
    monkeypatch.setattr(config, "EXPOSE_WRITE", True)
    assert "created" in _run(net._h_net_fetch("https://example.com/x", method="POST", body="{}"))


def test_unknown_method_rejected(net_policy):
    with pytest.raises(ValueError, match="not supported"):
        _run(net._h_net_fetch("https://example.com/x", method="BREW"))


# -- credential injection ---------------------------------------------
@pytest.fixture
def creds(net_policy, tmp_path, monkeypatch):
    tok = tmp_path / "token"
    tok.write_text("s3cret\n")
    monkeypatch.setenv("NET_AUTH_TOKEN_FILE", str(tok))
    monkeypatch.setattr(net, "NET_AUTH_HOSTS", ("example.com",))
    return net_policy


def test_token_read_from_file_then_env(tmp_path, monkeypatch):
    tok = tmp_path / "token"
    tok.write_text("from-file\n")
    monkeypatch.setenv("NET_AUTH_TOKEN_FILE", str(tok))
    monkeypatch.setenv("NET_AUTH_TOKEN", "from-env")
    assert net._net_token() == "from-file"
    monkeypatch.setenv("NET_AUTH_TOKEN_FILE", str(tmp_path / "missing"))
    assert net._net_token() == "from-env"


def test_credential_attached_for_configured_host(creds, monkeypatch):
    stub = _StubClient(httpx.Response(200, content=b"ok"))
    monkeypatch.setattr(net, "_client", stub)
    _run(net._h_net_fetch("https://example.com/x"))
    assert stub.headers[0]["Authorization"] == "Bearer s3cret"


def test_credential_withheld_from_other_allowed_hosts(creds, monkeypatch):
    stub = _StubClient(httpx.Response(200, content=b"ok"))
    monkeypatch.setattr(net, "_client", stub)
    _run(net._h_net_fetch("https://sub.example.org/x"))  # allow-listed, but not a credential host
    assert "Authorization" not in stub.headers[0]


def test_credential_dropped_on_redirect_to_another_host(creds, monkeypatch):
    """A bearer token forwarded across a redirect is how tokens escape."""
    stub = _StubClient(
        httpx.Response(302, headers={"location": "https://sub.example.org/y"}),
        httpx.Response(200, content=b"landed"),
    )
    monkeypatch.setattr(net, "_client", stub)
    _run(net._h_net_fetch("https://example.com/x"))
    assert stub.headers[0]["Authorization"] == "Bearer s3cret"
    assert "Authorization" not in stub.headers[1]


def test_caller_cannot_set_the_auth_header(creds, monkeypatch):
    stub = _StubClient(httpx.Response(200, content=b"ok"))
    monkeypatch.setattr(net, "_client", stub)
    with pytest.raises(ValueError, match="cannot be set by the caller"):
        _run(net._h_net_fetch("https://example.com/x", headers={"authorization": "Bearer mine"}))
    assert stub.seen == []


def test_token_never_appears_in_output(creds, monkeypatch):
    stub = _StubClient(httpx.Response(200, content=b"ok"))
    monkeypatch.setattr(net, "_client", stub)
    assert "s3cret" not in _run(net._h_net_fetch("https://example.com/x"))


# -- address pinning --------------------------------------------------
def test_request_goes_to_the_validated_address(net_policy, monkeypatch):
    """Connect to the address the check saw, not to a second lookup's answer."""
    stub = _StubClient(httpx.Response(200, content=b"ok"))
    monkeypatch.setattr(net, "_client", stub)
    _run(net._h_net_fetch("https://example.com/x"))
    assert stub.seen == [_pinned("/x")]
    assert stub.headers[0]["Host"] == "example.com"  # name still on the wire


def test_pinning_preserves_port_and_query(net_policy, monkeypatch):
    stub = _StubClient(httpx.Response(200, content=b"ok"))
    monkeypatch.setattr(net, "_client", stub)
    _run(net._h_net_fetch("https://example.com:8443/x?a=1"))
    assert stub.seen == [f"https://{_ADDR}:8443/x?a=1"]
    assert stub.headers[0]["Host"] == "example.com:8443"


def test_relative_redirect_resolves_against_the_hostname(net_policy, monkeypatch):
    """Joining against the pinned URL would check the literal address, not a host."""
    stub = _StubClient(
        httpx.Response(302, headers={"location": "/moved"}),
        httpx.Response(200, content=b"landed"),
    )
    monkeypatch.setattr(net, "_client", stub)
    out = _run(net._h_net_fetch("https://example.com/x"))
    assert "landed" in out
    assert stub.seen == [_pinned("/x"), _pinned("/moved")]
    assert stub.headers[1]["Host"] == "example.com"
    assert "https://example.com/moved" in out  # the chain reports the logical URL


def test_pinning_can_be_disabled(net_policy, monkeypatch):
    stub = _StubClient(httpx.Response(200, content=b"ok"))
    monkeypatch.setattr(net, "NET_PIN_ADDRESS", False)
    monkeypatch.setattr(net, "_client", stub)
    _run(net._h_net_fetch("https://example.com/x"))
    assert stub.seen == ["https://example.com/x"] and "Host" not in stub.headers[0]


def test_unresolvable_host_is_refused(net_policy, monkeypatch):
    async def _none(_host):
        return []

    monkeypatch.setattr(net, "_addresses", _none)
    with pytest.raises(ValueError, match="cannot resolve"):
        _run(net._check_url("https://example.com/x"))


def test_pinning_still_resolves_when_private_addresses_are_allowed(net_policy, monkeypatch):
    """Pinning is about which address; the private-address rule is about whether."""
    async def _internal(_host):
        return ["10.1.2.3"]

    monkeypatch.setattr(net, "_addresses", _internal)
    monkeypatch.setattr(net, "NET_ALLOW_PRIVATE_ADDRS", True)
    assert _run(net._check_url("https://example.com/x")) == ("https://example.com/x", "10.1.2.3")
