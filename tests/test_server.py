"""The server layer: tool listing and the write gate, dispatch, the
envelope on the wire, the audit log, and transport auth."""
from __future__ import annotations

import asyncio

import httpx
import pytest

import fs_ops
import server as srv


def _run(coro):
    return asyncio.run(coro)


# -- the write gate ---------------------------------------------------
def test_write_tools_hidden_when_gate_closed(tree):
    names = {t.name for t in _run(srv.list_tools(None, None)).tools}
    assert "fs_read" in names and "net_fetch" in names
    assert not (names & srv._WRITE_TOOL_NAMES)


def test_write_tools_listed_when_gate_open(writable):
    names = {t.name for t in _run(srv.list_tools(None, None)).tools}
    assert srv._WRITE_TOOL_NAMES <= names


def test_dispatch_refuses_write_tool_by_name_when_gate_closed(tree):
    """A client holding a stale tool list must not get through."""
    out = _run(srv._dispatch("fs_write", {"path": "new.txt", "content": "x"}))
    assert "disabled (EXPOSE_WRITE=false)" in out
    assert not (tree / "new.txt").exists()


# -- wiring -----------------------------------------------------------
def test_dispatch_unknown_tool():
    assert "unknown tool" in _run(srv._dispatch("fs_nope", {}))


def test_call_tool_surfaces_errors_as_text(tree):
    from mcp.types import CallToolRequestParams

    result = _run(srv.call_tool(None, CallToolRequestParams(name="fs_read", arguments={"path": "../outside/secret.txt"})))
    assert "Error:" in result.content[0].text and "not yours" not in result.content[0].text


def test_call_tool_attaches_the_envelope_to_the_wire_result(tree, monkeypatch):
    """The handler builds the envelope; this is the wiring that puts it on the
    result."""
    from mcp.types import CallToolRequestParams

    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 10)
    result = _run(
        srv.call_tool(None, CallToolRequestParams(name="fs_read", arguments={"path": "hello.py"}))
    )
    # Text is unchanged for a client that reads only text.
    assert "truncated" in result.content[0].text
    envelope = result.structured_content
    assert envelope["base_mcp_envelope"] == 1
    assert envelope["complete"] is False
    assert envelope["total_bytes"] == len((tree / "hello.py").read_bytes())


def test_call_tool_leaves_a_complete_read_unstructured(tree):
    """A small, complete read is plain text with no envelope."""
    from mcp.types import CallToolRequestParams

    result = _run(
        srv.call_tool(None, CallToolRequestParams(name="fs_read", arguments={"path": "hello.py"}))
    )
    assert "def greet" in result.content[0].text
    assert result.structured_content is None


def test_build_sse_app_constructs():
    """Catches Starlette/transport API mismatches the handler tests never touch."""
    app = srv.build_sse_app()
    assert [getattr(r, "path", None) for r in app.routes] == ["/healthz", "/sse", "/messages"]


# -- audit log --------------------------------------------------------
def _audit_records(caplog):
    import json

    return [json.loads(r.message) for r in caplog.records if r.name == "base-mcp"]


def test_audit_logs_outcome_and_safe_args(tree, caplog):
    from mcp.types import CallToolRequestParams

    with caplog.at_level("INFO", logger="base-mcp"):
        _run(srv.call_tool(None, CallToolRequestParams(name="fs_read", arguments={"path": "hello.py"})))
    rec = _audit_records(caplog)[-1]
    assert rec["tool"] == "fs_read" and rec["outcome"] == "ok" and rec["path"] == "hello.py"


def test_audit_records_refusals(tree, caplog):
    from mcp.types import CallToolRequestParams

    with caplog.at_level("INFO", logger="base-mcp"):
        _run(srv.call_tool(None, CallToolRequestParams(name="fs_read", arguments={"path": ".env"})))
        _run(srv.call_tool(None, CallToolRequestParams(
            name="fs_write", arguments={"path": "x.txt", "content": "hunter2"})))
    outcomes = [r["outcome"] for r in _audit_records(caplog)]
    assert outcomes == ["refused", "refused"]


def test_audit_never_logs_content_or_bodies(writable, caplog):
    from mcp.types import CallToolRequestParams

    with caplog.at_level("INFO", logger="base-mcp"):
        _run(srv.call_tool(None, CallToolRequestParams(
            name="fs_write", arguments={"path": "notes.txt", "content": "hunter2"})))
        _run(srv.call_tool(None, CallToolRequestParams(
            name="fs_edit", arguments={"path": "notes.txt", "old_string": "hunter2", "new_string": "swordfish"})))
    dumped = "\n".join(r.message for r in caplog.records)
    assert "hunter2" not in dumped and "swordfish" not in dumped
    assert '"tool": "fs_edit"' in dumped  # the call itself is still recorded


def test_audit_can_be_disabled(tree, caplog, monkeypatch):
    from mcp.types import CallToolRequestParams

    monkeypatch.setattr(srv, "AUDIT_LOG", False)
    with caplog.at_level("INFO", logger="base-mcp"):
        _run(srv.call_tool(None, CallToolRequestParams(name="fs_read", arguments={"path": "hello.py"})))
    assert _audit_records(caplog) == []


# -- transport auth (optional) ----------------------------------------
def _asgi(app, path, headers=None, method="GET"):
    async def _call():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            return await client.request(method, path, headers=headers or {})

    return _run(_call())


@pytest.fixture
def auth_token(tmp_path, monkeypatch):
    tok = tmp_path / "mcp-token"
    tok.write_text("shared-secret\n")
    monkeypatch.setenv("MCP_AUTH_TOKEN_FILE", str(tok))
    return "shared-secret"


def test_transport_auth_off_by_default(tmp_path, monkeypatch):
    """Unconfigured means open: the network policy is the boundary."""
    monkeypatch.setenv("MCP_AUTH_TOKEN_FILE", str(tmp_path / "missing"))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    assert srv._mcp_token() == ""
    assert _asgi(srv.build_sse_app(), "/messages/", method="POST").status_code != 401


def test_unauthenticated_request_is_refused_when_configured(auth_token):
    resp = _asgi(srv.build_sse_app(), "/messages/", method="POST")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"].startswith("Bearer")


def test_wrong_token_is_refused(auth_token):
    resp = _asgi(srv.build_sse_app(), "/messages/",
                 headers={"Authorization": "Bearer wrong"}, method="POST")
    assert resp.status_code == 401


def test_correct_token_passes_the_gate(auth_token):
    resp = _asgi(srv.build_sse_app(), "/messages/",
                 headers={"Authorization": f"Bearer {auth_token}"}, method="POST")
    assert resp.status_code != 401  # past auth; the transport handles it from here


def test_healthz_stays_open_for_probes(auth_token):
    resp = _asgi(srv.build_sse_app(), "/healthz")
    assert resp.status_code == 200 and resp.text == "ok"


def test_non_bearer_schemes_rejected(auth_token):
    for header in ("Basic shared-secret", "shared-secret", ""):
        assert not srv._bearer_ok(header, auth_token)
    assert srv._bearer_ok(f"Bearer {auth_token}", auth_token)


def test_failed_auth_is_audited_without_the_token(auth_token, caplog):
    with caplog.at_level("INFO", logger="base-mcp"):
        _asgi(srv.build_sse_app(), "/messages/",
              headers={"Authorization": "Bearer wrong"}, method="POST")
    rec = _audit_records(caplog)[-1]
    assert rec["outcome"] == "unauthenticated" and rec["tool"] == "_transport"
    assert "wrong" not in rec.get("detail", "") and auth_token not in "\n".join(
        r.message for r in caplog.records
    )
