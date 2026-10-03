"""The reload contract.

`conftest.reload_server` reloads every module in dependency order, so no module
keeps configuration from a previous environment. These tests go through the
write gate; the handler tests call handlers directly, below it.
"""
from __future__ import annotations

import asyncio

import pytest

import config
import fs_ops
import net
import server as srv


def test_reload_propagates_a_changed_flag(monkeypatch, reload_server):
    monkeypatch.setenv("EXPOSE_WRITE", "false")
    reload_server()
    assert config.EXPOSE_WRITE is False
    monkeypatch.setenv("EXPOSE_WRITE", "true")
    reload_server()
    assert config.EXPOSE_WRITE is True


def test_reload_propagates_the_audit_switch(monkeypatch, reload_server):
    monkeypatch.setenv("AUDIT_LOG", "false")
    assert reload_server().AUDIT_LOG is False
    monkeypatch.setenv("AUDIT_LOG", "true")
    assert reload_server().AUDIT_LOG is True


def test_the_write_gate_reads_the_reloaded_value(monkeypatch, tmp_path, reload_server):
    """Through `_dispatch`, which is where the gate actually is - the handler
    tests call handlers directly and never cross it."""
    monkeypatch.setenv("FS_ALLOW_ROOTS", str(tmp_path))
    monkeypatch.setenv("EXPOSE_WRITE", "false")
    srv = reload_server()
    out = asyncio.run(srv._dispatch("fs_write", {"path": "x.txt", "content": "hi"}))
    assert "disabled (EXPOSE_WRITE=false)" in out

    monkeypatch.setenv("EXPOSE_WRITE", "true")
    srv = reload_server()
    asyncio.run(srv._dispatch("fs_write", {"path": "x.txt", "content": "hi"}))
    assert (tmp_path / "x.txt").read_text() == "hi"


def test_the_write_gate_has_exactly_one_binding(monkeypatch):
    """No module keeps its own copy: patching `config` alone must move every
    gate, with no reload."""
    for mod in (config, fs_ops, net, srv):
        assert "EXPOSE_WRITE" not in vars(mod) or mod is config

    monkeypatch.setattr(config, "EXPOSE_WRITE", False)
    assert "Writes: disabled" in fs_ops._h_fs_roots()
    with pytest.raises(ValueError, match="disabled"):
        asyncio.run(net._h_net_fetch("https://nope.test/x", method="POST"))

    monkeypatch.setattr(config, "EXPOSE_WRITE", True)
    assert "Writes: enabled" in fs_ops._h_fs_roots()
