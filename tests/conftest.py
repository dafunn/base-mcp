"""Shared test fixtures.

Configuration is read at import, so a test that changes the environment calls
`reload_server`, which reloads every module in dependency order.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Dependency order: every module is reloaded after the ones it reads from, and
# `server` is last because it imports the others.
_RELOAD_ORDER = ("config", "content", "fs_ops", "net", "server")


def _reload_server():
    for name in _RELOAD_ORDER:
        mod = sys.modules.get(name)
        if mod is None:
            importlib.import_module(name)
        else:
            importlib.reload(mod)
    return sys.modules["server"]


@pytest.fixture
def reload_server():
    """Re-import the server so module-level config re-reads the environment.

    Returns the callable, not the module: the environment has to be set up
    inside the test before the reload happens.
    """
    return _reload_server


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A temp root with ordinary files, secret-shaped files, and an escape link."""
    import config
    import fs_ops

    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    (root / "src").mkdir(parents=True)
    (root / ".git").mkdir()
    outside.mkdir()

    (root / "hello.py").write_text("def greet():\n    return 'hi'\n")
    (root / "README.md").write_text("# workspace\n")
    (root / "src" / "core.py").write_text("X = 42  # the answer\nY = 43\n")
    (root / ".env").write_text("TOKEN=sekrit\n")
    (root / ".git" / "config").write_text("[core]\n")
    (outside / "secret.txt").write_text("not yours\n")
    (root / "escape").symlink_to(outside / "secret.txt")

    monkeypatch.setattr(fs_ops, "ALLOW_ROOTS", (root.resolve(),))
    monkeypatch.setattr(config, "EXPOSE_WRITE", False)
    return root


@pytest.fixture
def writable(tree, monkeypatch):
    import config

    monkeypatch.setattr(config, "EXPOSE_WRITE", True)
    return tree
