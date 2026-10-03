"""Read-only roots: served for reading, refused for writing, and the refusal
names the policy rather than a bare EPERM."""
from __future__ import annotations

import pytest

import fs_ops


@pytest.fixture
def srv(tmp_path, monkeypatch, reload_server):
    """A server with one writable root and one read-only root inside it."""
    (tmp_path / "ws").mkdir()
    (tmp_path / "refs").mkdir()
    (tmp_path / "ws" / "a.txt").write_text("writable\n")
    (tmp_path / "refs" / "r.txt").write_text("reference\n")
    monkeypatch.setenv("FS_ALLOW_ROOTS", f"{tmp_path / 'ws'},{tmp_path / 'refs'}")
    monkeypatch.setenv("FS_READONLY_ROOTS", str(tmp_path / "refs"))
    monkeypatch.setenv("EXPOSE_WRITE", "true")
    return reload_server()


def test_a_read_only_root_is_still_readable(srv, tmp_path):
    assert "reference" in fs_ops._h_fs_read(str(tmp_path / "refs" / "r.txt"))
    assert fs_ops._h_fs_list(str(tmp_path / "refs"), 1)


@pytest.mark.parametrize(
    "call",
    [
        lambda srv, p: fs_ops._h_fs_write(str(p / "refs" / "new.txt"), "x"),
        lambda srv, p: fs_ops._h_fs_write(str(p / "refs" / "r.txt"), "x"),
        lambda srv, p: fs_ops._h_fs_edit(str(p / "refs" / "r.txt"), "reference", "x"),
        lambda srv, p: fs_ops._h_fs_delete(str(p / "refs" / "r.txt")),
        lambda srv, p: fs_ops._h_fs_mkdir(str(p / "refs" / "sub")),
        lambda srv, p: fs_ops._h_fs_write_base64(str(p / "refs" / "b.bin"), "eA=="),
    ],
)
def test_every_write_tool_refuses_a_read_only_root(srv, tmp_path, call):
    with pytest.raises(ValueError, match="read-only root"):
        call(srv, tmp_path)


def test_the_refusal_names_the_policy_not_just_the_path(srv, tmp_path):
    """A bare "permission denied" makes the model guess; this does not."""
    with pytest.raises(ValueError, match="FS_READONLY_ROOTS"):
        fs_ops._h_fs_write(str(tmp_path / "refs" / "x.txt"), "x")


def test_writes_to_the_writable_root_are_unaffected(srv, tmp_path):
    fs_ops._h_fs_write(str(tmp_path / "ws" / "b.txt"), "ok")
    assert (tmp_path / "ws" / "b.txt").read_text() == "ok"


def test_copying_out_of_a_read_only_root_is_allowed(srv, tmp_path):
    """Only the destination is a write."""
    fs_ops._h_fs_copy(str(tmp_path / "refs" / "r.txt"), str(tmp_path / "ws" / "copied.txt"))
    assert (tmp_path / "ws" / "copied.txt").read_text() == "reference\n"


def test_copying_into_a_read_only_root_is_refused(srv, tmp_path):
    with pytest.raises(ValueError, match="read-only root"):
        fs_ops._h_fs_copy(str(tmp_path / "ws" / "a.txt"), str(tmp_path / "refs" / "c.txt"))


def test_moving_out_of_a_read_only_root_is_refused(srv, tmp_path):
    """A move removes the source, so it is a write to both ends."""
    with pytest.raises(ValueError, match="read-only root"):
        fs_ops._h_fs_move(str(tmp_path / "refs" / "r.txt"), str(tmp_path / "ws" / "m.txt"))


def test_fs_roots_reports_which_roots_are_read_only(srv, tmp_path):
    out = fs_ops._h_fs_roots()
    assert "(read-only)" in out
    ro_line = next(line for line in out.splitlines() if "refs" in line)
    ws_line = next(line for line in out.splitlines() if line.strip().endswith("ws"))
    assert "(read-only)" in ro_line
    assert "(read-only)" not in ws_line


def test_no_read_only_roots_changes_nothing(tmp_path, monkeypatch, reload_server):
    monkeypatch.setenv("FS_ALLOW_ROOTS", str(tmp_path))
    monkeypatch.delenv("FS_READONLY_ROOTS", raising=False)
    monkeypatch.setenv("EXPOSE_WRITE", "true")
    reload_server()
    assert fs_ops.READONLY_ROOTS == ()
    fs_ops._h_fs_write(str(tmp_path / "x.txt"), "ok")
    assert "(read-only)" not in fs_ops._h_fs_roots()


def test_a_relative_read_only_root_fails_loudly(tmp_path, monkeypatch, reload_server):
    """Same rule as FS_ALLOW_ROOTS."""
    monkeypatch.setenv("FS_ALLOW_ROOTS", str(tmp_path))
    monkeypatch.setenv("FS_READONLY_ROOTS", "refs")
    with pytest.raises(RuntimeError, match="absolute"):
        reload_server()
