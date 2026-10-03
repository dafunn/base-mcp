"""Filesystem handlers: path containment, listing and search, and the
write-side tools. Reads live in test_fs_read.py."""
from __future__ import annotations

import asyncio

import pytest

import fs_ops
import server as srv


def _run(coro):
    return asyncio.run(coro)


# -- path containment -------------------------------------------------
def test_resolve_accepts_paths_in_root(tree):
    assert fs_ops._resolve(str(tree / "hello.py")).name == "hello.py"
    assert fs_ops._resolve("src/core.py").name == "core.py"  # relative to the first root


@pytest.mark.parametrize("bad", ["../outside/secret.txt", "src/../../outside/secret.txt", "/etc/passwd"])
def test_resolve_rejects_traversal_and_absolute_escape(tree, bad):
    with pytest.raises(ValueError, match="outside the allowed roots"):
        fs_ops._resolve(bad)


def test_resolve_rejects_symlink_out_of_root(tree):
    """The link lives inside the root; what it points at does not."""
    with pytest.raises(ValueError, match="outside the allowed roots"):
        fs_ops._resolve("escape")


@pytest.mark.parametrize("secret", [".env", ".git/config", ".git"])
def test_resolve_rejects_denied_paths(tree, secret):
    with pytest.raises(ValueError, match="deny pattern"):
        fs_ops._resolve(secret)


def test_resolve_refuses_when_no_roots(tree, monkeypatch):
    monkeypatch.setattr(fs_ops, "ALLOW_ROOTS", ())
    with pytest.raises(ValueError, match="no filesystem roots"):
        fs_ops._resolve("hello.py")


def test_empty_path_rejected(tree):
    with pytest.raises(ValueError, match="path is required"):
        fs_ops._resolve("   ")


# -- read handlers ----------------------------------------------------
def test_fs_roots_reports_scope(tree):
    out = fs_ops._h_fs_roots()
    assert str(tree.resolve()) in out and "Writes: disabled" in out


def test_fs_list_depth_and_denied_entries(tree):
    shallow = fs_ops._h_fs_list(str(tree), depth=1)
    assert "hello.py" in shallow and "src/" in shallow
    assert "src/core.py" not in shallow
    deep = fs_ops._h_fs_list(str(tree), depth=0)
    assert "src/core.py" in deep
    # Neither depth ever shows the secrets, and the symlink is listed but not followed.
    for out in (shallow, deep):
        assert ".env" not in out and ".git" not in out
        assert "TOKEN" not in out


def test_fs_list_truncates(tree, monkeypatch):
    monkeypatch.setattr(fs_ops, "MAX_ENTRIES", 2)
    assert "truncated" in fs_ops._h_fs_list(str(tree), depth=0)


def test_fs_glob(tree):
    out = fs_ops._h_fs_glob(str(tree), "**/*.py")
    assert "hello.py" in out and "src/core.py" in out and "README.md" not in out


def test_fs_grep_matches_include_and_case(tree):
    out = fs_ops._h_fs_grep(str(tree), "the answer")
    assert "src/core.py:1" in out
    assert "No matches" in fs_ops._h_fs_grep(str(tree), "the answer", include="*.md")
    assert "hello.py" in fs_ops._h_fs_grep(str(tree), "GREET", ignore_case=True)


def test_fs_grep_never_reads_denied_files(tree):
    assert "No matches" in fs_ops._h_fs_grep(str(tree), "sekrit")


def test_fs_grep_caps_matches(tree, monkeypatch):
    monkeypatch.setattr(fs_ops, "MAX_GREP_MATCHES", 1)
    (tree / "many.txt").write_text("hit\nhit\nhit\n")
    assert "truncated" in fs_ops._h_fs_grep(str(tree), "hit")


def test_fs_stat(tree):
    out = fs_ops._h_fs_stat("hello.py")
    assert "kind:  file" in out and "size:" in out


# -- the write gate ---------------------------------------------------
def test_write_and_append(writable):
    fs_ops._h_fs_write("out/report.txt", "one\n")
    fs_ops._h_fs_write("out/report.txt", "two\n", append=True)
    assert (writable / "out" / "report.txt").read_text() == "one\ntwo\n"


def test_write_respects_containment(writable):
    for bad in ("../outside/pwned.txt", ".env"):
        with pytest.raises(ValueError):
            fs_ops._h_fs_write(bad, "x")
    assert not (writable.parent / "outside" / "pwned.txt").exists()
    assert (writable / ".env").read_text() == "TOKEN=sekrit\n"


def test_write_rejects_oversized_content(writable, monkeypatch):
    monkeypatch.setattr(fs_ops, "MAX_WRITE_BYTES", 4)
    with pytest.raises(ValueError, match="over FS_MAX_WRITE_BYTES"):
        fs_ops._h_fs_write("big.txt", "much too long")


def test_mkdir_move_delete(writable):
    fs_ops._h_fs_mkdir("a/b")
    assert (writable / "a" / "b").is_dir()
    fs_ops._h_fs_move("hello.py", "a/b/hello.py")
    assert (writable / "a" / "b" / "hello.py").is_file() and not (writable / "hello.py").exists()
    fs_ops._h_fs_delete("a/b/hello.py")
    assert not (writable / "a" / "b" / "hello.py").exists()
    fs_ops._h_fs_delete("a", recursive=True)
    assert not (writable / "a").exists()


def test_move_cannot_leave_the_roots(writable):
    with pytest.raises(ValueError, match="outside the allowed roots"):
        fs_ops._h_fs_move("hello.py", "../outside/hello.py")


def test_delete_needs_recursive_for_directories(writable):
    with pytest.raises(ValueError, match="recursive"):
        fs_ops._h_fs_delete("src")


def test_delete_refuses_a_root(writable):
    with pytest.raises(ValueError, match="refusing to delete a configured root"):
        fs_ops._h_fs_delete(str(writable))


# -- fs_edit ----------------------------------------------------------
def test_fs_edit_replaces_unique_match(writable):
    fs_ops._h_fs_edit("src/core.py", "X = 42", "X = 99")
    assert (writable / "src" / "core.py").read_text() == "X = 99  # the answer\nY = 43\n"


def test_fs_edit_refuses_ambiguous_match(writable):
    (writable / "dup.txt").write_text("same\nsame\n")
    with pytest.raises(ValueError, match="appears 2 times"):
        fs_ops._h_fs_edit("dup.txt", "same", "other")
    assert (writable / "dup.txt").read_text() == "same\nsame\n"  # untouched


def test_fs_edit_replace_all(writable):
    (writable / "dup.txt").write_text("same\nsame\n")
    out = fs_ops._h_fs_edit("dup.txt", "same", "other", replace_all=True)
    assert "2 occurrence" in out
    assert (writable / "dup.txt").read_text() == "other\nother\n"


def test_fs_edit_missing_string_errors(writable):
    with pytest.raises(ValueError, match="not found"):
        fs_ops._h_fs_edit("hello.py", "not in the file", "x")


def test_fs_edit_refuses_invalid_utf8(writable):
    """A lossy decode would write the damage back, unlike a read."""
    (writable / "latin.txt").write_bytes(b"caf\xe9 au lait\n")
    with pytest.raises(ValueError, match="not valid UTF-8"):
        fs_ops._h_fs_edit("latin.txt", "au lait", "noir")
    assert (writable / "latin.txt").read_bytes() == b"caf\xe9 au lait\n"


def test_fs_edit_respects_containment_and_gate(tree):
    with pytest.raises(ValueError, match="deny pattern"):
        fs_ops._h_fs_edit(".env", "TOKEN", "STOLEN")
    assert "disabled (EXPOSE_WRITE=false)" in _run(
        srv._dispatch("fs_edit", {"path": "hello.py", "old_string": "hi", "new_string": "bye"})
    )
    assert "hi" in (tree / "hello.py").read_text()


def test_fs_edit_refuses_oversized_file(writable, monkeypatch):
    monkeypatch.setattr(fs_ops, "MAX_WRITE_BYTES", 4)
    with pytest.raises(ValueError, match="too large to edit"):
        fs_ops._h_fs_edit("hello.py", "greet", "hello")


# -- atomic writes ----------------------------------------------------
def test_write_leaves_no_temp_files(writable):
    fs_ops._h_fs_write("out.txt", "content\n")
    fs_ops._h_fs_edit("out.txt", "content", "replaced")
    assert [f.name for f in writable.iterdir() if ".tmp-" in f.name] == []
    assert (writable / "out.txt").read_text() == "replaced\n"


# -- base64 writes ----------------------------------------------------
def test_fs_write_base64_roundtrip(writable):
    import base64

    payload = b"\x89PNG\r\n\x1a\n binary-ish"
    fs_ops._h_fs_write_base64("assets/img.png", base64.b64encode(payload).decode())
    assert (writable / "assets" / "img.png").read_bytes() == payload


def test_fs_write_base64_rejects_bad_input(writable):
    with pytest.raises(ValueError, match="not valid base64"):
        fs_ops._h_fs_write_base64("x.bin", "not base64 !!")


def test_fs_write_base64_respects_containment(writable):
    import base64

    with pytest.raises(ValueError, match="outside the allowed roots"):
        fs_ops._h_fs_write_base64("../outside/x.bin", base64.b64encode(b"x").decode())


# -- fs_copy ----------------------------------------------------------
def test_fs_copy_file(writable):
    fs_ops._h_fs_copy("hello.py", "backup/hello.py")
    assert (writable / "backup" / "hello.py").read_text() == (writable / "hello.py").read_text()


def test_fs_copy_directory_needs_recursive(writable):
    with pytest.raises(ValueError, match="recursive"):
        fs_ops._h_fs_copy("src", "src-copy")


def test_fs_copy_cannot_leave_the_roots(writable):
    with pytest.raises(ValueError, match="outside the allowed roots"):
        fs_ops._h_fs_copy(str(writable), str(writable.parent / "workspace-copy"), recursive=True)
    assert not (writable.parent / "workspace-copy").exists()


def test_fs_copy_tree_omits_secrets_and_keeps_links_unresolved(writable):
    fs_ops._h_fs_copy(".", "snapshot", recursive=True)
    snap = writable / "snapshot"
    assert (snap / "src" / "core.py").is_file()
    assert not (snap / ".env").exists() and not (snap / ".git").exists()
    # The escape link is copied as a link, not as the contents of its target.
    assert (snap / "escape").is_symlink()
    assert "not yours" not in fs_ops._h_fs_list(str(snap), depth=0)


def test_fs_copy_refuses_existing_destination(writable):
    with pytest.raises(ValueError, match="already exists"):
        fs_ops._h_fs_copy("hello.py", "README.md")
