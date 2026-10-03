"""fs_read and its relatives: ranges, truncation, byte paging, batch and
base64 reads, and the outline attached to a large read."""
from __future__ import annotations

import pytest

import fs_ops


# -- read handlers ----------------------------------------------------
def test_fs_read_whole_and_range(tree):
    assert "def greet" in fs_ops._h_fs_read("hello.py")
    assert fs_ops._h_fs_read("src/core.py", 2, 2).strip() == "Y = 43"


def test_fs_read_truncates(tree, monkeypatch):
    """A cut read returns text plus an envelope. The text is unchanged for a
    client that reads only that; the envelope carries the file's true size."""
    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 10)
    text, envelope = fs_ops._h_fs_read("hello.py")
    assert "truncated" in text
    assert envelope["complete"] is False
    assert envelope["total_bytes"] == len((tree / "hello.py").read_bytes())
    assert envelope["content"] == text.split("\n... truncated")[0]
    assert "start_byte=10" in envelope["continue_with"]
    # Absent when the whole file was not read.
    assert "total_lines" not in envelope


def test_fs_read_rejects_binary(tree):
    (tree / "blob.bin").write_bytes(b"\x00\x01\x02binary")
    with pytest.raises(ValueError, match="binary"):
        fs_ops._h_fs_read("blob.bin")


# -- batch and binary reads -------------------------------------------
def test_fs_read_many_returns_each_file(tree):
    out = fs_ops._h_fs_read_many(["hello.py", "src/core.py"])
    assert "===== hello.py =====" in out and "def greet" in out
    assert "===== src/core.py =====" in out and "the answer" in out


def test_fs_read_many_reports_bad_paths_inline(tree):
    out = fs_ops._h_fs_read_many(["hello.py", "../outside/secret.txt", ".env"])
    assert "def greet" in out  # the good file still came back
    assert out.count("Error:") == 2
    assert "not yours" not in out and "sekrit" not in out


def test_fs_read_many_says_how_to_continue_a_truncated_file(tree, monkeypatch):
    """A batch names which file was cut and where to resume."""
    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 10)
    out, envelope = fs_ops._h_fs_read_many(["hello.py", "src/core.py"])
    assert "truncated at 10 bytes" in out
    assert "start_byte=10" in out
    assert "fs_read('hello.py'" in out
    # The batch's own account: summed real sizes, and which files were cut.
    assert envelope["complete"] is False
    assert envelope["total_bytes"] == sum(
        len((tree / f).read_bytes()) for f in ("hello.py", "src/core.py")
    )
    assert "hello.py" in envelope["continue_with"]
    # The real size, so the caller can tell how much is left.
    assert f"of {len((tree / 'hello.py').read_bytes())};" in out


def test_fs_read_many_caps_batch_size(tree, monkeypatch):
    monkeypatch.setattr(fs_ops, "MAX_READ_FILES", 2)
    with pytest.raises(ValueError, match="over FS_MAX_READ_FILES"):
        fs_ops._h_fs_read_many(["a", "b", "c"])


def test_fs_read_base64_handles_binary(tree):
    import base64

    (tree / "blob.bin").write_bytes(b"\x00\x01\x02binary")
    assert base64.b64decode(fs_ops._h_fs_read_base64("blob.bin")) == b"\x00\x01\x02binary"


def test_fs_read_base64_respects_cap_and_containment(tree, monkeypatch):
    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 4)
    with pytest.raises(ValueError, match="over FS_MAX_FILE_BYTES"):
        fs_ops._h_fs_read_base64("hello.py")
    with pytest.raises(ValueError, match="deny pattern"):
        fs_ops._h_fs_read_base64(".env")


# -- byte-offset paging -----------------------------------------------
def test_fs_read_from_byte_offset(tree):
    (tree / "log.txt").write_text("0123456789abcdef")
    assert fs_ops._h_fs_read("log.txt", start_byte=10).startswith("abcdef")


def test_fs_read_paging_reports_next_offset(tree, monkeypatch):
    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 5)
    (tree / "log.txt").write_text("0123456789abcdef")
    first, _ = fs_ops._h_fs_read("log.txt", start_byte=0)  # 0 means the line-range path
    assert "continue with start_byte=5" in first
    second, envelope = fs_ops._h_fs_read("log.txt", start_byte=5)
    assert second.startswith("56789") and "continue with start_byte=10" in second
    assert envelope["total_bytes"] == 16 and "start_byte=10" in envelope["continue_with"]
    last = fs_ops._h_fs_read("log.txt", start_byte=15)
    # A final window is complete, so it is plain text with no envelope at all.
    assert last == "f"


def test_fs_read_rejects_mixing_offset_and_lines(tree):
    with pytest.raises(ValueError, match="cannot be combined"):
        fs_ops._h_fs_read("hello.py", start_line=1, start_byte=4)


def test_fs_read_rejects_offset_past_end(tree):
    with pytest.raises(ValueError, match="past the end"):
        fs_ops._h_fs_read("hello.py", start_byte=10_000)


def test_fs_read_offset_respects_containment(tree):
    with pytest.raises(ValueError, match="deny pattern"):
        fs_ops._h_fs_read(".env", start_byte=1)


# -- outline on read -----------------------------------------------
def test_fs_read_attaches_an_outline_for_a_large_source_file(tree, monkeypatch):
    """A whole file large enough to carry an outline; the counts are the
    file's, not a clip's."""
    monkeypatch.setattr(fs_ops, "OUTLINE_MIN_BYTES", 10)
    big = tree / "big.py"
    big.write_text("class Widget:\n    def render(self):\n        pass\n\ndef main():\n    pass\n")
    text, envelope = fs_ops._h_fs_read("big.py")
    assert "class Widget" in text  # the bytes are still there
    assert envelope["complete"] is True
    assert envelope["total_lines"] == 6
    names = [(e["name"], e["start_line"], e["end_line"]) for e in envelope["outline"]]
    assert ("render", 2, 3) in names and ("main", 5, 6) in names
    assert "start_line=" in envelope["continue_with"]


def test_fs_read_outlines_the_whole_file_not_the_clip(tree, monkeypatch):
    """The outline covers the whole file, not the read clip."""
    monkeypatch.setattr(fs_ops, "OUTLINE_MIN_BYTES", 10)
    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 40)
    big = tree / "big.py"
    big.write_text("".join(f"def f{i}():\n    pass\n" for i in range(50)))
    _, envelope = fs_ops._h_fs_read("big.py")
    assert envelope["complete"] is False
    # The fixture writes 50 definitions; a 40-byte read reaches about two.
    assert len(envelope["outline"]) == 50
    assert envelope["total_lines"] == 100


def test_a_wide_range_is_outlined_for_the_range_it_asked_for(tree, monkeypatch):
    """A ranged read outlines the range it asked for."""
    monkeypatch.setattr(fs_ops, "OUTLINE_MIN_BYTES", 10)
    big = tree / "big.py"
    big.write_text("".join(f"def f{i}():\n    pass\n" for i in range(50)))
    _, envelope = fs_ops._h_fs_read("big.py", start_line=41, end_line=60)
    names = [e["name"] for e in envelope["outline"]]
    # Lines 41-60 hold f20..f29, and nothing from either side of them.
    assert names == [f"f{i}" for i in range(20, 30)]


def test_a_line_past_the_byte_ceiling_is_reachable(tree, monkeypatch):
    """A range seeks by line, so a line past MAX_FILE_BYTES is reachable by
    number - `start_byte` is not something a caller reading source can compute."""
    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 200)
    big = tree / "big.py"
    big.write_text("".join(f"def f{i:04d}():\n    pass\n" for i in range(400)))
    assert big.stat().st_size > 200 * 10  # the target is far past the ceiling
    result = fs_ops._h_fs_read("big.py", start_line=501, end_line=502)
    text = result[0] if isinstance(result, tuple) else result
    assert "def f0250" in text


def test_a_range_that_overruns_the_ceiling_continues_by_line(tree, monkeypatch):
    """A ranged read continues by line, not by byte."""
    monkeypatch.setattr(fs_ops, "MAX_FILE_BYTES", 200)
    big = tree / "big.py"
    big.write_text("".join(f"def f{i:04d}():\n    pass\n" for i in range(400)))
    text, envelope = fs_ops._h_fs_read("big.py", start_line=1)
    assert "continue with start_line=" in text
    assert "start_line=" in envelope["continue_with"]
    assert envelope["complete"] is False


def test_a_range_past_the_end_says_so(tree):
    result = fs_ops._h_fs_read("hello.py", start_line=9999)
    assert "does not reach line 9999" in result


def test_a_thin_outline_is_not_attached_at_all(tree, monkeypatch):
    """A flat document parses to a handful of entries however large it is;
    that map is worth less than the bytes."""
    monkeypatch.setattr(fs_ops, "OUTLINE_MIN_BYTES", 10)
    thin = tree / "thin.py"
    thin.write_text("def only_one():\n    pass\n" + "x = 1\n" * 400)
    result = fs_ops._h_fs_read("thin.py")
    # Plain text, no envelope: nothing to say beyond the bytes themselves.
    assert isinstance(result, str)


def test_a_rich_outline_is_still_attached(tree, monkeypatch):
    """The other half - the guard must not suppress a useful map."""
    monkeypatch.setattr(fs_ops, "OUTLINE_MIN_BYTES", 10)
    rich = tree / "rich.py"
    rich.write_text("".join(f"def f{i}():\n    pass\n" for i in range(20)))
    _, envelope = fs_ops._h_fs_read("rich.py")
    assert len(envelope["outline"]) == 20
