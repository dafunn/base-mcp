"""Filesystem tools, confined to an explicit list of allowed roots.

Deny-by-default and enforced here rather than in the tool arguments, so the
model cannot widen the scope by asking. Roots are absolute and resolved once at
import.

Reads are always available. Writes are gated on `config.EXPOSE_WRITE`, and a
root listed in FS_READONLY_ROOTS is served for reading and refused for writing
even when that gate is open.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import config
import outline
from config import csv_env
from content import is_binary


def _roots() -> tuple[Path, ...]:
    """Resolve FS_ALLOW_ROOTS once, at import.

    Empty means deny. A relative entry is a configuration error: resolving it
    against the process cwd would make the scope depend on how the container
    was started.
    """
    out: list[Path] = []
    for raw in csv_env("FS_ALLOW_ROOTS"):
        p = Path(raw)
        if not p.is_absolute():
            raise RuntimeError(
                f"FS_ALLOW_ROOTS entry '{raw}' is not an absolute path - roots must be absolute"
            )
        out.append(p.resolve())
    return tuple(out)


# Sensitive paths never served, even inside an allowed root.
_DEFAULT_DENY = (
    "**/.git,**/.git/**,"
    "**/.ssh,**/.ssh/**,"
    "**/.gnupg,**/.gnupg/**,"
    "**/.aws,**/.aws/**,"
    "**/.kube,**/.kube/**,"
    "**/.env,**/.env.*,"
    "**/.netrc,**/.npmrc,"
    "**/*.pem,**/*.key,**/id_rsa*,**/id_ecdsa*,**/id_ed25519*,"
    "**/.docker/config.json"
)

def _readonly_roots() -> tuple[Path, ...]:
    """Resolve FS_READONLY_ROOTS once, at import.

    A root listed here is served for reading and refused for writing; `fs_roots`
    reports it up front and a refusal names the policy rather than a bare EPERM.
    Absolute, like FS_ALLOW_ROOTS, for the same reason.
    """
    out: list[Path] = []
    for raw in csv_env("FS_READONLY_ROOTS"):
        p = Path(raw)
        if not p.is_absolute():
            raise RuntimeError(
                f"FS_READONLY_ROOTS entry '{raw}' is not an absolute path - roots must be absolute"
            )
        out.append(p.resolve())
    return tuple(out)


ALLOW_ROOTS = _roots()
READONLY_ROOTS = _readonly_roots()
DENY_GLOBS = csv_env("FS_DENY_GLOBS", _DEFAULT_DENY)

# A resource ceiling, not a policy one: the client clips tool output far below
# this, so all this bounds is memory and wire cost.
MAX_FILE_BYTES = int(os.getenv("FS_MAX_FILE_BYTES", "200000"))
MAX_WRITE_BYTES = int(os.getenv("FS_MAX_WRITE_BYTES", "1000000"))
MAX_ENTRIES = int(os.getenv("FS_MAX_ENTRIES", "2000"))
MAX_GREP_MATCHES = int(os.getenv("FS_MAX_GREP_MATCHES", "200"))
MAX_READ_FILES = int(os.getenv("FS_MAX_READ_FILES", "20"))

# Outlining parses the whole file, not the read clip. tree-sitter holds both
# the source and the tree, so the parse gets its own ceiling.
MAX_OUTLINE_BYTES = int(os.getenv("FS_MAX_OUTLINE_BYTES", "4000000"))
# Below this a file is small enough to need no outline.
OUTLINE_MIN_BYTES = int(os.getenv("FS_OUTLINE_MIN_BYTES", "4096"))
# Below this count no outline is attached: a flat document parses to a handful
# of entries however large it is.
MIN_OUTLINE_ENTRIES = int(os.getenv("FS_MIN_OUTLINE_ENTRIES", "3"))


# -- Path containment -------------------------------------------------


def _denied(p: Path) -> str | None:
    """Return the deny pattern matching this path or one of its parents, else None.

    Patterns are fnmatch-style over the whole posix path, so `*` crosses
    separators and `**/.env` reads as "any .env anywhere". Parents are checked
    too, so a denied directory cannot be entered by naming a child directly.
    """
    for candidate in (p, *p.parents):
        s = candidate.as_posix()
        for pat in DENY_GLOBS:
            if fnmatch.fnmatchcase(s, pat):
                return pat
    return None


def _resolve(path: str) -> Path:
    """Resolve a caller-supplied path to a real path inside the allowed roots.

    `Path.resolve()` collapses `..` and follows symlinks, so a traversal
    argument and a symlink pointing out of the root both land outside the roots
    and are rejected by the same containment check. The check is on the
    resolved path only - never on the string the caller passed.
    """
    if not ALLOW_ROOTS:
        raise ValueError(
            "no filesystem roots are configured (FS_ALLOW_ROOTS is empty, which denies everything)"
        )
    if not path or not path.strip():
        raise ValueError("path is required")
    raw = Path(path)
    if not raw.is_absolute():
        raw = ALLOW_ROOTS[0] / raw  # relative paths are relative to the first root
    rp = raw.resolve()
    if not any(rp == root or root in rp.parents for root in ALLOW_ROOTS):
        raise ValueError(f"path '{path}' resolves outside the allowed roots")
    pat = _denied(rp)
    if pat:
        raise ValueError(f"path '{path}' is blocked by deny pattern '{pat}'")
    return rp


def _readonly(rp: Path) -> Path | None:
    """The read-only root containing this resolved path, if any."""
    for root in READONLY_ROOTS:
        if rp == root or root in rp.parents:
            return root
    return None


def _resolve_write(path: str) -> Path:
    """Resolve for a tool that changes the filesystem.

    Separate from `_resolve` so a read-only root stays readable by every tool
    that only reads.
    """
    rp = _resolve(path)
    root = _readonly(rp)
    if root is not None:
        raise ValueError(
            f"path '{path}' is under the read-only root '{root.as_posix()}' "
            "(FS_READONLY_ROOTS) and may be read but not changed"
        )
    return rp


def _rel(p: Path) -> str:
    """Path as the caller should see it: relative to its root when it is under one."""
    for root in ALLOW_ROOTS:
        if p == root:
            return "."
        if root in p.parents:
            return p.relative_to(root).as_posix()
    return p.as_posix()


def _read_text(p: Path, max_bytes: int) -> tuple[str, bool]:
    """Read up to max_bytes of a file as text. Returns (text, truncated).

    Reads the cap plus one byte, never the whole file, so a huge file cannot
    exhaust the server's memory.
    """
    with p.open("rb") as fh:
        data = fh.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    if is_binary(data[:8192]):
        raise ValueError(f"'{_rel(p)}' looks like a binary file")
    return data.decode("utf-8", "replace"), truncated


# -- Filesystem handlers (read) ---------------------------------------


def _h_fs_roots() -> str:
    if not ALLOW_ROOTS:
        return "No roots configured. Every filesystem tool will refuse (FS_ALLOW_ROOTS is empty)."
    lines = ["Allowed roots:"]
    for r in ALLOW_ROOTS:
        note = "" if r.is_dir() else "  (missing)"
        if _readonly(r) is not None:
            note += "  (read-only)"
        lines.append(f"  {r.as_posix()}{note}")
    # Reported even when it sits outside the allowed roots, so a root that is
    # configured read-only but not readable is visible rather than silent.
    for r in READONLY_ROOTS:
        if r not in ALLOW_ROOTS:
            lines.append(f"  {r.as_posix()}  (read-only)")
    lines.append(f"Writes: {'enabled' if config.EXPOSE_WRITE else 'disabled'}")
    lines.append(f"Deny patterns: {len(DENY_GLOBS)}")
    return "\n".join(lines)


def _walk(base: Path, depth: int) -> tuple[list[str], bool]:
    """Breadth-first listing under base, pruning denied entries. (lines, truncated)."""
    lines: list[str] = []
    queue: list[tuple[Path, int]] = [(base, 0)]
    while queue:
        current, level = queue.pop(0)
        try:
            entries = sorted(current.iterdir(), key=lambda e: (not e.is_dir(), e.name))
        except (NotADirectoryError, PermissionError, FileNotFoundError) as exc:
            raise ValueError(f"cannot list '{_rel(current)}': {exc.__class__.__name__}") from exc
        for e in entries:
            if _denied(e):
                continue
            if len(lines) >= MAX_ENTRIES:
                return lines, True
            if e.is_symlink():
                lines.append(f"{'link':>6}  {_rel(e)} -> {os.readlink(e)}")
                continue
            if e.is_dir():
                lines.append(f"{'dir':>6}  {_rel(e)}/")
                if depth == 0 or level + 1 < depth:
                    queue.append((e, level + 1))
            elif e.is_file():
                lines.append(f"{e.stat().st_size:>6}  {_rel(e)}")
    return lines, False


def _h_fs_list(path: str, depth: int = 1) -> str:
    p = _resolve(path)
    if p.is_file():
        return f"{p.stat().st_size:>6}  {_rel(p)}"
    lines, truncated = _walk(p, max(depth, 0))
    if not lines:
        return f"(empty) {_rel(p)}"
    if truncated:
        lines.append(f"... truncated at {MAX_ENTRIES} entries (FS_MAX_ENTRIES)")
    return "\n".join(lines)


# A read that could not return everything says so in structured content as
# well as in the text trailer; the envelope carries the file's true size. A
# small, complete read stays plain text.
ENVELOPE_VERSION = 1


def _envelope(
    content: str,
    rel: str,
    total_bytes: int,
    resume_at: int | None = None,
    total_lines: int = 0,
    entries: list | None = None,
) -> dict:
    """Structured content for a read that was cut, or a whole file large
    enough to carry an outline."""
    env: dict = {
        "base_mcp_envelope": ENVELOPE_VERSION,
        "content": content,
        "complete": resume_at is None,
        "total_bytes": total_bytes,
        "label": rel,
    }
    if resume_at is not None:
        env["continue_with"] = f"continue with fs_read('{rel}', start_byte={resume_at})."
    # Only set from a whole-file parse, so it is the file's count and not the
    # clip's.
    if total_lines:
        env["total_lines"] = total_lines
    if entries:
        env["outline"] = [
            {"name": e.name, "kind": e.kind, "start_line": e.start_line,
             "end_line": e.end_line, "depth": e.depth}
            for e in entries
        ]
        env["continue_with"] = (
            f"read a definition with fs_read('{rel}', start_line=..., end_line=...)."
        )
    return env


def _outline_for(p: Path, suffix: str, whole: bytes | None) -> tuple[list, int]:
    """`(entries, total_lines)` from a whole-file parse, or `([], 0)`.

    `whole` is the file's bytes when the caller already has them; otherwise
    they are read here, which is why the ceiling is checked first.
    """
    if not outline.supported(suffix):
        return [], 0
    try:
        source = p.read_bytes() if whole is None else whole
    except OSError:
        return [], 0
    if not source or len(source) > MAX_OUTLINE_BYTES:
        return [], 0
    entries = outline.outline_source(source, suffix)
    if not entries or len(entries) < MIN_OUTLINE_ENTRIES:
        # The line count is only reported alongside an outline.
        return [], 0
    return entries, len(source.splitlines())


def _read_line_range(p: Path, start: int, end: int, max_bytes: int) -> tuple[str, bool]:
    """Lines `start`..`end` (1-based, inclusive), found by reading forward.

    `max_bytes` bounds what is kept, not what is skipped.
    """
    kept: list[bytes] = []
    size = 0
    truncated = False
    with p.open("rb") as fh:
        if is_binary(fh.read(8192)):
            raise ValueError(f"'{_rel(p)}' looks like a binary file")
        fh.seek(0)
        for n, raw in enumerate(fh, 1):
            if n < start:
                continue
            if end and n > end:
                break
            size += len(raw)
            if size > max_bytes:
                truncated = True
                break
            kept.append(raw)
    text = b"".join(kept).decode("utf-8", "replace")
    # `splitlines`/join, matching the whole-file path: CRLF normalises to LF
    # and a trailing newline does not leave an empty last line.
    return "\n".join(text.splitlines()), truncated


def _h_fs_read(
    path: str,
    start_line: int = 0,
    end_line: int = 0,
    start_byte: int = 0,
    outline_only: bool = False,
) -> str | tuple[str, dict]:
    """Read a text file by line range, or by byte offset for paging through a big one.

    Line ranges suit source files; `start_byte` walks a large log or a
    single-line document a window at a time, and the trailer names the next
    offset.
    """
    p = _resolve(path)
    if not p.is_file():
        raise ValueError(f"'{_rel(p)}' is not a file")
    if start_byte and (start_line or end_line):
        raise ValueError("start_byte cannot be combined with start_line/end_line")
    if start_byte < 0:
        raise ValueError("start_byte cannot be negative")

    size = p.stat().st_size
    if start_byte:
        if start_byte >= size:
            raise ValueError(f"start_byte {start_byte} is at or past the end of '{_rel(p)}' ({size} bytes)")
        with p.open("rb") as fh:
            fh.seek(start_byte)
            data = fh.read(MAX_FILE_BYTES)
        if is_binary(data[:8192]):
            raise ValueError(f"'{_rel(p)}' looks like a binary file")
        # A window can split a multi-byte character at either edge; replacing is
        # right here, where the text is only ever read back out.
        body = data.decode("utf-8", "replace")
        end = start_byte + len(data)
        if end < size:
            trailer = f"\n... bytes {start_byte}-{end} of {size}; continue with start_byte={end}"
            return body + trailer, _envelope(body, _rel(p), size, end)
        return body

    ranged = bool(start_line or end_line)
    start = max(start_line, 1)
    end = end_line if end_line else 0

    # An explicit request for structure; without it a range means bytes.
    if outline_only:
        entries, total_lines = _outline_for(p, p.suffix, None)
        if not entries:
            return (
                f"(no structure; '{_rel(p)}' is not a file this server can parse, "
                f"or holds too little to map)"
            )
        if ranged:
            hi = end or (total_lines or 10**9)
            entries = [e for e in entries if e.start_line <= hi and e.end_line >= start]
            if not entries:
                return f"(no definitions in '{_rel(p)}' between lines {start} and {hi})"
        return "", _envelope("", _rel(p), size, None, total_lines, entries)

    if ranged:
        # Seek by line, so a number past the byte ceiling still resolves.
        body, truncated = _read_line_range(p, start, end, MAX_FILE_BYTES)
        whole = None
        if not body:
            return f"(no lines; '{_rel(p)}' does not reach line {start})"
    else:
        text, truncated = _read_text(p, MAX_FILE_BYTES)
        body = "\n".join(text.splitlines())
        whole = None if truncated else text.encode("utf-8", "replace")

    entries, total_lines = ([], 0)
    if size >= OUTLINE_MIN_BYTES:
        entries, total_lines = _outline_for(p, p.suffix, whole)
        if ranged and entries:
            # Structure of the range asked for, not of the whole file.
            hi = end or (total_lines or 10**9)
            entries = [e for e in entries if e.start_line <= hi and e.end_line >= start]

    if truncated:
        if ranged:
            nxt = start + len(body.splitlines())
            trailer = (
                f"\n... stopped at {MAX_FILE_BYTES} bytes (FS_MAX_FILE_BYTES); "
                f"continue with start_line={nxt}"
            )
            return body + trailer, _envelope(
                body, _rel(p), size, None, total_lines, entries
            ) | {"complete": False,
                 "continue_with": f"continue with fs_read('{_rel(p)}', start_line={nxt})."}
        trailer = (
            f"\n... truncated at {MAX_FILE_BYTES} bytes (FS_MAX_FILE_BYTES) of {size}; "
            f"continue with start_byte={MAX_FILE_BYTES}"
        )
        return body + trailer, _envelope(
            body, _rel(p), size, MAX_FILE_BYTES, total_lines, entries
        )
    if entries:
        return body, _envelope(body, _rel(p), size, None, total_lines, entries)
    return body


def _h_fs_glob(path: str, pattern: str) -> str:
    p = _resolve(path)
    if not pattern:
        raise ValueError("pattern is required")
    if not p.is_dir():
        raise ValueError(f"'{_rel(p)}' is not a directory")
    hits: list[str] = []
    for hit in sorted(p.glob(pattern)):
        if _denied(hit):
            continue
        if len(hits) >= MAX_ENTRIES:
            hits.append(f"... truncated at {MAX_ENTRIES} entries (FS_MAX_ENTRIES)")
            break
        hits.append(_rel(hit) + ("/" if hit.is_dir() else ""))
    return "\n".join(hits) if hits else f"No matches for '{pattern}' under {_rel(p)}"


def _h_fs_grep(path: str, pattern: str, include: str = "", ignore_case: bool = False) -> str:
    p = _resolve(path)
    if not pattern:
        raise ValueError("pattern is required")
    try:
        rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc

    files: list[Path] = [p] if p.is_file() else [f for f in sorted(p.rglob(include or "*")) if f.is_file()]
    out: list[str] = []
    for f in files:
        if _denied(f):
            continue
        try:
            text, _ = _read_text(f, MAX_FILE_BYTES)
        except (ValueError, OSError):
            continue  # binary or unreadable: not an error, just not a match
        for n, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                out.append(f"{_rel(f)}:{n}: {line.strip()[:300]}")
                if len(out) >= MAX_GREP_MATCHES:
                    out.append(f"... truncated at {MAX_GREP_MATCHES} matches (FS_MAX_GREP_MATCHES)")
                    return "\n".join(out)
    return "\n".join(out) if out else f"No matches for '{pattern}' under {_rel(p)}"


def _h_fs_stat(path: str) -> str:
    p = _resolve(path)
    try:
        st = p.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"'{_rel(p)}' does not exist") from exc
    kind = "dir" if p.is_dir() else "symlink" if p.is_symlink() else "file"
    mtime = datetime.fromtimestamp(st.st_mtime, UTC).isoformat(timespec="seconds")
    return "\n".join([
        f"path:  {_rel(p)}",
        f"kind:  {kind}",
        f"size:  {st.st_size}",
        f"mode:  {oct(st.st_mode & 0o777)}",
        f"mtime: {mtime}",
    ])


def _h_fs_read_many(paths: list) -> str | tuple[str, dict]:
    """Read several files in one call.

    One unreadable path reports inline instead of failing the batch. A batch
    that had to cut any of its files returns an envelope too, with the summed
    real sizes.
    """
    if not paths:
        raise ValueError("paths is required")
    if len(paths) > MAX_READ_FILES:
        raise ValueError(f"{len(paths)} paths requested, over FS_MAX_READ_FILES ({MAX_READ_FILES})")
    out: list[str] = []
    total_bytes = 0
    cut: list[str] = []
    for raw in paths:
        try:
            p = _resolve(str(raw))
            if not p.is_file():
                raise ValueError(f"'{_rel(p)}' is not a file")
            total_bytes += p.stat().st_size
            text, truncated = _read_text(p, MAX_FILE_BYTES)
            if truncated:
                cut.append(_rel(p))
                # Name the file and the offset: a batch concatenates several.
                text += (
                    f"\n... truncated at {MAX_FILE_BYTES} bytes (FS_MAX_FILE_BYTES) "
                    f"of {p.stat().st_size}; continue with "
                    f"fs_read('{_rel(p)}', start_byte={MAX_FILE_BYTES})"
                )
            out.append(f"===== {_rel(p)} =====\n{text}")
        except (ValueError, OSError) as exc:
            out.append(f"===== {raw} =====\nError: {exc}")
    body = "\n\n".join(out)
    if not cut:
        return body
    return body, {
        "base_mcp_envelope": ENVELOPE_VERSION,
        "content": body,
        "complete": False,
        "total_bytes": total_bytes,
        # Not counted: it would mean reading every file whole.
        "label": f"{len(paths)} files",
        "continue_with": (
            "read one file at a time with fs_read(path, start_byte=...); "
            f"cut: {', '.join(cut)}."
        ),
    }


def _h_fs_read_base64(path: str) -> str:
    """Read any file, text or not, as base64 - the only way to get bytes out."""
    p = _resolve(path)
    if not p.is_file():
        raise ValueError(f"'{_rel(p)}' is not a file")
    size = p.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"'{_rel(p)}' is {size} bytes, over FS_MAX_FILE_BYTES ({MAX_FILE_BYTES})")
    return base64.b64encode(p.read_bytes()).decode("ascii")


# -- Filesystem handlers (write, gated by EXPOSE_WRITE) ----------------


def _atomic_write(p: Path, data: bytes) -> None:
    """Write through a temp file in the same directory, then rename over, so an
    interrupted write leaves the old content rather than a truncated file."""
    tmp = p.with_name(f".{p.name}.tmp-{os.getpid()}")
    try:
        with tmp.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    finally:
        tmp.unlink(missing_ok=True)


def _h_fs_write(path: str, content: str, append: bool = False) -> str:
    p = _resolve_write(path)
    data = content.encode("utf-8")
    if len(data) > MAX_WRITE_BYTES:
        raise ValueError(f"content is {len(data)} bytes, over FS_MAX_WRITE_BYTES ({MAX_WRITE_BYTES})")
    if p.is_dir():
        raise ValueError(f"'{_rel(p)}' is a directory")
    # Parents are created: every one of them resolved inside an allowed root.
    p.parent.mkdir(parents=True, exist_ok=True)
    if append:
        with p.open("ab") as fh:
            fh.write(data)
    else:
        _atomic_write(p, data)
    return f"{'Appended' if append else 'Wrote'} {len(data)} bytes to {_rel(p)}"


def _h_fs_mkdir(path: str) -> str:
    p = _resolve_write(path)
    p.mkdir(parents=True, exist_ok=True)
    return f"Created {_rel(p)}/"


def _h_fs_move(src: str, dest: str) -> str:
    # Both ends: a move out of a read-only root would remove the source.
    s = _resolve_write(src)
    d = _resolve_write(dest)  # the destination is contained too: no move out of the roots
    if not s.exists():
        raise ValueError(f"'{_rel(s)}' does not exist")
    if d.exists():
        raise ValueError(f"'{_rel(d)}' already exists")
    d.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(s), str(d))
    return f"Moved {_rel(s)} -> {_rel(d)}"


def _h_fs_delete(path: str, recursive: bool = False) -> str:
    p = _resolve_write(path)
    if p in ALLOW_ROOTS:
        raise ValueError("refusing to delete a configured root")
    if not p.exists():
        raise ValueError(f"'{_rel(p)}' does not exist")
    if p.is_dir():
        if not recursive:
            raise ValueError(f"'{_rel(p)}' is a directory (pass recursive=true)")
        shutil.rmtree(p)
        return f"Deleted directory {_rel(p)}"
    p.unlink()
    return f"Deleted {_rel(p)}"


def _h_fs_edit(path: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    """Replace an exact string in a file.

    The match is literal, not a regex: a regex the caller got subtly wrong
    would silently rewrite the wrong span.
    """
    p = _resolve_write(path)
    if not p.is_file():
        raise ValueError(f"'{_rel(p)}' is not a file")
    if not old_string:
        raise ValueError("old_string is required (use fs_write to create a file)")
    size = p.stat().st_size
    if size > MAX_WRITE_BYTES:
        raise ValueError(
            f"'{_rel(p)}' is {size} bytes, over FS_MAX_WRITE_BYTES ({MAX_WRITE_BYTES}) - too large to edit whole"
        )
    raw = p.read_bytes()
    try:
        # Strict, unlike a read: a lossy decode here would write the damage back.
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"'{_rel(p)}' is not valid UTF-8; refusing to rewrite it") from exc

    count = text.count(old_string)
    if count == 0:
        raise ValueError("old_string not found (whitespace and indentation must match exactly)")
    if count > 1 and not replace_all:
        raise ValueError(
            f"old_string appears {count} times; add surrounding context to make it unique, or pass replace_all=true"
        )
    updated = text.replace(old_string, new_string) if replace_all else text.replace(old_string, new_string, 1)
    data = updated.encode("utf-8")
    if len(data) > MAX_WRITE_BYTES:
        raise ValueError(f"result would be {len(data)} bytes, over FS_MAX_WRITE_BYTES ({MAX_WRITE_BYTES})")
    _atomic_write(p, data)
    return f"Replaced {count if replace_all else 1} occurrence(s) in {_rel(p)}"


def _copy_ignore(directory: str, names: list[str]) -> set[str]:
    base = Path(directory)
    return {n for n in names if _denied(base / n)}


def _h_fs_copy(src: str, dest: str, recursive: bool = False) -> str:
    # The source is only read, so copying out of a read-only root is allowed.
    s = _resolve(src)
    d = _resolve_write(dest)  # the destination is contained too: no copy out of the roots
    if not s.exists():
        raise ValueError(f"'{_rel(s)}' does not exist")
    if d.exists():
        raise ValueError(f"'{_rel(d)}' already exists")
    d.parent.mkdir(parents=True, exist_ok=True)
    if s.is_dir():
        if not recursive:
            raise ValueError(f"'{_rel(s)}' is a directory (pass recursive=true)")
        # symlinks=True copies links as links: dereferencing would pull in
        # targets outside the roots. Denied names are skipped.
        shutil.copytree(s, d, symlinks=True, ignore=_copy_ignore)
        return f"Copied directory {_rel(s)} -> {_rel(d)}"
    shutil.copy2(s, d)
    return f"Copied {_rel(s)} -> {_rel(d)}"


def _h_fs_write_base64(path: str, content_base64: str) -> str:
    """Write bytes decoded from base64 - the only way to put a non-text file in place."""
    p = _resolve_write(path)
    try:
        data = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"content_base64 is not valid base64: {exc}") from exc
    if len(data) > MAX_WRITE_BYTES:
        raise ValueError(f"content is {len(data)} bytes, over FS_MAX_WRITE_BYTES ({MAX_WRITE_BYTES})")
    if p.is_dir():
        raise ValueError(f"'{_rel(p)}' is a directory")
    p.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(p, data)
    return f"Wrote {len(data)} bytes to {_rel(p)}"
