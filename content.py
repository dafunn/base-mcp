"""How bytes are presented to the caller: shared by fs_ops and net so both
decide the same way whether a payload is text."""

from __future__ import annotations


def is_binary(chunk: bytes) -> bool:
    """A NUL byte is the marker."""
    return b"\x00" in chunk
