"""Environment configuration shared by fs_ops and net: the env parsers, the
write gate, and the audit switch.

Everything is read once, at import. A test that changes the environment has to
re-import to see it, and must reload this module before the ones that read from
it; `tests/conftest.py` owns that order.
"""

from __future__ import annotations

import logging
import os
import sys


def flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def csv_env(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(v.strip() for v in os.getenv(name, default).split(",") if v.strip())


# The single write gate: one answer to "may this server change anything",
# covering file writes and HTTP methods other than GET/HEAD.
EXPOSE_WRITE = flag("EXPOSE_WRITE", False)

# Read it as `config.EXPOSE_WRITE`, never `from config import EXPOSE_WRITE`, so
# patching `config` changes it for every module.

AUDIT_LOG = flag("AUDIT_LOG", True)

logging.basicConfig(stream=sys.stderr, level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
log = logging.getLogger("base-mcp")
