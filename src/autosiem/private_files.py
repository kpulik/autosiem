"""Owner-only files for secrets and telemetry (SEC-016).

The users file holds token verifiers; the database, archive journal and durable
queue hold raw events. Created under a typical 022 umask they came out 0644,
readable by every local account. Everything here opens files with mode 0600,
which a umask can only narrow.
"""

from __future__ import annotations

import os
from pathlib import Path

PRIVATE_MODE = 0o600


def create_private(path: str | Path) -> None:
    """Create ``path`` empty and owner-only if it does not exist yet.

    An existing file is left alone: an operator who chose a mode for it, for
    example a group-readable database, keeps that choice.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_MODE)
    except FileExistsError:
        return
    os.close(fd)


def write_private_text(path: str | Path, text: str) -> None:
    """Atomically replace ``path`` with ``text`` as an owner-only file.

    The rename gives the result a fresh inode, so a previously world-readable
    file comes out 0600 too.
    """
    target = Path(path)
    tmp = target.with_name(target.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        if hasattr(os, "fchmod"):
            # A temp file left by a crashed write keeps its old mode on O_CREAT.
            os.fchmod(handle.fileno(), PRIVATE_MODE)
        handle.write(text)
    os.replace(tmp, target)
