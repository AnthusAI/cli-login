"""Per-key process locks. POSIX only for now; Windows arrives with its own story."""

from __future__ import annotations

import os
import re
from contextlib import contextmanager
from pathlib import Path

from .errors import AuthError

_SAFE = re.compile(r"[A-Za-z0-9._-]{1,200}")


def default_state_dir(namespace: str) -> Path:
    return Path.home() / ".config" / "anthus-cli-login" / namespace


def ensure_state_dir(path: Path) -> Path:
    """Create the private (0700) metadata directory, refusing a symlink."""
    path = Path(path)
    if path.is_symlink():
        raise AuthError("CLI session metadata directory must not be a symlink.")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError:
        raise AuthError("Unable to access private CLI session metadata; check directory permissions.") from None
    return path


@contextmanager
def key_lock(state_dir: Path, key: str):
    """Hold an exclusive lock for one stored key, never a global lock."""
    try:
        import fcntl
    except ImportError:
        raise AuthError(
            "Process-safe session locking is currently supported on macOS and Linux; Windows support is not available yet."
        ) from None
    if not _SAFE.fullmatch(key or ""):
        raise AuthError("Invalid lock key.")
    path = ensure_state_dir(state_dir) / ("session-" + key + ".lock")
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        raise AuthError("Unable to open the private CLI session lock; check directory permissions.") from None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            raise AuthError(
                "Unable to lock the CLI session safely; retry after checking directory permissions."
            ) from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
