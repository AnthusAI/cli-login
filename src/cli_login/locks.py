"""Per-key process locks, on POSIX (``flock``) and on Windows (``msvcrt.locking``).

One lock file per stored key, ``session-<key>.lock`` in the private state directory. There is no global lock:
different keys never block each other.
"""

from __future__ import annotations

import errno
import os
import re
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from .errors import AuthError

_SAFE = re.compile(r"[A-Za-z0-9._-]{1,200}")


def default_state_dir(namespace: str) -> Path:
    return Path.home() / ".config" / "cli-login" / namespace


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


def _lock_posix(fd: int) -> None:
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_EX)


def _unlock_posix(fd: int) -> None:
    import fcntl

    fcntl.flock(fd, fcntl.LOCK_UN)


def _lock_windows(fd: int) -> None:
    """Lock byte 0 of the file, waiting without a deadline.

    ``LK_LOCK`` gives up after ten seconds, so poll the non-blocking form with a short, growing sleep.
    """
    import msvcrt

    delay = 0.005
    while True:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EDEADLK):
                raise
        time.sleep(delay)
        delay = min(delay * 2, 0.1)


def _unlock_windows(fd: int) -> None:
    import msvcrt

    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


if sys.platform == "win32":
    _lock, _unlock = _lock_windows, _unlock_windows
else:
    _lock, _unlock = _lock_posix, _unlock_posix


@contextmanager
def key_lock(state_dir: Path, key: str):
    """Hold an exclusive lock for one stored key, never a global lock."""
    if not _SAFE.fullmatch(key or ""):
        raise AuthError("Invalid lock key.")
    path = ensure_state_dir(state_dir) / ("session-" + key + ".lock")
    if path.is_symlink():
        raise AuthError("The CLI session lock must not be a symlink.")
    try:
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        raise AuthError("Unable to open the private CLI session lock; check directory permissions.") from None
    try:
        try:
            _lock(fd)
        except OSError:
            raise AuthError(
                "Unable to lock the CLI session safely; retry after checking directory permissions."
            ) from None
        try:
            yield
        finally:
            try:
                _unlock(fd)
            except OSError:
                pass  # closing the descriptor releases the lock
    finally:
        os.close(fd)
