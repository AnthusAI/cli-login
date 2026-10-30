import sys

import pytest

from .errors import AuthError
from .locks import ensure_state_dir, key_lock

posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX locks")


@posix
def test_the_lock_is_taken_and_released_per_key(tmp_path):
    with key_lock(tmp_path / "s", "a"), key_lock(tmp_path / "s", "b"):  # a different key does not block
        pass
    assert (tmp_path / "s" / "session-a.lock").exists()
    assert oct((tmp_path / "s" / "session-a.lock").stat().st_mode & 0o777) == "0o600"


@posix
def test_an_unsafe_key_is_refused(tmp_path):
    with pytest.raises(AuthError), key_lock(tmp_path, "../x"):
        pass


def test_a_symlinked_state_directory_is_refused(tmp_path):
    if sys.platform == "win32":
        pytest.skip("symlinks need privileges")
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with pytest.raises(AuthError):
        ensure_state_dir(tmp_path / "link")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_windows_fails_with_a_clear_message(tmp_path):
    with pytest.raises(AuthError, match="Windows"), key_lock(tmp_path, "a"):
        pass
