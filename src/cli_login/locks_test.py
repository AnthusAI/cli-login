import os
import sys
import time

import pytest

from .errors import AuthError
from .locks import ensure_state_dir, key_lock
from .testing_processes import spawn, wait_for


def test_the_lock_is_taken_and_released_per_key(tmp_path):
    with key_lock(tmp_path / "s", "a"), key_lock(tmp_path / "s", "b"):  # a different key does not block
        pass
    assert (tmp_path / "s" / "session-a.lock").exists()
    if sys.platform != "win32":
        assert oct((tmp_path / "s" / "session-a.lock").stat().st_mode & 0o777) == "0o600"


def test_the_lock_can_be_retaken_after_release(tmp_path):
    for _ in range(3):
        with key_lock(tmp_path, "a"):
            pass


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


def test_a_symlinked_lock_file_is_refused(tmp_path):
    if sys.platform == "win32":
        pytest.skip("symlinks need privileges")
    (tmp_path / "target").write_text("")
    (tmp_path / "session-a.lock").symlink_to(tmp_path / "target")
    with pytest.raises(AuthError), key_lock(tmp_path, "a"):
        pass


def test_real_processes_on_the_same_key_take_turns(tmp_path):
    counter = tmp_path / "counter"
    children = [spawn("counter", tmp_path / "s", "key-1", counter, 5) for _ in range(4)]
    assert [child.wait(timeout=120) for child in children] == [0, 0, 0, 0]
    assert counter.read_text() == "20"


def test_a_real_process_holding_one_key_does_not_block_another(tmp_path):
    state, ready, release = tmp_path / "s", tmp_path / "ready", tmp_path / "release"
    holder = spawn("hold", state, "key-1", ready, release)
    try:
        wait_for(ready)
        started = time.monotonic()
        with key_lock(state, "key-2"):
            pass
        assert time.monotonic() - started < 5
    finally:
        release.write_text("go")
        assert holder.wait(timeout=60) == 0


def test_a_real_process_holding_the_key_blocks_until_it_releases(tmp_path):
    state, ready, release = tmp_path / "s", tmp_path / "ready", tmp_path / "release"
    holder = spawn("hold", state, "key-1", ready, release)
    waiter = None
    try:
        wait_for(ready)
        done = tmp_path / "done"
        waiter = spawn("counter", state, "key-1", done, 1)
        time.sleep(0.5)
        assert waiter.poll() is None and not os.path.exists(done)  # still waiting for the holder
    finally:
        release.write_text("go")
        assert holder.wait(timeout=60) == 0
    assert waiter.wait(timeout=60) == 0
    assert done.read_text() == "1"
