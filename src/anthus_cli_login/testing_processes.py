"""Real child processes for specs: lock contention, and concurrent renewal and logout.

``python -m anthus_cli_login.testing_processes <command> ...`` runs one child. ``FileStore`` is a test double
shared by those children; it writes JSON to a file and is never offered by ``open_store``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .errors import AuthError
from .locks import key_lock


class FileStore:
    """A store that several test processes share. Callers lock the key, as ``Session`` does."""

    def __init__(self, path):
        self.path = Path(path)

    def _read(self):
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}

    def get(self, key):
        return self._read().get(key)

    def set(self, key, value):
        data = self._read()
        data[key] = value
        self.path.write_text(json.dumps(data))

    def delete(self, key):
        data = self._read()
        data.pop(key, None)
        self.path.write_text(json.dumps(data))


def short_state_dir() -> str:
    """A state directory short enough for a Unix socket path (macOS temp paths are too long)."""
    import tempfile

    return tempfile.mkdtemp(prefix="acl-", dir="/tmp" if os.path.isdir("/tmp") else None)


def run_agent_thread(namespace: str, state_dir):
    """Run the real memory agent in a thread of this process; returns a function that stops it."""
    import threading

    from .stores import agent

    ready = threading.Event()
    thread = threading.Thread(
        target=agent.serve, args=(namespace,), kwargs={"state_dir": state_dir, "ready": ready}, daemon=True
    )
    thread.start()
    if not ready.wait(10):
        raise TimeoutError("agent did not start")

    def stop():
        agent.stop(namespace, state_dir=state_dir)
        thread.join(10)

    return stop


def spawn(*args) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", "anthus_cli_login.testing_processes", *map(str, args)])


def wait_for(path, timeout=30.0) -> None:
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise TimeoutError(str(path))
        time.sleep(0.01)


def _session(state_dir, store_file):
    from .session import Session
    from .testing import FakeProvider, make_target

    return Session(
        make_target(),
        store=FileStore(store_file),
        provider=FakeProvider(time.time),
        state_dir=state_dir,
        login_command="tool login",
    )


def main(argv) -> int:
    command, rest = argv[0], argv[1:]
    if command == "counter":  # state_dir key counter_file times
        state_dir, key, counter, times = rest
        for _ in range(int(times)):
            with key_lock(state_dir, key):
                value = int(Path(counter).read_text() or 0) if os.path.exists(counter) else 0
                time.sleep(0.002)  # widen the window in which an unlocked writer would lose an update
                Path(counter).write_text(str(value + 1))
        return 0
    if command == "hold":  # state_dir key ready_file release_file
        state_dir, key, ready, release = rest
        with key_lock(state_dir, key):
            Path(ready).write_text("held")
            wait_for(release, 60)
        return 0
    if command == "login":  # state_dir store_file
        from .testing import FakeProvider, make_target

        session = _session(*rest)
        target = make_target()
        session.store_token_set(
            FakeProvider(time.time).post(target.token_endpoint, {"grant_type": "authorization_code"})
        )
        return 0
    if command == "renew":
        try:
            _session(*rest).headers(make_target_endpoint())
            print("renewed")
        except AuthError as error:
            print("no-session" if "No session" in str(error) else "failed:" + str(error))
        return 0
    if command == "logout":
        _session(*rest).logout()
        print("logged-out")
        return 0
    return 2


def make_target_endpoint() -> str:
    from .testing import make_target

    return make_target().api_endpoint


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
