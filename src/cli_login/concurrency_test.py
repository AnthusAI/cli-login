"""Real processes renewing and signing out of one shared session, on every operating system."""

import subprocess
import sys

from .testing_processes import FileStore, spawn


def run(command, state, store_file):
    return subprocess.Popen(
        [sys.executable, "-m", "cli_login.testing_processes", command, str(state), str(store_file)],
        stdout=subprocess.PIPE,
        text=True,
    )


def test_concurrent_renewals_all_succeed_and_keep_the_session(tmp_path):
    store_file = tmp_path / "store.json"
    assert spawn("login", tmp_path / "s", store_file).wait(timeout=60) == 0
    children = [run("renew", tmp_path / "s", store_file) for _ in range(4)]
    assert [child.communicate(timeout=120)[0].strip() for child in children] == ["renewed"] * 4
    assert FileStore(store_file).get("key-1") is not None


def test_logout_racing_renewals_never_resurrects_the_session(tmp_path):
    for _ in range(3):
        store_file = tmp_path / "store.json"
        assert spawn("login", tmp_path / "s", store_file).wait(timeout=60) == 0
        children = [run("renew", tmp_path / "s", store_file) for _ in range(3)] + [
            run("logout", tmp_path / "s", store_file)
        ]
        outputs = [child.communicate(timeout=120)[0].strip() for child in children]
        assert set(outputs) <= {"renewed", "no-session", "logged-out"}, outputs
        assert FileStore(store_file).get("key-1") is None
