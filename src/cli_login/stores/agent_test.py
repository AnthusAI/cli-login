import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from ..errors import AuthError, StoreUnavailable
from ..testing_processes import run_agent_thread, short_state_dir
from . import agent
from .agent import AgentClient, AgentStore, MemoryAgent

unix = pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets")


@pytest.fixture
def state():
    path = short_state_dir()
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def running(state):
    stop = run_agent_thread("ns", state)
    yield state
    stop()


def store(state, namespace="ns"):
    return AgentStore(namespace, state_dir=state, environ={})


def test_the_state_machine_without_a_socket():
    memory = MemoryAgent("ns")
    assert memory.handle({"op": "set", "key": "k", "value": "v"}) == {"ok": True}
    assert memory.handle({"op": "get", "key": "k"}) == {"ok": True, "value": "v"}
    assert memory.handle({"op": "delete", "key": "k"}) == {"ok": True}
    assert memory.handle({"op": "get", "key": "k"})["value"] is None
    assert memory.handle({"op": "ping"})["namespace"] == "ns"
    assert memory.handle({"op": "get", "key": "../x"})["ok"] is False
    assert memory.handle({"op": "set", "key": "k", "value": 5})["ok"] is False
    assert memory.handle({"op": "nope"})["error"] == "unknown_operation"
    assert not memory.stopping.is_set()
    memory.handle({"op": "stop"})
    assert memory.stopping.is_set()


@unix
def test_round_trip_over_a_real_socket(running):
    client = store(running)
    client.set("k", "one")
    client.set("k", "two")
    assert client.get("k") == "two"
    assert client.get("absent") is None
    client.delete("k")
    assert client.get("k") is None


@unix
def test_the_socket_is_private_and_nothing_secret_touches_disk(running):
    store(running).set("k", "secret-value")
    sock = os.path.join(running, "agent", "agent.sock")
    assert stat.S_IMODE(os.stat(sock).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(sock)).st_mode) == 0o700
    for root, _, names in os.walk(running):
        for name in names:
            full = os.path.join(root, name)
            if os.path.isfile(full):
                assert b"secret-value" not in Path(full).read_bytes()


@unix
def test_stop_forgets_everything_and_removes_the_socket(state):
    stop = run_agent_thread("ns", state)
    store(state).set("k", "v")
    assert agent.stop("ns", state_dir=state) is True
    stop()
    assert not os.path.lexists(os.path.join(state, "agent", "agent.sock"))
    with pytest.raises(StoreUnavailable, match="agent serve"):
        store(state).get("k")
    assert agent.stop("ns", state_dir=state) is False
    assert agent.status("ns", state_dir=state) is None


@unix
def test_a_second_agent_for_the_same_product_is_refused(running):
    with pytest.raises(AuthError, match="already running"):
        agent.serve("ns", state_dir=running)


@unix
def test_another_products_client_is_refused(running):
    with pytest.raises(StoreUnavailable, match="different product"):
        store(running, "other").probe()


@unix
def test_the_environment_override_names_the_socket(state, monkeypatch):
    path = os.path.join(state, "private", "a.sock")
    monkeypatch.setenv(agent.ENV_SOCKET, path)
    stop = run_agent_thread("ns", state)  # serve() reads the same override through socket_path_for
    try:
        assert os.path.exists(path) and not os.path.exists(os.path.join(state, "agent"))
        client = AgentStore("ns")
        client.set("k", "v")
        assert client.get("k") == "v"
    finally:
        stop()


@unix
def test_a_stale_socket_is_replaced(state):
    os.makedirs(os.path.join(state, "agent"), mode=0o700)
    leftover = socket.socket(socket.AF_UNIX)
    leftover.bind(os.path.join(state, "agent", "agent.sock"))
    leftover.close()
    stop = run_agent_thread("ns", state)
    try:
        assert agent.status("ns", state_dir=state)["namespace"] == "ns"
    finally:
        stop()


@unix
def test_garbage_does_not_harm_the_agent(running):
    path = os.path.join(running, "agent", "agent.sock")
    for payload in (struct.pack(">I", 0xFFFFFFFF), struct.pack(">I", 5) + b"notjs", b"\x00", b"", struct.pack(">I", 2) + b"[]"):
        client = socket.socket(socket.AF_UNIX)
        client.connect(path)
        client.sendall(payload)
        client.close()
    assert agent.status("ns", state_dir=running) is not None


@unix
def test_a_loose_directory_or_a_symlink_is_refused(state):
    directory = os.path.join(state, "agent")
    os.makedirs(directory, mode=0o755)
    os.chmod(directory, 0o755)
    with pytest.raises(AuthError, match="0700"):
        agent.serve("ns", state_dir=state)
    with pytest.raises(StoreUnavailable, match="0700"):
        store(state).probe()
    os.chmod(directory, 0o700)
    os.rename(directory, directory + "-real")
    os.symlink(directory + "-real", directory)
    with pytest.raises(AuthError, match="symlink"):
        agent.serve("ns", state_dir=state)


@unix
def test_a_socket_path_that_is_too_long_is_refused(tmp_path):
    with pytest.raises(AuthError, match="too long"):
        agent.serve("ns", state_dir=tmp_path / ("x" * 120))


@unix
def test_a_foreign_user_gets_no_answer(running, monkeypatch):
    monkeypatch.setattr(agent, "peer_uid", lambda sock: os.geteuid() + 1)
    with pytest.raises(StoreUnavailable):
        store(running).get("k")


@unix
def test_the_peer_uid_is_ours_on_a_real_socket_pair():
    a, b = socket.socketpair(socket.AF_UNIX)
    try:
        assert agent.peer_uid(a) == os.geteuid()
    finally:
        a.close()
        b.close()


@unix
def test_keys_must_be_safe(running):
    with pytest.raises(AuthError):
        store(running).set("../x", "v")


@unix
def test_the_command_line_serves_in_the_background_reports_and_stops(state):
    base = [sys.executable, "-m", "cli_login.stores.agent"]
    common = ["--namespace", "ns", "--state-dir", state]

    def run(action, *extra):
        return subprocess.run([*base, action, *common, *extra], capture_output=True, text=True, timeout=60, check=False)

    try:
        assert run("status").returncode == 1
        assert run("serve", "--background").returncode == 0
        store(state).set("k", "v")
        done = run("status")
        assert done.returncode == 0 and "1 stored" in done.stdout and "v" not in done.stdout.replace("running", "")
        assert run("serve", "--background").returncode == 0  # already running: still fine
    finally:
        done = run("stop")
    assert "stopped" in done.stdout
    assert run("status").returncode == 1


def test_windows_is_not_supported(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(AuthError, match="Windows"):
        agent.serve("ns", state_dir=tmp_path)
    with pytest.raises(AuthError, match="Windows"):
        AgentClient(tmp_path / "x", "ns")
