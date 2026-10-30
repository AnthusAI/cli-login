import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path
from unittest import mock

from behave import given, then, when

from cli_login.errors import AuthError, StoreUnavailable
from cli_login.stores import agent
from cli_login.stores.agent import AgentStore
from cli_login.testing_processes import run_agent_thread, short_state_dir

NS = "example-product"


def state(context):
    context.state_dir = short_state_dir()
    context.add_cleanup(shutil.rmtree, context.state_dir, True)
    context.make_store = lambda namespace: AgentStore(namespace, state_dir=context.state_dir, environ={})
    context.store = context.make_store(NS)


@given('a running memory agent for the namespace "{namespace}"')
def running(context, namespace):
    state(context)
    context.add_cleanup(run_agent_thread(namespace, context.state_dir))
    context.sock = os.path.join(context.state_dir, "agent", "agent.sock")


@given("no memory agent is running")
def none_running(context):
    state(context)


@given("an empty private state directory")
def empty(context):
    state(context)
    context.add_cleanup(
        lambda: subprocess.run(cli(context, "stop"), capture_output=True, timeout=30, check=False)
    )


@given("a stale socket left by a crashed agent")
def stale(context):
    state(context)
    directory = os.path.join(context.state_dir, "agent")
    os.makedirs(directory, mode=0o700)
    leftover = socket.socket(socket.AF_UNIX)
    leftover.bind(os.path.join(directory, "agent.sock"))
    leftover.close()  # the file stays behind, nothing listens


def cli(context, *args):
    return [sys.executable, "-m", "cli_login.stores.agent", args[0], "--namespace", NS,
            "--state-dir", context.state_dir, *args[1:]]


@when('the session "{value}" is saved under the key "{key}" through the agent')
def save(context, value, key):
    context.store.set(key, value)


@when('the key "{key}" is deleted through the agent')
def delete(context, key):
    context.store.delete(key)


@when("the agent is stopped")
def stop(context):
    assert agent.stop(NS, state_dir=context.state_dir)


@when('an agent is started for the namespace "{namespace}"')
def start(context, namespace):
    context.add_cleanup(run_agent_thread(namespace, context.state_dir))


@when("a client sends garbage and an oversized length")
def garbage(context):
    for payload in (struct.pack(">I", 0xFFFFFFFF), struct.pack(">I", 5) + b"notjs", b"\x00"):
        client = socket.socket(socket.AF_UNIX)
        client.connect(context.sock)
        client.sendall(payload)
        client.close()


@when('the agent command "{command}" is run')
def run_command(context, command):
    done = subprocess.run(cli(context, *command.split()), capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr


@then('reading "{key}" through the agent returns "{value}"')
def returns(context, key, value):
    assert context.store.get(key) == value


@then('reading "{key}" through the agent returns nothing')
def returns_nothing(context, key):
    assert context.store.get(key) is None


@then("the agent socket has mode 0600 inside a directory with mode 0700")
def modes(context):
    assert stat.S_IMODE(os.stat(context.sock).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(context.sock)).st_mode) == 0o700


@then('no file under the state directory contains "{text}"')
def no_file(context, text):
    for root, _, names in os.walk(context.state_dir):
        for name in names:
            path = os.path.join(root, name)
            if os.path.isfile(path):
                assert text.encode() not in Path(path).read_bytes()


@then("the agent is not running")
def not_running(context):
    assert agent.status(NS, state_dir=context.state_dir) is None


@then("its socket is gone")
def socket_gone(context):
    assert not os.path.lexists(context.sock)


@then('reading through the agent fails with guidance mentioning "{text}"')
def read_fails(context, text):
    try:
        context.store.get("key-1")
    except StoreUnavailable as error:
        assert text in str(error)
    else:
        raise AssertionError("expected failure")


@then('a client for the namespace "{namespace}" at the same socket is unavailable')
def other_product(context, namespace):
    try:
        context.make_store(namespace).probe()
    except StoreUnavailable as error:
        assert "different product" in str(error)
    else:
        raise AssertionError("expected refusal")


@then('a client store is unavailable with guidance mentioning "{text}"')
def client_unavailable(context, text):
    try:
        context.store.probe()
    except StoreUnavailable as error:
        assert text in str(error)
    else:
        raise AssertionError("expected unavailable")


@then('starting another agent for the namespace "{namespace}" fails')
def second(context, namespace):
    try:
        agent.serve(namespace, state_dir=context.state_dir)
    except AuthError as error:
        assert "already running" in str(error)
    else:
        raise AssertionError("expected refusal")


@then("the agent still answers a ping")
@then("the agent answers a ping")
def pings(context):
    assert agent.status(NS, state_dir=context.state_dir)["namespace"] == NS


@then('saving under the key "{key}" through the agent fails')
def bad_key(context, key):
    try:
        context.store.set(key, "v")
    except AuthError:
        pass
    else:
        raise AssertionError("expected refusal")


def command_output(context, command):
    return subprocess.run(cli(context, command), capture_output=True, text=True, timeout=60, check=False)


@then('the agent command "{command}" reports it running')
def reports_running(context, command):
    done = command_output(context, command)
    assert done.returncode == 0 and "running" in done.stdout and "not running" not in done.stdout


@then('the agent command "{command}" reports it not running')
def reports_not_running(context, command):
    done = command_output(context, command)
    assert done.returncode == 1 and "not running" in done.stdout


@then('the agent command "{command}" reports it stopped')
def reports_stopped(context, command):
    done = command_output(context, command)
    assert done.returncode == 0 and "stopped" in done.stdout


@then("starting the agent fails saying Windows is not supported")
def windows(context):
    with mock.patch("sys.platform", "win32"):
        try:
            agent.serve(NS, state_dir="/nonexistent")
        except AuthError as error:
            assert "Windows" in str(error)
        else:
            raise AssertionError("expected refusal")


