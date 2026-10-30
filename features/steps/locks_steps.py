import os
import shutil
import tempfile
import time
from pathlib import Path

from behave import given, then, when

from anthus_cli_login.errors import AuthError
from anthus_cli_login.locks import key_lock
from anthus_cli_login.testing_processes import FileStore, spawn, wait_for


@given("a private state directory")
def private(context):
    context.dir = tempfile.mkdtemp()
    context.add_cleanup(shutil.rmtree, context.dir, True)
    context.state = os.path.join(context.dir, "state")
    context.children = []


def finish_children(context):
    for child in context.children:
        child.wait(timeout=60)


@given('a real process holds the lock for key "{key}"')
def holder(context, key):
    context.ready, context.release = os.path.join(context.dir, "ready"), os.path.join(context.dir, "release")
    context.holder = spawn("hold", context.state, key, context.ready, context.release)

    def cleanup():
        Path(context.release).write_text("go")
        context.holder.wait(timeout=60)

    context.add_cleanup(cleanup)
    wait_for(context.ready)


@when('{count:d} real processes each add 1 to a shared counter {times:d} times while holding the lock for key "{key}"')
def counters(context, count, times, key):
    context.counter = os.path.join(context.dir, "counter")
    children = [spawn("counter", context.state, key, context.counter, times) for _ in range(count)]
    assert [child.wait(timeout=120) for child in children] == [0] * count


@then("the counter reads {value:d}")
def counter(context, value):
    assert int(Path(context.counter).read_text()) == value


@when('this process takes the lock for key "{key}"')
def take(context, key):
    started = time.monotonic()
    with key_lock(context.state, key):
        context.waited = time.monotonic() - started


@then("it is granted at once")
def at_once(context):
    assert context.waited < 5


@when('the holder releases the lock for key "{key}"')
def release(context, key):
    Path(context.release).write_text("go")
    assert context.holder.wait(timeout=60) == 0


@then('this process can take the lock for key "{key}"')
def can_take(context, key):
    with key_lock(context.state, key):
        pass


@when('a lock is requested for the key "{key}"')
def request(context, key):
    context.error = None
    try:
        with key_lock(context.state, key):
            pass
    except AuthError as error:
        context.error = error


@given('the lock file for key "{key}" is a symlink')
def symlinked(context, key):
    os.makedirs(context.state, exist_ok=True)
    target = os.path.join(context.dir, "elsewhere")
    Path(target).write_text("")
    try:
        os.symlink(target, os.path.join(context.state, f"session-{key}.lock"))
    except OSError:
        context.scenario.skip("symlinks need privileges")


@then("it is refused with an error")
def refused(context):
    if context.scenario.status == "skipped":
        return
    assert isinstance(context.error, AuthError)


@given("a shared session store used by real processes")
def shared(context):
    private(context)
    context.store_file = os.path.join(context.dir, "store.json")
    context.store = FileStore(context.store_file)


@given("a real process has signed the person in")
def signed_in(context):
    assert spawn("login", context.state, context.store_file).wait(timeout=60) == 0


@when("{renewals:d} real processes renew the session while 1 real process signs out")
def race(context, renewals):
    import subprocess
    import sys

    def run(command):
        return subprocess.Popen(
            [sys.executable, "-m", "anthus_cli_login.testing_processes", command, context.state, context.store_file],
            stdout=subprocess.PIPE,
            text=True,
        )

    children = [run("renew") for _ in range(renewals)] + [run("logout")]
    context.outputs = [child.communicate(timeout=120)[0].strip() for child in children]


@then("every renewal either succeeded or reported that no session exists")
def renewals(context):
    assert all(out in ("renewed", "no-session", "logged-out") for out in context.outputs), context.outputs


@then("the shared store ends with no session")
def ends_empty(context):
    assert context.store.get("key-1") is None
