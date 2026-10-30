import shutil
from unittest import mock

from behave import given, then, when

from cli_login import stores
from cli_login.errors import AuthError
from cli_login.stores.agent import AgentStore
from cli_login.stores.kernel_keyring import KernelKeyringStore
from cli_login.stores.macos import MacOSKeychain, MacOSKeychainStore
from cli_login.stores.secret_service import SecretServiceStore
from cli_login.stores.windows import WindowsCredentialStore
from cli_login.testing import FakeCredentialManager, FakeKeyctl, FakeSecretStorage, make_target
from cli_login.testing_processes import run_agent_thread, short_state_dir


class Keychain(MacOSKeychain):
    def __init__(self):
        pass


def setup(context, platform, *, secret=None, keyring=None, agent_running=False):
    context.platform = platform
    context.state_dir = short_state_dir()
    context.add_cleanup(shutil.rmtree, context.state_dir, True)
    if agent_running:
        context.add_cleanup(run_agent_thread("example-product", context.state_dir))
    patched = {
        "keychain": (lambda t, s, e: MacOSKeychainStore(t.namespace, Keychain()), "darwin"),
        "secret-service": (lambda t, s, e: SecretServiceStore(t.namespace, module=secret or FakeSecretStorage()), "linux"),
        "kernel-keyring": (lambda t, s, e: KernelKeyringStore(t.namespace, backend=keyring or FakeKeyctl()), "linux"),
        "agent": (lambda t, s, e: AgentStore(t.namespace, state_dir=s, environ={}), ("linux", "darwin")),
        "credential-manager": (lambda t, s, e: WindowsCredentialStore(t.namespace, backend=FakeCredentialManager()), "win32"),
    }
    patcher = mock.patch.dict(stores.BACKENDS, patched)
    patcher.start()
    context.add_cleanup(patcher.stop)


@given("a macOS machine")
def mac(context):
    setup(context, "darwin")


@given("a Windows machine")
def windows(context):
    setup(context, "win32")


@given("a Linux machine where every store works")
def linux_all(context):
    setup(context, "linux")


@given("a Linux machine whose Secret Service is locked and whose kernel keyring works")
def linux_locked(context):
    setup(context, "linux", secret=FakeSecretStorage(locked=True))


@given("a Linux machine whose Secret Service is absent, whose kernel keyring is blocked, and whose memory agent runs")
def linux_container(context):
    import errno

    setup(context, "linux", secret=FakeSecretStorage(no_bus=True), keyring=FakeKeyctl(blocked=errno.EPERM), agent_running=True)


@given("a Linux machine where no store is usable")
def linux_none(context):
    import errno

    setup(context, "linux", secret=FakeSecretStorage(no_bus=True), keyring=FakeKeyctl(blocked=errno.ENOSYS))


def attempt(context, backend):
    context.error, context.store = None, None
    try:
        context.store = stores.open_store(
            make_target(), backend=backend, platform=context.platform, state_dir=context.state_dir, environ={}
        )
    except AuthError as error:
        context.error = error


@when("a store is opened for the target")
def opened(context):
    attempt(context, None)


@when('a store is opened for the target choosing "{choice}"')
def opened_choosing(context, choice):
    attempt(context, choice)


@then('it is the Keychain store for the namespace "{namespace}"')
def keychain(context, namespace):
    assert isinstance(context.store, MacOSKeychainStore) and context.store.namespace == namespace


@then('the chosen store is "{name}"')
def chosen(context, name):
    assert context.error is None, context.error
    assert context.store.name == name, context.store.name


@then('it fails with guidance naming "{one}", "{two}" and each store\'s reason')
def guidance(context, one, two):
    message = str(context.error)
    for text in (one, two, "secret-service:", "kernel-keyring:", "agent:"):
        assert text in message, message


@then("the guidance says plaintext storage is never used")
@then("it fails saying plaintext storage is never used")
def never_plaintext(context):
    assert isinstance(context.error, AuthError) and "never used" in str(context.error)


@then('it fails with guidance mentioning "{text}"')
def fails_mentioning(context, text):
    assert text in str(context.error), context.error


@then("it fails saying the store is not available on this platform")
def wrong_platform(context):
    assert "not available on this platform" in str(context.error)
