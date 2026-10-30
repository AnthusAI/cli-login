import errno
import sys

import pytest

from .. import stores
from ..errors import AuthError
from ..testing import FakeCredentialManager, FakeKeyctl, FakeSecretStorage, make_target
from ..testing_processes import run_agent_thread, short_state_dir
from . import open_store
from .agent import AgentStore
from .kernel_keyring import KernelKeyringStore
from .macos import MacOSKeychain, MacOSKeychainStore
from .secret_service import SecretServiceStore
from .windows import WindowsCredentialStore


class Keychain(MacOSKeychain):
    def __init__(self):
        pass


@pytest.fixture
def machine(monkeypatch):
    """Fake backends for every store; returns knobs the specs turn."""
    knobs = {"secret": FakeSecretStorage(), "keyring": FakeKeyctl()}
    patched = {
        "keychain": (lambda t, s, e: MacOSKeychainStore(t.namespace, Keychain()), "darwin"),
        "secret-service": (lambda t, s, e: SecretServiceStore(t.namespace, module=knobs["secret"]), "linux"),
        "kernel-keyring": (lambda t, s, e: KernelKeyringStore(t.namespace, backend=knobs["keyring"]), "linux"),
        "agent": (lambda t, s, e: AgentStore(t.namespace, state_dir=s, environ={}), ("linux", "darwin")),
        "credential-manager": (lambda t, s, e: WindowsCredentialStore(t.namespace, backend=FakeCredentialManager()), "win32"),
    }
    monkeypatch.setattr(stores, "BACKENDS", patched)
    return knobs


def choose(platform="linux", **kwargs):
    return open_store(make_target(), platform=platform, environ=kwargs.pop("environ", {}), **kwargs)


def test_each_platform_gets_its_default(machine):
    assert isinstance(choose("darwin"), MacOSKeychainStore)
    assert choose("win32").name == "Windows Credential Manager"
    assert choose("linux").name == "Secret Service"


unix = pytest.mark.skipif(sys.platform == "win32", reason="the memory agent needs Unix sockets")


@unix
def test_linux_moves_down_the_order(machine):
    machine["secret"].locked = True
    assert choose().name == "kernel keyring"
    machine["keyring"].blocked = errno.EPERM
    state = short_state_dir()
    stop = run_agent_thread("example-product", state)
    try:
        assert choose(state_dir=state).name == "memory agent"
    finally:
        stop()


@unix
def test_nothing_usable_names_the_exact_recovery_steps(machine, tmp_path):
    machine["secret"].no_bus = True
    machine["keyring"].blocked = errno.ENOSYS
    with pytest.raises(AuthError) as caught:
        choose(state_dir=tmp_path / "s")
    message = str(caught.value)
    assert "agent serve --namespace example-product" in message
    assert "cli-login[linux]" in message
    assert "secret-service:" in message and "kernel-keyring:" in message and "agent:" in message
    assert "plaintext storage is never used" in message.lower()


def test_the_environment_variable_chooses_a_store(machine):
    assert choose(environ={"CLI_LOGIN_STORE": "kernel-keyring"}).name == "kernel keyring"
    assert choose(backend="kernel-keyring", environ={"CLI_LOGIN_STORE": "secret-service"}).name == "kernel keyring"


@pytest.mark.parametrize("name", ["file", "plaintext", "keyring", "json", "../x"])
def test_plaintext_can_never_be_chosen(machine, name):
    with pytest.raises(AuthError, match="never used"):
        choose(backend=name)


def test_an_explicit_choice_does_not_fall_back(machine):
    machine["secret"].locked = True
    with pytest.raises(AuthError, match="unlock"):
        choose(backend="secret-service")


def test_a_store_from_another_platform_is_refused(machine):
    with pytest.raises(AuthError, match="not available on this platform"):
        choose(backend="credential-manager")


def test_an_unknown_platform_fails_closed(machine):
    with pytest.raises(AuthError, match="plaintext"):
        choose("plan9")


def test_importing_the_package_loads_no_store_backend():
    import subprocess
    import sys

    code = "import sys, cli_login, cli_login.stores; print(sorted(m for m in sys.modules if m.startswith('cli_login.stores.') or m == 'secretstorage'))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "[]"
