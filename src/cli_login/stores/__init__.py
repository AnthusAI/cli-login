"""Secure session stores. Choosing one fails closed; there is no plaintext fallback.

Order of choice:
- macOS: the Keychain.
- Linux: Secret Service, then the kernel keyring, then a running memory agent.
- Windows: Credential Manager.

Set ``CLI_LOGIN_STORE`` (or pass ``backend=``) to one of ``keychain``, ``secret-service``,
``kernel-keyring``, ``agent`` or ``credential-manager`` to choose explicitly. Any other value, a file or
plaintext included, is refused. Backends load lazily so importing the package needs no optional dependency.
"""

from __future__ import annotations

import os
import sys

from ..errors import AuthError, StoreUnavailable
from ..target import Target

ENV_STORE = "CLI_LOGIN_STORE"


def _keychain(target, state_dir, environ):
    from .macos import MacOSKeychainStore

    return MacOSKeychainStore(target.namespace)


def _secret_service(target, state_dir, environ):
    from .secret_service import SecretServiceStore

    return SecretServiceStore(target.namespace)


def _kernel_keyring(target, state_dir, environ):
    from .kernel_keyring import KernelKeyringStore

    return KernelKeyringStore(target.namespace)


def _agent(target, state_dir, environ):
    from .agent import AgentStore

    return AgentStore(target.namespace, state_dir=state_dir, environ=environ)


def _credential_manager(target, state_dir, environ):
    from .windows import WindowsCredentialStore

    return WindowsCredentialStore(target.namespace)


# name -> (factory, platform prefix). Tests may replace entries.
BACKENDS = {
    "keychain": (_keychain, "darwin"),
    "secret-service": (_secret_service, "linux"),
    "kernel-keyring": (_kernel_keyring, "linux"),
    "agent": (_agent, ("linux", "darwin")),
    "credential-manager": (_credential_manager, "win32"),
}
DEFAULT_ORDER = {
    "darwin": ["keychain"],
    "linux": ["secret-service", "kernel-keyring", "agent"],
    "win32": ["credential-manager"],
}


def _supported(name: str, platform: str) -> bool:
    return platform.startswith(BACKENDS[name][1])


def _try(name, target, state_dir, environ):
    store = BACKENDS[name][0](target, state_dir, environ)
    if hasattr(store, "probe"):
        store.probe()
    return store


def _guidance(target: Target, reasons: list[tuple[str, str]], state_dir) -> AuthError:
    from .agent import agent_command

    lines = ["No secure credential store is available on this machine."]
    lines += [f"- {name}: {reason}" for name, reason in reasons]
    lines.append(
        f"On a cloud machine, start the memory agent: {agent_command(target.namespace, state_dir=state_dir)} "
        "then sign in again. Elsewhere, install the Linux extra "
        '(pip install "cli-login[linux]") and unlock your desktop keyring. '
        "Plaintext storage is never used."
    )
    return AuthError("\n".join(lines))


def open_store(target: Target, *, backend: str | None = None, state_dir=None, environ=None, platform: str | None = None):
    """The secure store for this machine, or an AuthError that says exactly what to do."""
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    chosen = backend or environ.get(ENV_STORE) or None
    if chosen:
        if chosen not in BACKENDS:
            raise AuthError(
                f"Unknown credential store {chosen!r}; choose one of {', '.join(BACKENDS)}. "
                "Plaintext storage is never used."
            )
        if not _supported(chosen, platform):
            raise AuthError(f"The {chosen} store is not available on this platform.")
        try:
            return _try(chosen, target, state_dir, environ)
        except StoreUnavailable as error:
            raise AuthError(str(error)) from None
    order = next((names for prefix, names in DEFAULT_ORDER.items() if platform.startswith(prefix)), None)
    if order is None:
        raise AuthError("No secure credential store is available on this platform; plaintext storage is never used.")
    reasons = []
    for name in order:
        try:
            return _try(name, target, state_dir, environ)
        except StoreUnavailable as error:
            reasons.append((name, str(error)))
    if platform.startswith("linux"):
        raise _guidance(target, reasons, state_dir)
    raise AuthError("\n".join(["No secure credential store is available."] + [f"- {n}: {r}" for n, r in reasons]))
