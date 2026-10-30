"""Secure session stores. Choosing one fails closed; there is no plaintext fallback."""

from __future__ import annotations

import sys

from ..errors import AuthError
from ..target import Target


def open_store(target: Target):
    """The secure store for this platform. Only macOS exists so far; other platforms fail closed."""
    if sys.platform == "darwin":
        from .macos import MacOSKeychainStore

        return MacOSKeychainStore(target.namespace)
    raise AuthError("No secure credential store is available on this platform yet; plaintext storage is never used.")
