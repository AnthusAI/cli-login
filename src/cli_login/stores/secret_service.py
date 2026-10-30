"""Linux Secret Service (D-Bus), through the optional ``secretstorage`` package.

Install it with ``pip install "cli-login[linux]"``. Items are labelled and attributed by namespace and
key. The module never asks for an unlock prompt: a locked or absent keyring is reported as unavailable so that
selection moves on, and the message says how to recover.
"""

from __future__ import annotations

import contextlib

from ..errors import AuthError, StoreUnavailable

APPLICATION = "cli-login"

INSTALL = 'Install the Linux extra: pip install "cli-login[linux]".'
NO_BUS = (
    "No Secret Service is reachable (no D-Bus session or no keyring daemon such as gnome-keyring or "
    "KeePassXC); on a cloud machine use the memory agent."
)
LOCKED = "The Secret Service keyring is locked; unlock it (log in to the desktop session) and retry."


def _load():
    try:
        import secretstorage
    except ImportError:
        raise StoreUnavailable(INSTALL) from None
    return secretstorage


class SecretServiceStore:
    name = "Secret Service"

    def __init__(self, namespace: str, *, module=None):
        if not namespace:
            raise AuthError("A store namespace is required.")
        self.namespace = namespace
        self.module = module if module is not None else _load()

    def _attributes(self, key: str) -> dict:
        return {"application": APPLICATION, "namespace": self.namespace, "key": key}

    def _is(self, error: Exception, name: str) -> bool:
        cls = getattr(getattr(self.module, "exceptions", None), name, None)
        return isinstance(cls, type) and isinstance(error, cls)

    def _open(self):
        """(connection, unlocked default collection). Raises StoreUnavailable if there is none."""
        try:
            connection = self.module.dbus_init()
        except Exception:  # noqa: BLE001 - backend text must never reach the user
            raise StoreUnavailable(NO_BUS) from None
        try:
            collection = self.module.get_default_collection(connection)
            if collection.is_locked():
                raise StoreUnavailable(LOCKED)
        except StoreUnavailable:
            self._close(connection)
            raise
        except Exception as error:  # noqa: BLE001
            self._close(connection)
            raise StoreUnavailable(LOCKED if self._is(error, "LockedException") else NO_BUS) from None
        return connection, collection

    @staticmethod
    def _close(connection) -> None:
        with contextlib.suppress(Exception):
            connection.close()

    def probe(self) -> None:
        connection, _ = self._open()
        self._close(connection)

    def _run(self, action, failure: str):
        try:
            connection, collection = self._open()
        except StoreUnavailable as error:
            raise AuthError(str(error)) from None
        try:
            return action(collection)
        except Exception:  # noqa: BLE001 - backend text must never reach the user
            raise AuthError(failure) from None
        finally:
            self._close(connection)

    def get(self, key):
        def read(collection):
            for item in collection.search_items(self._attributes(key)):
                return item.get_secret().decode("utf-8")
            return None

        return self._run(read, "Unable to read the Secret Service keyring; unlock it and retry.")

    def set(self, key, value):
        def write(collection):
            collection.create_item(
                f"{self.namespace}/{key}",
                self._attributes(key),
                value.encode("utf-8"),
                replace=True,
                content_type="text/plain",
            )

        self._run(write, "Unable to save the session in the Secret Service keyring; unlock it and retry login.")

    def delete(self, key):
        def remove(collection):
            for item in list(collection.search_items(self._attributes(key))):
                item.delete()

        self._run(remove, "Unable to remove the session from the Secret Service keyring; unlock it and retry logout.")
