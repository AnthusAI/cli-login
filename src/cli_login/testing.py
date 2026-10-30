"""Fakes for specs: a provider, a store and a clock with no network, Keychain or credentials."""

from __future__ import annotations

import base64
import json

from .errors import AuthError
from .target import Target

ISSUER = "https://idp.example.test/pool-1"
CLIENT_ID = "client-1"


def make_target(**overrides) -> Target:
    values = {
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "oauth_domain": "https://auth.example.test",
        "token_endpoint": "https://auth.example.test/oauth2/token",
        "api_endpoint": "https://api.example.test/graphql",
        "key": "key-1",
        "namespace": "example-product",
        "callback_uri": "http://127.0.0.1:5182/oauth/callback",
    }
    values.update(overrides)
    return Target(**values)


def make_id_token(now, *, subject="person-1", issuer=ISSUER, audience=CLIENT_ID, token_use="id", lifetime=3600):
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "token_use": token_use,
        "exp": now + lifetime,
        "email": "person@example.test",
    }

    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return encode({"alg": "RS256"}) + "." + encode(claims) + ".fixture-signature"


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeStore:
    def __init__(self):
        self.data = {}
        self.locked = False

    def _check(self):
        if self.locked:
            raise AuthError("Unable to read OS secure credential storage; unlock it and retry.")

    def get(self, key):
        self._check()
        return self.data.get(key)

    def set(self, key, value):
        self._check()
        self.data[key] = value

    def delete(self, key):
        self._check()
        self.data.pop(key, None)


class FakeProvider:
    """Answers the token and revoke endpoints; `failure` is raised by the next token call."""

    def __init__(self, clock, *, subject="person-1"):
        self.clock = clock
        self.subject = subject
        self.calls = []
        self.failure = None
        self.revocation_failure = False
        self.issuer = ISSUER

    def post(self, url, fields):
        self.calls.append((url, fields))
        if url.endswith("/oauth2/revoke"):
            if self.revocation_failure:
                raise AuthError("Provider temporarily unavailable; retry later.")
            return {}
        if self.failure:
            raise self.failure
        return {
            "id_token": make_id_token(self.clock(), subject=self.subject, issuer=self.issuer),
            "refresh_token": "refresh-secret-" + str(len(self.calls)),
            "expires_in": 3600,
        }


class FakeKeyctl:
    """An in-memory kernel keyring with the same methods as ``Keyctl``. ``blocked`` mimics a seccomp profile."""

    def __init__(self, *, blocked=None, persistent=True):
        import errno

        self.errno = errno
        self.blocked = blocked  # an errno, e.g. EPERM, raised by every call
        self.persistent = persistent
        self.keys = {}  # (ring, description) -> (id, payload)
        self.ids = {}
        self.next_id = 100

    def _guard(self):
        if self.blocked:
            raise OSError(self.blocked, "blocked")

    def user_keyring(self):
        self._guard()
        return 1

    def persistent_keyring(self):
        self._guard()
        if not self.persistent:
            raise OSError(95, "no persistent keyrings")
        return 2

    def add_key(self, ring, description, payload):
        self._guard()
        existing = self.keys.get((ring, description))
        key_id = existing[0] if existing else self.next_id
        if not existing:
            self.next_id += 1
        self.keys[(ring, description)] = (key_id, bytes(payload))
        self.ids[key_id] = (ring, description)
        return key_id

    def search(self, ring, description):
        self._guard()
        if (ring, description) not in self.keys:
            raise OSError(126, "no key")  # ENOKEY on Linux
        return self.keys[(ring, description)][0]

    def read(self, key):
        self._guard()
        return self.keys[self.ids[key]][1]

    def unlink(self, key, ring):
        self._guard()
        self.keys.pop(self.ids.pop(key))


class FakeCredentialManager:
    """In-memory Credential Manager with the real 2,560-byte blob limit and optional crash injection."""

    def __init__(self, *, fail_after_writes=None, broken=False):
        self.items = {}
        self.writes = 0
        self.fail_after_writes = fail_after_writes  # raise on the write after this many succeeded
        self.broken = broken

    def _guard(self):
        if self.broken:
            raise OSError(5, "access denied")

    def write(self, target, blob, user):
        self._guard()
        if len(blob) > 2560:
            raise OSError(1783, "blob too large")
        if self.fail_after_writes is not None and self.writes >= self.fail_after_writes:
            raise OSError(1, "simulated crash")
        self.writes += 1
        self.items[target] = bytes(blob)

    def read(self, target):
        self._guard()
        return self.items.get(target)

    def delete(self, target):
        self._guard()
        self.items.pop(target, None)

    def enumerate(self, prefix):
        self._guard()
        return [t for t in list(self.items) if t.startswith(prefix)]


class FakeSecretStorage:
    """A stand-in for the ``secretstorage`` module: a default collection that can be locked or missing."""

    class exceptions:
        class SecretStorageException(Exception):
            pass

        class SecretServiceNotAvailableException(SecretStorageException):
            pass

        class LockedException(SecretStorageException):
            pass

    class _Item:
        def __init__(self, collection, attributes, secret):
            self.collection, self.attributes, self.secret = collection, attributes, secret

        def get_secret(self):
            return self.secret

        def delete(self):
            self.collection.items.remove(self)

    class _Collection:
        def __init__(self, owner):
            self.owner, self.items = owner, []

        def is_locked(self):
            return self.owner.locked

        def create_item(self, label, attributes, secret, replace=False, content_type="text/plain"):
            if replace:
                self.items = [i for i in self.items if i.attributes != attributes]
            self.owner.labels.append(label)
            item = FakeSecretStorage._Item(self, dict(attributes), secret)
            self.items.append(item)
            return item

        def search_items(self, attributes):
            return iter([i for i in self.items if i.attributes == attributes])

    class _Connection:
        def close(self):
            pass

    def __init__(self, *, locked=False, no_bus=False):
        self.locked, self.no_bus, self.labels = locked, no_bus, []
        self.collection = self._Collection(self)

    def dbus_init(self):
        if self.no_bus:
            raise self.exceptions.SecretServiceNotAvailableException("raw bus failure naming secret-value")
        return self._Connection()

    def get_default_collection(self, connection):
        return self.collection


def skip_or_fail(name: str, reason: str) -> None:
    """Skip a real-backend spec, unless CI requires that backend (ANTHUS_REQUIRE_REAL lists its name)."""
    import os

    import pytest

    if name in os.environ.get("ANTHUS_REQUIRE_REAL", "").split(","):
        pytest.fail(f"{name} is required in this run but unavailable: {reason}")
    pytest.skip(f"{name} unavailable: {reason}")
