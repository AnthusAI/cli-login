import sys

import pytest

from ..errors import AuthError, StoreUnavailable
from ..testing import FakeSecretStorage, skip_or_fail
from .secret_service import SecretServiceStore


def test_items_are_labelled_and_attributed_by_namespace_and_key():
    fake = FakeSecretStorage()
    SecretServiceStore("ns", module=fake).set("k", "v")
    item = fake.collection.items[0]
    assert fake.labels == ["ns/k"]
    assert item.attributes == {"application": "cli-login", "namespace": "ns", "key": "k"}


def test_round_trip_replace_delete_and_isolation():
    fake = FakeSecretStorage()
    store = SecretServiceStore("ns", module=fake)
    store.set("k", "one")
    store.set("k", "two")
    assert store.get("k") == "two" and len(fake.collection.items) == 1
    assert SecretServiceStore("other", module=fake).get("k") is None
    store.delete("k")
    assert store.get("k") is None


def test_locked_and_absent_are_unavailable():
    with pytest.raises(StoreUnavailable, match="unlock"):
        SecretServiceStore("ns", module=FakeSecretStorage(locked=True)).probe()
    with pytest.raises(StoreUnavailable) as caught:
        SecretServiceStore("ns", module=FakeSecretStorage(no_bus=True)).probe()
    assert "secret-value" not in str(caught.value) and "memory agent" in str(caught.value)


def test_a_missing_package_names_the_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "secretstorage", None)
    with pytest.raises(StoreUnavailable, match=r"cli-login\[linux\]"):
        SecretServiceStore("ns")


def test_a_keyring_that_locks_later_fails_closed():
    fake = FakeSecretStorage()
    store = SecretServiceStore("ns", module=fake)
    store.set("k", "v")
    fake.locked = True
    for action in (lambda: store.get("k"), lambda: store.set("k", "secret-value"), lambda: store.delete("k")):
        with pytest.raises(AuthError, match="unlock") as caught:
            action()
        assert "secret-value" not in str(caught.value)
    assert fake.collection.items[0].secret == b"v"


def test_a_failing_backend_never_leaks_its_text():
    fake = FakeSecretStorage()

    def boom(*a, **k):
        raise RuntimeError("raw failure naming secret-value")

    fake.collection.create_item = boom
    with pytest.raises(AuthError) as caught:
        SecretServiceStore("ns", module=fake).set("k", "v")
    assert "secret-value" not in str(caught.value)


def test_the_real_secret_service_on_linux():
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux only")
    try:
        store = SecretServiceStore("anthus-spec-ns")
        store.probe()
    except StoreUnavailable as error:
        skip_or_fail("secret-service", str(error))
    store.set("key-1", "real-value")
    try:
        assert store.get("key-1") == "real-value"
        store.set("key-1", "replaced")
        assert store.get("key-1") == "replaced"
    finally:
        store.delete("key-1")
    assert store.get("key-1") is None


