import pytest

from ..errors import AuthError
from .macos import MacOSKeychain, MacOSKeychainStore


class FakeKeychain(MacOSKeychain):
    """A Keychain double keyed by (service, account), exactly as the real one is."""

    def __init__(self, items=None, broken=False):
        self.items = dict(items or {})
        self.broken = broken
        self.reads = []

    def get_password(self, service, account):
        self.reads.append((service, account))
        if self.broken:
            raise RuntimeError("raw failure mentioning secret-value")
        return self.items.get((service, account))

    def set_password(self, service, account, value):
        if self.broken:
            raise RuntimeError("fail")
        self.items[(service, account)] = value

    def delete_password(self, service, account):
        self.items.pop((service, account), None)


def test_an_existing_papyrus_session_is_read_from_the_same_service_and_key():
    keychain = FakeKeychain({("papyrus-newsroom-oauth", "site-key-1"): "stored-session"})
    store = MacOSKeychainStore("papyrus-newsroom-oauth", keychain)
    assert store.get("site-key-1") == "stored-session"
    assert keychain.reads == [("papyrus-newsroom-oauth", "site-key-1")]


def test_writes_land_under_the_same_service_and_key():
    keychain = FakeKeychain()
    MacOSKeychainStore("papyrus-newsroom-oauth", keychain).set("site-key-1", "v")
    assert keychain.items == {("papyrus-newsroom-oauth", "site-key-1"): "v"}


def test_another_namespace_does_not_see_the_session():
    keychain = FakeKeychain({("papyrus-newsroom-oauth", "site-key-1"): "stored-session"})
    assert MacOSKeychainStore("other-product", keychain).get("site-key-1") is None


def test_a_broken_keychain_fails_closed_without_leaking_text():
    store = MacOSKeychainStore("ns", FakeKeychain(broken=True))
    for action in (lambda: store.get("k"), lambda: store.set("k", "v")):
        with pytest.raises(AuthError) as caught:
            action()
        assert "secret-value" not in str(caught.value)


def test_a_non_keychain_backend_is_refused():
    with pytest.raises(AuthError, match="plaintext"):
        MacOSKeychainStore("ns", object())


def test_delete_removes_only_an_existing_item():
    keychain = FakeKeychain({("ns", "k"): "v"})
    store = MacOSKeychainStore("ns", keychain)
    store.delete("k")
    store.delete("k")
    assert keychain.items == {}


def test_the_module_imports_everywhere_and_fails_only_when_used(monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    with pytest.raises(AuthError, match="Keychain"):
        MacOSKeychainStore("ns")
