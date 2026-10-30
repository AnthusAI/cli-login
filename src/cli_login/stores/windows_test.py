import sys

import pytest

from ..errors import AuthError
from ..testing import FakeCredentialManager
from .windows import MAX_BLOB, WindowsCredentialStore


def store_with(fake=None):
    fake = fake or FakeCredentialManager()
    return WindowsCredentialStore("ns", backend=fake), fake


def test_a_small_value_uses_one_credential_named_namespace_slash_key():
    store, fake = store_with()
    store.set("k", "v")
    assert list(fake.items) == ["ns/k"]
    assert store.get("k") == "v"


@pytest.mark.parametrize("size", [2556, 2557, 2560, 2561, 5120, 5121, 20000])
def test_values_of_every_size_round_trip_within_the_blob_limit(size):
    store, fake = store_with()
    value = "".join(chr(0x41 + i % 26) for i in range(size))
    store.set("k", value)
    assert store.get("k") == value
    assert all(len(blob) <= MAX_BLOB for blob in fake.items.values())


def test_multibyte_text_survives_chunk_boundaries():
    store, _ = store_with()
    value = "é€\U0001f600" * 1500
    store.set("k", value)
    assert store.get("k") == value


def test_rotation_leaves_only_the_new_generation():
    store, fake = store_with()
    store.set("k", "a" * 7000)
    store.set("k", "b" * 5000)
    assert len(fake.items) == 3
    store.set("k", "small")
    assert list(fake.items) == ["ns/k"]


@pytest.mark.parametrize("writes", range(6))
@pytest.mark.parametrize("old,new", [(7000, 7000), (7000, 100), (100, 7000)])
def test_a_crash_never_leaves_a_mixture(writes, old, new):
    store, fake = store_with()
    before, after = "o" * old, "n" * new
    store.set("k", before)
    fake.fail_after_writes = fake.writes + writes
    try:
        store.set("k", after)
    except AuthError:
        pass
    fake.fail_after_writes = None
    assert store.get("k") in (before, after)
    store.set("k", after)  # the next save sweeps any leftovers
    assert store.get("k") == after
    expected = 1 if new <= 2556 else 1 + -(-new // MAX_BLOB)
    assert len(fake.items) == expected


def test_delete_removes_header_and_chunks_and_is_idempotent():
    store, fake = store_with()
    store.set("k", "x" * 9000)
    store.delete("k")
    store.delete("k")
    assert fake.items == {} and store.get("k") is None


def test_keys_do_not_touch_each_other_or_other_namespaces():
    fake = FakeCredentialManager()
    first, other = WindowsCredentialStore("ns", backend=fake), WindowsCredentialStore("other", backend=fake)
    first.set("a", "x" * 6000)
    first.set("ab", "y")
    first.delete("a")
    assert first.get("ab") == "y" and other.get("ab") is None


def test_a_damaged_or_missing_chunk_is_reported():
    store, fake = store_with()
    store.set("k", "x" * 7000)
    chunk = next(t for t in fake.items if "#" in t)
    saved = fake.items[chunk]
    fake.items[chunk] = b"y" * len(saved)
    with pytest.raises(AuthError, match="damaged"):
        store.get("k")
    del fake.items[chunk]
    with pytest.raises(AuthError, match="damaged"):
        store.get("k")


def test_failures_never_leak_backend_text():
    store, _ = store_with(FakeCredentialManager(broken=True))
    for action in (lambda: store.get("k"), lambda: store.set("k", "secret-value"), lambda: store.delete("k")):
        with pytest.raises(AuthError) as caught:
            action()
        assert "secret-value" not in str(caught.value) and "denied" not in str(caught.value)


def test_the_module_imports_everywhere_and_the_real_api_loads_only_on_windows():
    if sys.platform == "win32":
        pytest.skip("covered by the real specs")
    from .windows import CredentialManager

    with pytest.raises(AuthError, match="Windows"):
        CredentialManager()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Credential Manager")
def test_the_real_credential_manager():
    from .windows import CredentialManager

    store = WindowsCredentialStore("anthus-spec-ns", backend=CredentialManager())
    store.probe()
    small, large = "small-value", "".join(chr(0x61 + i % 26) for i in range(9000)) + "é"
    try:
        store.set("key-1", small)
        assert store.get("key-1") == small
        store.set("key-1", large)
        assert store.get("key-1") == large
        store.set("key-1", small)
        assert store.get("key-1") == small
        assert CredentialManager().enumerate("anthus-spec-ns/key-1#") == []
    finally:
        store.delete("key-1")
    assert store.get("key-1") is None
    assert CredentialManager().enumerate("anthus-spec-ns/") == []
