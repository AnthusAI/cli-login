import errno
import sys

import pytest

from ..errors import AuthError, StoreUnavailable
from ..testing import FakeKeyctl, skip_or_fail
from .kernel_keyring import KernelKeyringStore


def test_a_session_round_trips_and_is_replaced_in_place():
    fake = FakeKeyctl()
    store = KernelKeyringStore("ns", backend=fake)
    store.set("k", "one")
    store.set("k", "two")
    assert store.get("k") == "two"
    assert len(fake.keys) == 1


def test_namespaces_are_separate_and_missing_is_none():
    fake = FakeKeyctl()
    KernelKeyringStore("ns", backend=fake).set("k", "v")
    assert KernelKeyringStore("other", backend=fake).get("k") is None
    assert KernelKeyringStore("ns", backend=fake).get("absent") is None


def test_delete_is_idempotent():
    store = KernelKeyringStore("ns", backend=FakeKeyctl())
    store.set("k", "v")
    store.delete("k")
    store.delete("k")
    assert store.get("k") is None


def test_user_keyring_is_used_when_no_persistent_keyring_exists():
    fake = FakeKeyctl(persistent=False)
    KernelKeyringStore("ns", backend=fake).set("k", "v")
    assert next(iter(fake.keys))[0] == 1


@pytest.mark.parametrize("code", [errno.EPERM, errno.ENOSYS, errno.EACCES])
def test_blocked_syscalls_are_unavailable(code):
    with pytest.raises(StoreUnavailable, match="memory agent"):
        KernelKeyringStore("ns", backend=FakeKeyctl(blocked=code)).probe()


def test_a_failure_after_selection_is_a_safe_auth_error():
    fake = FakeKeyctl()
    store = KernelKeyringStore("ns", backend=fake)
    fake.blocked = errno.EPERM
    for action in (lambda: store.get("k"), lambda: store.set("k", "secret-value"), lambda: store.delete("k")):
        with pytest.raises(AuthError) as caught:
            action()
        assert "secret-value" not in str(caught.value)


def test_an_oversized_session_is_refused():
    with pytest.raises(AuthError, match="too large"):
        KernelKeyringStore("ns", backend=FakeKeyctl()).set("k", "x" * 40000)


def test_the_real_probe_and_round_trip_on_linux():
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux only")
    try:
        store = KernelKeyringStore("anthus-spec-" + str(id(sys)))
        store.probe()
    except StoreUnavailable as error:
        skip_or_fail("kernel-keyring", str(error))
    store.set("key-1", "real-value")
    try:
        assert store.get("key-1") == "real-value"
        store.set("key-1", "replaced")
        assert store.get("key-1") == "replaced"
    finally:
        store.delete("key-1")
    assert store.get("key-1") is None


def test_a_real_secret_outlives_the_process_that_wrote_it():
    import subprocess

    if not sys.platform.startswith("linux"):
        pytest.skip("Linux only")
    store = KernelKeyringStore("anthus-spec-cross")
    try:
        store.probe()
    except StoreUnavailable as error:
        skip_or_fail("kernel-keyring", str(error))
    code = (
        "from anthus_cli_login.stores.kernel_keyring import KernelKeyringStore as S;"
        "S('anthus-spec-cross').set('key-1', 'written-elsewhere')"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
    try:
        assert store.get("key-1") == "written-elsewhere"
    finally:
        store.delete("key-1")
