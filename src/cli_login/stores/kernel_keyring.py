"""The Linux kernel keyring, through raw syscalls with ctypes (no extra dependency).

Secrets live in kernel memory, in the user's *persistent* keyring when the kernel offers one, else in the user
keyring. They last until the machine reboots, or, for the persistent keyring, until its expiry
(``/proc/sys/kernel/keys/persistent_keyring_expiry``, three days by default, counted from last use). They are
readable by processes of the same user, as with the memory agent.

Docker's default seccomp profile blocks ``add_key`` and ``keyctl``. The store therefore probes first with a
real write, read and delete, and reports itself unavailable when the kernel refuses.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import sys

from ..errors import AuthError, StoreUnavailable

# (add_key, keyctl) syscall numbers by architecture.
_SYSCALLS = {
    "x86_64": (248, 250),
    "aarch64": (217, 219),
    "arm64": (217, 219),
    "riscv64": (217, 219),
}
KEY_SPEC_SESSION_KEYRING = -3
KEY_SPEC_USER_KEYRING = -4
KEYCTL_GET_KEYRING_ID = 0
KEYCTL_UNLINK = 9
KEYCTL_SEARCH = 10
KEYCTL_READ = 11
KEYCTL_GET_PERSISTENT = 22
ENOKEY, EKEYEXPIRED, EKEYREVOKED = 126, 127, 128  # Linux values; absent from errno on other systems
_MISSING = (ENOKEY, EKEYREVOKED, EKEYEXPIRED)
MAX_PAYLOAD = 32767  # the kernel's limit for a "user" key

GUIDANCE_MEMORY = "the kernel keyring is unavailable here (a container's seccomp profile often blocks it)"


class KeyctlError(OSError):
    """A syscall failed; carries only an errno."""


class Keyctl:
    """The real syscalls. Tests substitute an in-memory double with the same methods."""

    def __init__(self):
        if not sys.platform.startswith("linux") or platform.system() != "Linux":
            raise StoreUnavailable("The kernel keyring exists only on Linux.")
        numbers = _SYSCALLS.get(platform.machine())
        if numbers is None:
            raise StoreUnavailable("The kernel keyring is not supported on this CPU architecture.")
        self._add_key, self._keyctl = numbers
        try:
            self._syscall = ctypes.CDLL(None, use_errno=True).syscall
        except (OSError, AttributeError):
            raise StoreUnavailable("The kernel keyring cannot be reached from Python here.") from None
        self._syscall.restype = ctypes.c_long

    def _call(self, *args):
        result = self._syscall(*args)
        if result < 0:
            code = ctypes.get_errno()
            raise KeyctlError(code, os.strerror(code))
        return result

    @staticmethod
    def _n(value):
        return ctypes.c_long(value)

    def keyctl(self, command, *numbers):
        padded = list(numbers) + [0] * (4 - len(numbers))
        return self._call(self._n(self._keyctl), self._n(command), *(self._n(x) for x in padded))

    def user_keyring(self) -> int:
        return self.keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING, 1)

    def persistent_keyring(self) -> int:
        # Link it into the session keyring: only a keyring the process *possesses* may be written to.
        return self.keyctl(KEYCTL_GET_PERSISTENT, -1, KEY_SPEC_SESSION_KEYRING)

    def add_key(self, ring: int, description: str, payload: bytes) -> int:
        buffer = ctypes.create_string_buffer(payload, len(payload) or 1)
        return self._call(
            self._n(self._add_key),
            ctypes.c_char_p(b"user"),
            ctypes.c_char_p(description.encode("utf-8")),
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.c_size_t(len(payload)),
            self._n(ring),
        )

    def search(self, ring: int, description: str) -> int:
        return self._call(
            self._n(self._keyctl),
            self._n(KEYCTL_SEARCH),
            self._n(ring),
            ctypes.c_char_p(b"user"),
            ctypes.c_char_p(description.encode("utf-8")),
            self._n(0),
        )

    def read(self, key: int) -> bytes:
        size = 512
        while True:
            buffer = ctypes.create_string_buffer(size)
            needed = self._call(
                self._n(self._keyctl),
                self._n(KEYCTL_READ),
                self._n(key),
                ctypes.cast(buffer, ctypes.c_void_p),
                ctypes.c_size_t(size),
                self._n(0),
            )
            if needed <= size:
                return buffer.raw[:needed]
            size = needed

    def unlink(self, key: int, ring: int) -> None:
        self.keyctl(KEYCTL_UNLINK, key, ring)


class KernelKeyringStore:
    name = "kernel keyring"

    def __init__(self, namespace: str, *, backend=None):
        if not namespace:
            raise AuthError("A store namespace is required.")
        self.namespace = namespace
        self.backend = backend if backend is not None else Keyctl()
        self._ring = None

    def _description(self, key: str) -> str:
        return f"cli-login:{self.namespace}:{key}"

    def _keyring(self) -> int:
        if self._ring is None:
            try:
                self._ring = self.backend.persistent_keyring()
            except OSError:
                self._ring = self.backend.user_keyring()  # kernels without persistent keyrings
        return self._ring

    def probe(self) -> None:
        """Write, read back and remove a throwaway key; unavailable if the kernel refuses any step."""
        description = f"cli-login:probe:{os.getpid()}"
        try:
            ring = self._keyring()
            key = self.backend.add_key(ring, description, b"probe")
            try:
                ok = self.backend.read(key) == b"probe"
            finally:
                self.backend.unlink(key, ring)
        except OSError as error:
            blocked = error.errno in (errno.EPERM, errno.ENOSYS, errno.EACCES)
            raise StoreUnavailable(
                (GUIDANCE_MEMORY if blocked else "The kernel keyring could not be used")
                + "; use the memory agent instead."
            ) from None
        if not ok:
            raise StoreUnavailable("The kernel keyring did not return what was written; " + "use the memory agent.")

    def get(self, key):
        try:
            ring = self._keyring()
            try:
                found = self.backend.search(ring, self._description(key))
            except OSError as error:
                if error.errno in _MISSING:
                    return None
                raise
            return self.backend.read(found).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            raise AuthError("Unable to read the kernel keyring; start a new login or use the memory agent.") from None

    def set(self, key, value):
        payload = value.encode("utf-8")
        if len(payload) > MAX_PAYLOAD:
            raise AuthError("The session is too large for the kernel keyring.")
        try:
            # Adding a key with the same type and description replaces its payload in place.
            self.backend.add_key(self._keyring(), self._description(key), payload)
        except OSError:
            raise AuthError(
                "Unable to save the session in the kernel keyring; use the memory agent or retry login."
            ) from None

    def delete(self, key):
        try:
            ring = self._keyring()
            try:
                found = self.backend.search(ring, self._description(key))
            except OSError as error:
                if error.errno in _MISSING:
                    return
                raise
            self.backend.unlink(found, ring)
        except OSError:
            raise AuthError("Unable to remove the session from the kernel keyring; retry logout.") from None
