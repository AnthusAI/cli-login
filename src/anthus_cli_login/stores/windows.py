"""Windows Credential Manager, through ctypes (CredWriteW / CredReadW / CredDeleteW / CredEnumerateW).

Importable everywhere; the real API loads only on Windows. A generic credential blob holds at most 2,560
bytes, so a larger value is split into chunks:

- ``<namespace>/<key>`` is the *header*. It holds either the whole value (``I1:`` + value) or a pointer to a
  generation of chunks (``C1:<generation>:<count>:<sha256 of the whole value>``).
- ``<namespace>/<key>#<generation>-<n>`` holds chunk ``n`` of that generation.

A generation is random per write, so new chunks never overwrite old ones. A write stores the new chunks, then
the header (one atomic CredWrite switches the value), then deletes stale chunks. A crash at any point leaves
either the old value or the new one, never a mix; leftovers are swept by the next write or delete. Callers hold
the key's lock (``key_lock``) while writing, which is how ``Session`` uses a store.
"""

from __future__ import annotations

import hashlib
import secrets
import sys

from ..errors import AuthError, StoreUnavailable

MAX_BLOB = 2560  # CRED_MAX_CREDENTIAL_BLOB_SIZE
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
ERROR_NOT_FOUND = 1168
_INLINE = b"I1:"
_CHUNKED = b"C1:"


class CredentialError(OSError):
    """A Credential Manager call failed; carries only the Windows error code."""


class CredentialManager:
    """The real Win32 API. Tests substitute an in-memory double with the same four methods."""

    def __init__(self):
        if sys.platform != "win32":
            raise StoreUnavailable("Windows Credential Manager exists only on Windows.")
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        self._c = ctypes
        self._CREDENTIAL = CREDENTIAL
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        pcred = ctypes.POINTER(CREDENTIAL)
        advapi.CredWriteW.argtypes = [pcred, wintypes.DWORD]
        advapi.CredWriteW.restype = wintypes.BOOL
        advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(pcred)]
        advapi.CredReadW.restype = wintypes.BOOL
        advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        advapi.CredDeleteW.restype = wintypes.BOOL
        advapi.CredEnumerateW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.POINTER(pcred)),
        ]
        advapi.CredEnumerateW.restype = wintypes.BOOL
        advapi.CredFree.argtypes = [ctypes.c_void_p]
        advapi.CredFree.restype = None
        self._api = advapi

    def _fail(self):
        raise CredentialError(self._c.get_last_error(), "credential call failed")

    def write(self, target: str, blob: bytes, user: str) -> None:
        c = self._c
        buffer = (c.c_ubyte * max(len(blob), 1)).from_buffer_copy(blob or b"\0")
        credential = self._CREDENTIAL()
        credential.Type = CRED_TYPE_GENERIC
        credential.TargetName = target
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = c.cast(buffer, c.POINTER(c.c_ubyte))
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = user
        if not self._api.CredWriteW(c.byref(credential), 0):
            self._fail()

    def read(self, target: str) -> bytes | None:
        c = self._c
        pointer = c.POINTER(self._CREDENTIAL)()
        if not self._api.CredReadW(target, CRED_TYPE_GENERIC, 0, c.byref(pointer)):
            if c.get_last_error() == ERROR_NOT_FOUND:
                return None
            self._fail()
        try:
            credential = pointer.contents
            return c.string_at(credential.CredentialBlob, credential.CredentialBlobSize) if credential.CredentialBlobSize else b""
        finally:
            self._api.CredFree(pointer)

    def delete(self, target: str) -> None:
        if not self._api.CredDeleteW(target, CRED_TYPE_GENERIC, 0) and self._c.get_last_error() != ERROR_NOT_FOUND:
            self._fail()

    def enumerate(self, prefix: str) -> list[str]:
        """Target names that start with ``prefix``."""
        c = self._c
        from ctypes import wintypes

        count = wintypes.DWORD()
        items = c.POINTER(c.POINTER(self._CREDENTIAL))()
        if not self._api.CredEnumerateW(prefix + "*", 0, c.byref(count), c.byref(items)):
            if c.get_last_error() == ERROR_NOT_FOUND:
                return []
            self._fail()
        try:
            return [items[i].contents.TargetName for i in range(count.value)]
        finally:
            self._api.CredFree(items)


class WindowsCredentialStore:
    name = "Windows Credential Manager"

    def __init__(self, namespace: str, *, backend=None):
        if not namespace:
            raise AuthError("A store namespace is required.")
        self.namespace = namespace
        self.backend = backend if backend is not None else CredentialManager()

    def _header(self, key: str) -> str:
        return f"{self.namespace}/{key}"

    def _chunk(self, key: str, generation: str, index: int) -> str:
        return f"{self.namespace}/{key}#{generation}-{index}"

    def probe(self) -> None:
        try:
            self.backend.read(self._header("probe"))
        except OSError:
            raise StoreUnavailable("Windows Credential Manager could not be reached; sign in to Windows and retry.") from None

    def _sweep(self, key: str, keep: str | None) -> None:
        for target in self.backend.enumerate(self._header(key) + "#"):
            if keep is None or not target.startswith(f"{self._header(key)}#{keep}-"):
                self.backend.delete(target)

    def get(self, key):
        try:
            header = self.backend.read(self._header(key))
            if header is None:
                return None
            if header.startswith(_INLINE):
                return header[len(_INLINE):].decode("utf-8")
            if not header.startswith(_CHUNKED):
                raise ValueError()
            generation, count, digest = header[len(_CHUNKED):].decode("ascii").split(":")
            parts = []
            for index in range(int(count)):
                part = self.backend.read(self._chunk(key, generation, index))
                if part is None:
                    raise ValueError()
                parts.append(part)
            value = b"".join(parts)
            if hashlib.sha256(value).hexdigest() != digest:
                raise ValueError()
            return value.decode("utf-8")
        except OSError:
            raise AuthError("Unable to read Windows Credential Manager; retry, or sign in to Windows again.") from None
        except (ValueError, UnicodeDecodeError):
            raise AuthError("The stored session is damaged; run the login command to replace it.") from None

    def set(self, key, value):
        data = value.encode("utf-8")
        try:
            if len(_INLINE) + len(data) <= MAX_BLOB:
                self.backend.write(self._header(key), _INLINE + data, self.namespace)
                self._sweep(key, None)
                return
            generation = secrets.token_hex(6)
            size = MAX_BLOB
            pieces = [data[i : i + size] for i in range(0, len(data), size)]
            for index, piece in enumerate(pieces):
                self.backend.write(self._chunk(key, generation, index), piece, self.namespace)
            header = f"{generation}:{len(pieces)}:{hashlib.sha256(data).hexdigest()}".encode("ascii")
            self.backend.write(self._header(key), _CHUNKED + header, self.namespace)
            self._sweep(key, generation)
        except OSError:
            raise AuthError(
                "Unable to save the session in Windows Credential Manager; retry login."
            ) from None

    def delete(self, key):
        try:
            self.backend.delete(self._header(key))
            self._sweep(key, None)
        except OSError:
            raise AuthError("Unable to remove the session from Windows Credential Manager; retry logout.") from None
