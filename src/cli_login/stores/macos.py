"""macOS Keychain, through Apple's Security framework. No plaintext fallback, ever.

Importable on every platform; it fails only when used off macOS.
"""

from __future__ import annotations

import ctypes as C
import sys

from ..errors import AuthError


class MacOSKeychain:
    """Minimal generic-password adapter. No subprocess arguments, token files or keyring fallback."""

    def __init__(self):
        if sys.platform != "darwin":
            raise RuntimeError("macOS Keychain is required")
        self.cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
        signatures = {
            "CFStringCreateWithCString": ([C.c_void_p, C.c_char_p, C.c_uint32], C.c_void_p),
            "CFDataCreate": ([C.c_void_p, C.c_void_p, C.c_long], C.c_void_p),
            "CFDictionaryCreate": (
                [C.c_void_p, C.POINTER(C.c_void_p), C.POINTER(C.c_void_p), C.c_long, C.c_void_p, C.c_void_p],
                C.c_void_p,
            ),
            "CFDataGetLength": ([C.c_void_p], C.c_long),
            "CFDataGetBytePtr": ([C.c_void_p], C.c_void_p),
            "CFRelease": ([C.c_void_p], None),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.cf, name)
            function.argtypes, function.restype = arguments, result
        for name, args in {
            "SecItemAdd": [C.c_void_p, C.POINTER(C.c_void_p)],
            "SecItemCopyMatching": [C.c_void_p, C.POINTER(C.c_void_p)],
            "SecItemUpdate": [C.c_void_p, C.c_void_p],
            "SecItemDelete": [C.c_void_p],
        }.items():
            function = getattr(self.sec, name)
            function.argtypes, function.restype = args, C.c_int32

    def _constant(self, name):
        return C.c_void_p.in_dll(self.sec, name).value

    def _dictionary(self, service, account, *, value=None, read=False, payload_only=False):
        owned = []
        pairs = []

        def text(name, text_value):
            pointer = self.cf.CFStringCreateWithCString(None, text_value.encode("utf-8"), 0x08000100)
            if not pointer:
                raise RuntimeError("Keychain allocation failed")
            owned.append(pointer)
            pairs.append((self._constant(name), pointer))

        if not payload_only:
            pairs.append((self._constant("kSecClass"), self._constant("kSecClassGenericPassword")))
            text("kSecAttrService", service)
            text("kSecAttrAccount", account)
            # Do not trigger an unexpected unlock/authentication dialog from a worker.
            pairs.append((self._constant("kSecUseAuthenticationUI"), self._constant("kSecUseAuthenticationUIFail")))
        if read:
            pairs.append((self._constant("kSecReturnData"), C.c_void_p.in_dll(self.cf, "kCFBooleanTrue").value))
            pairs.append((self._constant("kSecMatchLimit"), self._constant("kSecMatchLimitOne")))
        if value is not None:
            encoded = value.encode("utf-8")
            pointer = self.cf.CFDataCreate(None, encoded, len(encoded))
            if not pointer:
                raise RuntimeError("Keychain allocation failed")
            owned.append(pointer)
            pairs.append((self._constant("kSecValueData"), pointer))
        keys = (C.c_void_p * len(pairs))(*(x[0] for x in pairs))
        values = (C.c_void_p * len(pairs))(*(x[1] for x in pairs))
        pointer = self.cf.CFDictionaryCreate(None, keys, values, len(pairs), None, None)
        if not pointer:
            raise RuntimeError("Keychain allocation failed")
        return pointer, owned

    def _release(self, dictionary):
        pointer, owned = dictionary
        self.cf.CFRelease(pointer)
        for item in owned:
            self.cf.CFRelease(item)

    def get_password(self, service, account):
        dictionary = self._dictionary(service, account, read=True)
        result = C.c_void_p()
        try:
            status = self.sec.SecItemCopyMatching(dictionary[0], C.byref(result))
            if status == -25300:  # errSecItemNotFound
                return None
            if status != 0:
                raise RuntimeError("Keychain read failed")
            try:
                return C.string_at(self.cf.CFDataGetBytePtr(result), self.cf.CFDataGetLength(result)).decode("utf-8")
            finally:
                self.cf.CFRelease(result)
        finally:
            self._release(dictionary)

    def set_password(self, service, account, value):
        dictionary = self._dictionary(service, account, value=value)
        try:
            status = self.sec.SecItemAdd(dictionary[0], None)
        finally:
            self._release(dictionary)
        if status == -25299:  # errSecDuplicateItem: update without deleting the old secret first.
            query = self._dictionary(service, account)
            payload = self._dictionary(service, account, value=value, payload_only=True)
            try:
                status = self.sec.SecItemUpdate(query[0], payload[0])
            finally:
                self._release(payload)
                self._release(query)
        if status != 0:
            raise RuntimeError("Keychain save failed")

    def delete_password(self, service, account):
        dictionary = self._dictionary(service, account)
        try:
            status = self.sec.SecItemDelete(dictionary[0])
        finally:
            self._release(dictionary)
        if status not in (0, -25300):
            raise RuntimeError("Keychain delete failed")


class MacOSKeychainStore:
    """Keychain store whose service name is the target's namespace.

    A product that already stores sessions under a service name keeps that name as its namespace,
    so its existing sessions are found under the same service and key.
    """

    def __init__(self, namespace: str, backend=None):
        if not namespace:
            raise AuthError("A store namespace is required.")
        if backend is None:
            try:
                backend = MacOSKeychain()
            except Exception:  # noqa: BLE001 - backend text must never reach the user
                raise AuthError(
                    "macOS Keychain is unavailable. Use the tool on an unlocked Mac; no plaintext credential fallback is supported."
                ) from None
        if not isinstance(backend, MacOSKeychain):
            raise AuthError(
                "A supported OS secure credential store is required; plaintext/fallback backends are refused."
            )
        self.namespace = namespace
        self.backend = backend

    def get(self, key):
        try:
            return self.backend.get_password(self.namespace, key)
        except Exception:  # noqa: BLE001 - backend text must never reach the user
            raise AuthError("Unable to read OS secure credential storage; unlock it and retry.") from None

    def set(self, key, value):
        try:
            self.backend.set_password(self.namespace, key, value)
        except Exception:  # noqa: BLE001 - backend text must never reach the user
            raise AuthError(
                "Unable to save the session in OS secure credential storage; unlock it and retry login."
            ) from None

    def delete(self, key):
        if self.get(key) is None:
            return
        try:
            self.backend.delete_password(self.namespace, key)
        except Exception:  # noqa: BLE001 - backend text must never reach the user
            raise AuthError(
                "Unable to remove the local OS credential; unlock the secure store and retry logout."
            ) from None
