"""Error types. Messages never carry token values or provider payloads."""

from __future__ import annotations


class AuthError(ValueError):
    """A safe, operator-facing message; never include provider payloads or secrets."""


class StoreUnavailable(AuthError):
    """A secure store cannot be used here (absent, locked or blocked).

    Choosing a store moves on to the next candidate; the message is the recovery guidance and never carries a
    secret or a backend's raw text.
    """


class OAuthError(AuthError):
    """The provider refused or could not serve a token request."""

    def __init__(self, code: str, *, transient: bool = False, login_command: str | None = None):
        self.code = code
        self.transient = transient
        login = login_command or "login"
        super().__init__(
            "Sign-in provider temporarily unavailable; retry later."
            if transient
            else f"Session expired or was revoked; run `{login}`."
        )
