"""The product's target: everything the library needs to sign in, and nothing secret."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from .errors import AuthError

_SAFE_NAME = re.compile(r"[A-Za-z0-9._-]{1,200}")


def https_url(value: object, label: str, *, origin: bool = False) -> None:
    """Require a plain HTTPS URL (or origin): no credentials, query or fragment."""
    if not isinstance(value, str):
        raise AuthError(f"Invalid {label}: a configured HTTPS URL is required.")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or (origin and parsed.path not in ("", "/"))
    ):
        raise AuthError(f"Invalid {label}: a configured HTTPS {'origin' if origin else 'URL'} is required.")


def is_loopback_callback(callback_uri: str) -> bool:
    """True for a fixed-port HTTP callback on literal 127.0.0.1 or localhost."""
    callback = urllib.parse.urlsplit(callback_uri)
    try:
        port_ok = callback.port is not None and 1024 <= callback.port <= 65535
    except ValueError:
        port_ok = False
    return (
        callback.scheme == "http"
        and callback.hostname in ("127.0.0.1", "localhost")
        and port_ok
        and not (callback.username or callback.password or callback.query or callback.fragment)
    )


@dataclass(frozen=True)
class Target:
    issuer: str
    client_id: str
    oauth_domain: str
    token_endpoint: str
    api_endpoint: str
    key: str
    namespace: str
    callback_uri: str
    broker_endpoint: str | None = None

    def __post_init__(self):
        https_url(self.issuer, "issuer")
        https_url(self.oauth_domain, "oauth_domain", origin=True)
        https_url(self.token_endpoint, "token_endpoint")
        https_url(self.api_endpoint, "api_endpoint")
        if self.broker_endpoint is not None:
            https_url(self.broker_endpoint, "broker_endpoint")
        object.__setattr__(self, "oauth_domain", self.oauth_domain.rstrip("/"))
        if not self.client_id or not isinstance(self.client_id, str):
            raise AuthError("A registered OAuth client id is required.")
        for label in ("key", "namespace"):
            value = getattr(self, label)
            if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value):
                raise AuthError(f"Invalid {label}: letters, digits, dot, dash and underscore only.")
        if not isinstance(self.callback_uri, str):
            raise AuthError("A callback URI is required.")
        if not is_loopback_callback(self.callback_uri):
            try:
                https_url(self.callback_uri, "callback_uri")
            except AuthError:
                raise AuthError(
                    "The callback must be an HTTPS URL, or an HTTP URL on literal 127.0.0.1 or localhost "
                    "with a fixed unprivileged port."
                ) from None

    @property
    def revoke_endpoint(self) -> str:
        return self.oauth_domain + "/oauth2/revoke"

    @property
    def authorize_endpoint(self) -> str:
        return self.oauth_domain + "/oauth2/authorize"

    @property
    def has_loopback_callback(self) -> bool:
        return is_loopback_callback(self.callback_uri)
