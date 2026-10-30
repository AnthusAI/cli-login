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
