"""A renewable session: login, renewal, status and logout with honest revocation."""

from __future__ import annotations

import base64
import json
import math
import secrets
import threading
import time
from contextlib import contextmanager

from .errors import AuthError, OAuthError
from .locks import default_state_dir, key_lock
from .oauth import HTTPProvider, authorization_url, pkce_pair, receive_code
from .stores import open_store
from .target import Target


class Session:
    def __init__(
        self,
        target: Target,
        *,
        store=None,
        provider=None,
        clock=time.time,
        receive=receive_code,
        state_dir=None,
        login_command: str = "login",
        identity_provider: str | None = None,
    ):
        self.target = target
        self.store = store if store is not None else open_store(target)
        self.provider = provider if provider is not None else HTTPProvider()
        self.clock = clock
        self.receive = receive
        self.state_dir = state_dir if state_dir is not None else default_state_dir(target.namespace)
        self.login_command = login_command
        self.identity_provider = identity_provider
        self._token = None
        self._expires = 0.0
        self._subject = None
        self._guard = threading.RLock()
        self._depth = 0

    @contextmanager
    def _hold(self):
        """The key's lock, re-entrant within this session so locked callers can store a token set."""
        with self._guard:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            with key_lock(self.state_dir, self.target.key):
                self._depth = 1
                try:
                    yield
                finally:
                    self._depth = 0

    def _record(self):
        raw = self.store.get(self.target.key)
        if raw is None:
            raise AuthError(f"No session; run `{self.login_command}`.")
        try:
            record = json.loads(raw)
            if (
                not isinstance(record.get("refresh_token"), str)
                or not record["refresh_token"]
                or not isinstance(record.get("subject"), str)
                or not record["subject"]
                or not isinstance(record.get("label"), str)
            ):
                raise ValueError()
            record["created_at"] = float(record["created_at"])
            if not math.isfinite(record["created_at"]):
                raise ValueError()
            return record
        except (KeyError, ValueError, AttributeError, TypeError):
            raise AuthError(f"Stored session is invalid; run `{self.login_command}` to replace it.") from None

    def store_token_set(self, response, *, previous=None) -> dict:
        """Check a token response against the target and save the session under the key's lock.

        Returns {subject, label, created_at}. Raises AuthError, saving nothing, on any mismatch.
        """
        try:
            value = response["id_token"]
            claims = json.loads(base64.urlsafe_b64decode(value.split(".")[1] + "==="))
            expected = self.target
            if (
                claims["iss"] != expected.issuer
                or claims["aud"] != expected.client_id
                or claims["token_use"] != "id"
                or not claims["sub"]
                or (previous and claims["sub"] != previous["subject"])
                or float(claims["exp"]) <= self.clock()
            ):
                raise ValueError()
            expires = min(float(claims["exp"]), self.clock() + float(response["expires_in"]))
            if (
                not math.isfinite(expires)
                or not math.isfinite(float(response["expires_in"]))
                or expires <= self.clock()
            ):
                raise ValueError()
            refresh = response.get("refresh_token") or (previous or {}).get("refresh_token")
            if not isinstance(refresh, str) or not refresh:
                raise ValueError()
        except (KeyError, ValueError, TypeError, IndexError, AttributeError):
            raise AuthError(
                "Provider token does not match the configured identity or client. No new session was saved."
            ) from None
        # Tokens arrive only from the configured TLS token endpoint; the API verifies signature and
        # permissions. Local decoded claims are display and binding only.
        record = {
            "subject": claims["sub"],
            "label": str(claims.get("email") or claims["sub"]),
            "refresh_token": refresh,
            "created_at": (previous or {}).get("created_at", self.clock()),
        }
        with self._hold():
            self.store.set(self.target.key, json.dumps(record))
        self._token, self._expires, self._subject = value, expires, record["subject"]
        return {"subject": record["subject"], "label": record["label"], "created_at": record["created_at"]}

    def login(self) -> dict:
        """Local browser sign-in on the target's loopback callback."""
        if not self.target.has_loopback_callback:
            raise AuthError("Local sign-in needs a loopback callback; this target's callback is not one.")
        state = secrets.token_urlsafe(32)
        verifier, challenge = pkce_pair()
        url = authorization_url(self.target, state=state, challenge=challenge, identity_provider=self.identity_provider)
        code = self.receive(self.target.callback_uri, url, state, 180.0)
        with self._hold():
            response = self.provider.post(
                self.target.token_endpoint,
                {
                    "grant_type": "authorization_code",
                    "client_id": self.target.client_id,
                    "code": code,
                    "redirect_uri": self.target.callback_uri,
                    "code_verifier": verifier,
                },
            )
            return self.store_token_set(response)

    def headers(self, endpoint):
        if endpoint != self.target.api_endpoint:
            raise AuthError("Endpoint does not match the signed-in target; sign in to the target that owns it.")
        with self._hold():
            record = self._record()  # Check even with a cached access token: local logout must win.
            if self._subject is not None and self._subject != record["subject"]:
                self._token = None  # Another process explicitly signed in as a different person.
            if not self._token or self._expires <= self.clock() + 60:
                try:
                    response = self.provider.post(
                        self.target.token_endpoint,
                        {
                            "grant_type": "refresh_token",
                            "client_id": self.target.client_id,
                            "refresh_token": record["refresh_token"],
                        },
                    )
                except OAuthError as error:
                    if error.code == "invalid_grant":
                        self.store.delete(self.target.key)
                        self._token = None
                    raise OAuthError(error.code, transient=error.transient, login_command=self.login_command) from None
                self.store_token_set(response, previous=record)
            return {"content-type": "application/json", "Authorization": self._token}

    def status(self) -> dict:
        try:
            record = self._record()
        except AuthError:
            # Locked or unavailable stores stay errors, never a fabricated signed-out state.
            if self.store.get(self.target.key) is not None:
                raise
            return {"signed_in": False}
        return {
            "signed_in": True,
            "subject": record["subject"],
            "label": record["label"],
            "access_expires_at": self._expires or None,
            "elapsed_session_seconds": max(0, self.clock() - record["created_at"]),
        }

    def logout(self) -> dict:
        remote = "not_needed"
        with self._hold():
            raw = self.store.get(self.target.key)
            try:
                if raw:
                    remote = "unconfirmed"
                    record = self._record()
                    self.provider.post(
                        self.target.revoke_endpoint,
                        {"client_id": self.target.client_id, "token": record["refresh_token"]},
                    )
                    remote = "confirmed"
            except AuthError:
                pass
            finally:
                self.store.delete(self.target.key)
                self._token = None
                self._expires = 0.0
        # An access token the API already accepted stays valid until it expires.
        return {"local_session_removed": True, "remote_revocation": remote}
