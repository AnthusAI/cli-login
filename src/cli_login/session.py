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
from .remote import RemoteLoginError, _claims
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
        api_token: str = "id",
        authorization_scheme: str | None = None,
    ):
        """``api_token`` names the token ``headers()`` hands to the API: ``"id"`` (Papyrus's AppSync) or ``"access"``
        (an API that checks Cognito access tokens, such as the Cyclotron lab). ``authorization_scheme`` prefixes it,
        for example ``"Bearer"``. The access token is only ever held in memory, never stored."""
        if api_token not in ("id", "access"):
            raise ValueError('api_token is "id" or "access"')
        if authorization_scheme not in (None, "Bearer"):
            raise ValueError('authorization_scheme is None or "Bearer"')
        self.target = target
        self.store = store if store is not None else open_store(target)
        self.provider = provider if provider is not None else HTTPProvider()
        self.clock = clock
        self.receive = receive
        self.state_dir = state_dir if state_dir is not None else default_state_dir(target.namespace)
        self.login_command = login_command
        self.identity_provider = identity_provider
        self.api_token = api_token
        self.authorization_scheme = authorization_scheme
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
            if self.api_token == "access":
                value = response["access_token"]
                access = json.loads(base64.urlsafe_b64decode(value.split(".")[1] + "==="))
                if (
                    access["iss"] != expected.issuer
                    or access["client_id"] != expected.client_id
                    or access["token_use"] != "access"
                    or access["sub"] != claims["sub"]
                ):
                    raise ValueError()
                expires = min(expires, float(access["exp"]))
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

    def login(self, *, prepare=None, enroll=None) -> dict:
        """Local browser sign-in on the target's loopback callback.

        For a product whose sign-in enrolls each login (the Cyclotron lab enrolls each Cognito login at Prospectus),
        two optional hooks mirror ``remote_login``'s ``enroll``:

        ``prepare(state)`` runs once ``state`` and PKCE exist, before the authorize URL is built. It gets the raw
        ``state`` and returns ``(nonce, enrollment)``. The nonce becomes the OpenID ``nonce`` authorize parameter, and
        the ID token must carry it back or nothing is saved. ``enrollment`` is opaque to this library.

        ``enroll(tokens, state, enrollment)`` runs after the token exchange and the nonce check, before anything is
        stored. If it raises, the tokens are discarded, the refresh token is revoked on a best-effort basis, and
        nothing is stored. With neither hook, sign-in is unchanged."""
        if not self.target.has_loopback_callback:
            raise AuthError("Local sign-in needs a loopback callback; this target's callback is not one.")
        state = secrets.token_urlsafe(32)
        verifier, challenge = pkce_pair()
        nonce = enrollment = None
        if prepare is not None:
            nonce, enrollment = prepare(state)
            if not isinstance(nonce, str) or not nonce:
                raise ValueError("prepare must return (nonce, enrollment) with a non-empty nonce string")
        url = authorization_url(
            self.target, state=state, challenge=challenge, identity_provider=self.identity_provider, nonce=nonce
        )
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
            if nonce is not None or enroll is not None:
                try:
                    if nonce is not None and _claims(response.get("id_token")).get("nonce") != nonce:
                        raise RemoteLoginError(
                            "nonce_mismatch", "The sign-in answered tokens for a different request; nothing was saved."
                        )
                    if enroll is not None:
                        enroll(response, state, enrollment)
                except BaseException:
                    self._revoke_quietly(response)
                    raise
            return self.store_token_set(response)

    def _revoke_quietly(self, response):
        """Best effort: an unsaved login must not leave a live refresh token behind."""
        try:
            refresh = response.get("refresh_token")
            if isinstance(refresh, str) and refresh:
                self.provider.post(self.target.revoke_endpoint, {"client_id": self.target.client_id, "token": refresh})
        except Exception:
            pass

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
            token = self._token if self.authorization_scheme is None else f"{self.authorization_scheme} {self._token}"
            return {"content-type": "application/json", "Authorization": token}

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
