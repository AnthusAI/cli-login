"""Remote sign-in: a CLI with no browser gets a session that a person approves from another device.

The CLI keeps two secrets and sends only their hashes: the PKCE verifier V (the broker sees ``S256(V)``) and the
poll secret P (the broker sees ``sha256(P)``). The person opens the approval URL, checks the matching code and
signs in; the broker then holds an authorization code that is useless without V, and hands it only to a poll that
knows P. The CLI exchanges the code itself and passes the token response to the session store.

See docs/protocol.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from . import PROTOCOL_VERSION, __version__


class RemoteLoginError(ValueError):
    """A remote sign-in that did not finish. ``transient`` says whether trying again later may work.

    Matches the shape of ``errors.OAuthError`` (``code`` and ``transient``) until that module lands.
    """

    def __init__(self, code: str, message: str, *, transient: bool = False):
        super().__init__(message)
        self.code = code
        self.transient = transient


def default_http(method: str, url: str, *, json_body=None, form=None, timeout: float = 30) -> tuple[int, dict[str, Any], dict[str, str]]:
    """One HTTPS request; answers (status, JSON body, headers). Network failures raise OSError."""
    if json_body is not None:
        data, content_type = json.dumps(json_body).encode(), "application/json"
    else:
        data, content_type = urllib.parse.urlencode(form or {}).encode(), "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, method=method, headers={"content-type": content_type, "accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw, headers = response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        status, raw, headers = error.code, error.read(), dict(error.headers or {})
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        body = {}
    return status, body if isinstance(body, dict) else {}, {key.lower(): value for key, value in headers.items()}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _https(value: Any, what: str) -> str:
    parts = urllib.parse.urlsplit(value if isinstance(value, str) else "")
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise RemoteLoginError("invalid_broker_answer", f"The broker answered an unusable {what}.")
    return value


def _claims(token: Any) -> dict[str, Any]:
    """The payload of a JWT the CLI received straight from the token endpoint over TLS (no signature check here)."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (AttributeError, IndexError, ValueError):
        raise RemoteLoginError("invalid_token", "The sign-in provider answered an unreadable token.") from None


def remote_login(
    target,
    store_token_set: Callable[[Mapping[str, Any]], Any],
    *,
    http=default_http,
    out: Callable[[str], None] = print,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    host: str | None = None,
    note: str | None = None,
    token=secrets.token_urlsafe,
):
    """Sign in through the target's broker and return what ``store_token_set`` returns.

    ``target`` supplies ``client_id``, ``broker_endpoint``, ``token_endpoint`` and ``api_endpoint``, which names the
    binding to the broker and on the approval page. Nothing secret is printed: only the approval URL and the
    matching code.
    """
    broker = getattr(target, "broker_endpoint", None)
    if not broker:
        raise RemoteLoginError("remote_unavailable", "This target has no remote sign-in broker; sign in on a machine with a browser.")
    broker = _https(broker, "broker endpoint").rstrip("/")
    verifier, poll_secret, nonce = token(64), token(32), token(24)
    requester = {"host": host or socket.gethostname(), "version": __version__}
    if note:
        requester["note"] = note
    try:
        status, started, _ = http("POST", broker + "/start", json_body={
            "protocol": PROTOCOL_VERSION,
            "client_id": target.client_id,
            "target": target.api_endpoint,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
            "poll_secret_hash": hashlib.sha256(poll_secret.encode()).hexdigest(),
            "nonce": nonce,
            "requester": requester,
        })
    except OSError:
        raise RemoteLoginError("broker_unreachable", "The sign-in broker could not be reached; try again.", transient=True) from None
    if status == 429:
        raise RemoteLoginError("too_many_requests", "Too many sign-in attempts from this machine; wait a minute and try again.", transient=True)
    if status != 200 or started.get("protocol") != PROTOCOL_VERSION:
        raise RemoteLoginError(started.get("error") or "start_refused", "The sign-in broker refused to start a sign-in.")
    url = _https(started.get("approval_url"), "approval URL")
    transaction, code = started.get("transaction"), started.get("matching_code")
    if not isinstance(transaction, str) or not isinstance(code, str):
        raise RemoteLoginError("invalid_broker_answer", "The broker answered an unusable transaction.")
    interval, expires_at = max(int(started.get("interval") or 5), 1), int(started.get("expires_at") or clock() + 600)
    out(f"To approve this sign-in, open {url}\nand check that the page shows the code {code}.")

    while True:
        if clock() >= expires_at:
            raise RemoteLoginError("expired_token", "The approval link expired; start the sign-in again.")
        sleep(interval)
        try:
            status, answer, headers = http("POST", broker + "/poll", json_body={"transaction": transaction, "poll_secret": poll_secret})
        except OSError:
            continue  # polling is safe to repeat; the code is handed over only once, to a poll that knows P
        if status == 200:
            break
        error = answer.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval = max(int(answer.get("interval") or interval + 5), interval + 1)
        elif status == 429:
            sleep(float(headers.get("retry-after") or answer.get("retry_after") or 60))
        elif error == "access_denied":
            raise RemoteLoginError("access_denied", "The sign-in was denied on the approval page.")
        elif error == "expired_token":
            raise RemoteLoginError("expired_token", "The approval link expired or was already used; start the sign-in again.")
        elif status < 500:
            raise RemoteLoginError(error or "poll_refused", "The sign-in broker refused the sign-in.")

    authorization_code, redirect_uri = answer.get("code"), _https(answer.get("redirect_uri"), "redirect URI")
    if not isinstance(authorization_code, str) or not authorization_code:
        raise RemoteLoginError("invalid_broker_answer", "The broker answered without a code.")
    try:
        status, tokens, _ = http("POST", _https(target.token_endpoint, "token endpoint"), form={
            "grant_type": "authorization_code",
            "client_id": target.client_id,
            "code": authorization_code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        })
    except OSError:
        # The code is single use and may already be spent; a retry cannot be known to be safe, so start again.
        raise RemoteLoginError("exchange_uncertain", "The sign-in provider did not answer; start the sign-in again.") from None
    if status != 200:
        raise RemoteLoginError(str(tokens.get("error") or "exchange_refused"), "The sign-in provider refused the code; start the sign-in again.")
    if _claims(tokens.get("id_token")).get("nonce") != nonce:
        raise RemoteLoginError("nonce_mismatch", "The sign-in answered tokens for a different request; nothing was saved.")
    return store_token_set(tokens)
