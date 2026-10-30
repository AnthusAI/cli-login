"""PKCE, the authorization URL, the loopback callback receiver and the HTTP provider."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .errors import AuthError, OAuthError
from .target import Target, https_url


def pkce_pair() -> tuple[str, str]:
    """A fresh (verifier, S256 challenge) pair."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def authorization_url(
    target: Target,
    *,
    state: str,
    challenge: str,
    identity_provider: str | None = None,
    scope: str = "openid email profile",
) -> str:
    fields = {
        "response_type": "code",
        "client_id": target.client_id,
        "redirect_uri": target.callback_uri,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if identity_provider:
        fields["identity_provider"] = identity_provider
    return target.authorize_endpoint + "?" + urllib.parse.urlencode(fields)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class HTTPProvider:
    """Posts form fields to the configured provider. Redirects are refused: secrets go nowhere else."""

    def post(self, url: str, fields: dict[str, str]) -> dict[str, Any]:
        https_url(url, "OAuth endpoint")
        request = urllib.request.Request(
            url,
            data=urllib.parse.urlencode(fields).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            opener = urllib.request.build_opener(_NoRedirect())
            with opener.open(request, timeout=20) as response:
                raw = response.read(1024 * 1024)
            return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as error:
            try:
                code = json.loads(error.read(4096)).get("error")
            except (ValueError, AttributeError):
                code = None
            if code == "invalid_grant":
                raise OAuthError("invalid_grant") from None
            if error.code == 429 or error.code >= 500:
                raise OAuthError("temporarily_unavailable", transient=True) from None
            raise AuthError(
                "OAuth request rejected. Check the registered client and callback configuration; no provider payload was logged."
            ) from None
        except (OSError, urllib.error.URLError):
            raise OAuthError("temporarily_unavailable", transient=True) from None
        except (ValueError, TypeError):
            raise AuthError(
                "Sign-in provider returned an invalid response; retry without discarding your session."
            ) from None


def receive_code(callback_uri: str, authorization_url: str, state: str, timeout: float) -> str:
    """Open the browser and wait for the one authorization code on the loopback callback."""
    callback = urllib.parse.urlsplit(callback_uri)
    outcome: dict[str, str] = {}

    class Callback(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # The request URL contains the authorization code.

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            valid = (
                parsed.path == (callback.path or "/")
                and query.get("state") == [state]
                and ((len(query.get("code", [])) == 1 and bool(query["code"][0])) or len(query.get("error", [])) == 1)
            )
            self.send_response(200 if valid else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(
                b"Sign-in response received. You may close this page." if valid else b"Invalid sign-in response."
            )
            if valid:
                outcome.update(code=query.get("code", [""])[0], error="denied" if query.get("error") else "")

    class CallbackServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(min(5, timeout))
            return connection, address

    try:
        # Never resolve the registered host to pick an interface, and never bind a wildcard.
        server = CallbackServer(("127.0.0.1", callback.port), Callback)
    except OSError:
        raise AuthError(
            f"Sign-in needs local port {callback.port} for its callback, but it is already in use. "
            "Stop whatever is using it and run the login again."
        ) from None
    with server:
        server.timeout = min(0.25, timeout)
        if not webbrowser.open(authorization_url):
            raise AuthError("Could not open the system browser. Run the login in an interactive desktop session.")
        deadline = time.monotonic() + timeout
        while not outcome and time.monotonic() < deadline:
            server.handle_request()
    if not outcome:
        raise AuthError("Sign-in timed out. Run the login again.")
    if outcome.get("error") or not outcome.get("code"):
        raise AuthError("Sign-in was declined. No session was saved.")
    return outcome["code"]
