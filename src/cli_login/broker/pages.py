"""The approval and callback pages a product serves on its own domain, framework-neutral.

A product mounts ``ApprovalPages.approve`` at ``/cli/approve`` (GET and POST) and ``ApprovalPages.callback`` at
``/cli/callback`` (GET), turning each ``Page`` into its framework's response. ``invoke`` calls the product's broker
Lambda directly with IAM and returns its answer; the pages never reach the broker's function URL.

- ``/cli/approve`` shows who is asking, the matching code, the target and what the session can do. Approving
  needs the person to confirm the code matches, a CSRF check, and binds the transaction to a nonce N kept in a
  first-party cookie before sending the browser to the sign-in provider.
- ``/cli/callback`` checks that the state's N matches the cookie, then hands the code to the broker.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from .handler import PRIVATE_MARKER

# __Secure-: browsers accept these cookies only over HTTPS with the Secure attribute, so a plain-HTTP page or a
# sibling subdomain over HTTP cannot plant one.
CSRF_COOKIE = "__Secure-cli_login_csrf"
NONCE_COOKIE = "__Secure-cli_login_nonce"
COOKIE_SECONDS = 600


@dataclass
class Page:
    status: int
    body: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)


def _cookie(name: str, value: str, path: str, *, same_site: str, max_age: int = COOKIE_SECONDS) -> tuple[str, str]:
    return "Set-Cookie", f"{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; Secure; SameSite={same_site}"


def _cleared(name: str, path: str) -> tuple[str, str]:
    return _cookie(name, "", path, same_site="Lax", max_age=0)


def _headers(form_action: str = "'self'") -> list[tuple[str, str]]:
    # form-action also governs where the approve POST's 303 may go, so it must allow the sign-in provider's origin.
    return [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Security-Policy", f"default-src 'none'; style-src 'unsafe-inline'; form-action {form_action}; frame-ancestors 'none'"),
    ]


BASE_HEADERS = _headers()


def _document(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
        ".code{font-size:2rem;font-weight:700;letter-spacing:.15em;font-family:ui-monospace,monospace}"
        "dt{font-weight:600}dd{margin:0 0 .75rem;overflow-wrap:anywhere}.note{max-height:6rem;overflow:auto}button{font-size:1rem;padding:.5rem 1rem;margin-right:.5rem}</style>"
        f"</head><body>{body}</body></html>"
    )


def _message(status: int, title: str, text: str, headers=()) -> Page:
    return Page(status, _document(title, f"<h1>{html.escape(title)}</h1><p>{html.escape(text)}</p>"), [*BASE_HEADERS, *headers])


def _gone() -> Page:
    return _message(410, "This sign-in link is no longer valid", "It expired, was already used, or was denied. Start the sign-in again from the CLI.")


class ApprovalPages:
    def __init__(
        self,
        invoke: Callable[[dict], Mapping],
        *,
        authorize_endpoint: str,
        product: str,
        privileges: str,
        scope: str = "openid email profile",
        identity_provider: str | None = None,
        prepare: Callable[[str, Mapping], tuple[str, str]] | None = None,
        token=secrets.token_urlsafe,
    ):
        """``prepare(transaction, described)``, when given, runs on Approve before the bind and returns the OpenID
        nonce the sign-in must use and an opaque ``enrollment`` string for the product's own enrollment step (for
        example a central identity challenge's nonce and its sealed proof). The broker hands both to the CLI with
        the code; a CLI accepts the nonce only when it asked to enroll."""
        self.invoke, self.authorize_endpoint, self.product = (lambda payload: invoke({**payload, "cli_login": PRIVATE_MARKER})), authorize_endpoint, product
        parts = urlsplit(authorize_endpoint)
        self.form_action = f"'self' {parts.scheme}://{parts.netloc}"
        self.privileges, self.scope, self.identity_provider, self.token = privileges, scope, identity_provider, token
        self.prepare = prepare

    def approve(self, method: str, query: Mapping[str, str], form: Mapping[str, str], cookies: Mapping[str, str]) -> Page:
        if method == "GET":
            return self._show(query.get("t", ""))
        if method != "POST":
            return _message(405, "Not allowed", "Use the approval page.")
        csrf = form.get("csrf", "")
        if not csrf or not hmac.compare_digest(csrf, cookies.get(CSRF_COOKIE, "")):
            return _message(403, "This page expired", "Open the approval link again.")
        transaction = form.get("t", "")
        if form.get("action") == "deny":
            self.invoke({"operation": "deny", "transaction": transaction})
            return _message(200, "Sign-in denied", "The waiting CLI will not be signed in.", [_cleared(CSRF_COOKIE, "/cli/approve")])
        if form.get("action") != "approve" or form.get("confirm") != "yes":
            return _message(400, "Confirm the code", "Check that the code matches the one the CLI showed, then approve.")
        described = self.invoke({"operation": "describe", "transaction": transaction})
        if not described.get("ok"):
            return _gone()
        nonce = self.token(32)
        bind = {"operation": "bind", "transaction": transaction, "nonce_hash": hashlib.sha256(nonce.encode()).hexdigest()}
        oidc_nonce = described["nonce"]
        if self.prepare is not None:
            try:
                oidc_nonce, enrollment = self.prepare(transaction, described)
            except Exception:  # noqa: BLE001 - the product's enrollment service is unavailable: nothing is bound
                return _message(503, "Sign-in is unavailable", "Try the approval link again in a moment.")
            bind |= {"nonce": oidc_nonce, "enrollment": enrollment}
        if not self.invoke(bind).get("ok"):
            return _gone()
        query_string = {
            "client_id": described["client_id"],
            "response_type": "code",
            "redirect_uri": described["redirect_uri"],
            "scope": self.scope,
            "state": f"{transaction}.{nonce}",
            "nonce": oidc_nonce,
            "code_challenge": described["code_challenge"],
            "code_challenge_method": "S256",
        }
        if self.identity_provider:
            query_string["identity_provider"] = self.identity_provider
        return Page(303, "", [
            *_headers(self.form_action),
            ("Location", f"{self.authorize_endpoint}?{urlencode(query_string)}"),
            _cookie(NONCE_COOKIE, nonce, "/cli/callback", same_site="Lax"),
            _cleared(CSRF_COOKIE, "/cli/approve"),
        ])

    def _show(self, transaction: str) -> Page:
        described = self.invoke({"operation": "describe", "transaction": transaction})
        if not described.get("ok"):
            return _gone()
        csrf = self.token(32)
        requester = described.get("requester") or {}
        e = html.escape
        note = f"<dt>Note</dt><dd class=\"note\">{e(requester['note'])}</dd>" if requester.get("note") else ""
        body = (
            f"<h1>Approve a {e(self.product)} CLI sign-in?</h1>"
            "<p><strong>The CLI will be signed in as you.</strong> Approve only if you started this sign-in, or an agent "
            "you run asked you to, and the code below matches the one it showed you.</p>"
            f"<p>Code</p><p class=\"code\">{e(described['matching_code'])}</p>"
            f"<dl><dt>Requested by</dt><dd>{e(requester.get('host', ''))}, CLI {e(requester.get('version', ''))}</dd>{note}"
            f"<dt>Signs in to</dt><dd>{e(described['target'])}</dd>"
            f"<dt>It will be able to</dt><dd>{e(self.privileges)}</dd></dl>"
            "<form method=\"post\" action=\"/cli/approve\">"
            f"<input type=\"hidden\" name=\"t\" value=\"{e(transaction)}\"><input type=\"hidden\" name=\"csrf\" value=\"{e(csrf)}\">"
            "<p><label><input type=\"checkbox\" name=\"confirm\" value=\"yes\" required> "
            "This code matches the one the CLI showed</label></p>"
            "<button name=\"action\" value=\"approve\">Approve</button>"
            "<button name=\"action\" value=\"deny\" formnovalidate>Deny</button></form>"
        )
        return Page(200, _document(f"Approve a {self.product} CLI sign-in", body),
                    [*_headers(self.form_action), _cookie(CSRF_COOKIE, csrf, "/cli/approve", same_site="Strict")])

    def callback(self, query: Mapping[str, str], cookies: Mapping[str, str]) -> Page:
        transaction, _, nonce = query.get("state", "").partition(".")
        clear = [_cleared(NONCE_COOKIE, "/cli/callback")]
        if not transaction or not nonce or not hmac.compare_digest(nonce, cookies.get(NONCE_COOKIE, "")):
            return _message(400, "This sign-in could not be checked",
                            "Finish the sign-in in the same browser you approved it in, or start again from the CLI.", clear)
        if query.get("error") or not query.get("code"):
            self.invoke({"operation": "deny", "transaction": transaction})
            return _message(200, "Sign-in cancelled", "The waiting CLI will not be signed in.", clear)
        if not self.invoke({"operation": "complete", "transaction": transaction, "nonce": nonce, "code": query["code"]}).get("ok"):
            return _gone()
        return _message(200, "Sign-in approved", "You can close this page. The waiting CLI is signing in now.", clear)
