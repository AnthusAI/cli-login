"""The broker Lambda: hands one authorization code to the one CLI that asked for it, and never holds a token.

Two kinds of event reach it:

- **Function URL requests**: only ``POST /start`` and ``POST /poll``, called by the CLI directly. Each caller is
  rate-limited, and a CLI that polls one transaction too fast is told ``slow_down``.
- **Direct invocations** with IAM, from the product's own approval pages: ``describe``, ``bind``, ``complete``
  and ``deny``. They are never reachable through the function URL, so knowing a transaction id is not enough to
  attach a sign-in to it.

See docs/protocol.md for every request and answer.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .. import PROTOCOL_VERSION
from . import throttle
from .transactions import APPROVED, BOUND, DENIED, PENDING

LIFETIME_SECONDS = 600
INTERVAL_SECONDS = 5
SLOW_DOWN_SECONDS = 5
MATCHING_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"  # no vowels, so no words; no 0/O or 1/I to confuse
CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
HEX64 = re.compile(r"[0-9a-f]{64}")
NONCE = re.compile(r"[A-Za-z0-9_-]{16,128}")
TRANSACTION = re.compile(r"[A-Za-z0-9_-]{22}")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _https_url(value: str, name: str) -> str:
    parts = urlsplit(value or "")
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"{name} must be an https URL")
    return value


@dataclass(frozen=True)
class BrokerConfig:
    client_id: str
    targets: tuple[str, ...]
    approval_url: str
    callback_uri: str

    def __post_init__(self):
        if not self.client_id:
            raise ValueError("the broker serves exactly one client id")
        if not self.targets or not all(isinstance(t, str) and t for t in self.targets):
            raise ValueError("the broker needs the targets it may sign in to")
        _https_url(self.approval_url, "approval_url")
        _https_url(self.callback_uri, "callback_uri")

    @classmethod
    def from_environment(cls, environ=os.environ) -> BrokerConfig:
        return cls(
            client_id=environ.get("BROKER_CLIENT_ID", ""),
            targets=tuple(json.loads(environ.get("BROKER_TARGETS") or "[]")),
            approval_url=environ.get("BROKER_APPROVAL_URL", ""),
            callback_uri=environ.get("BROKER_CALLBACK_URI", ""),
        )


def _text(value: Any) -> str:
    """Display text from the requester: control characters removed, so a label cannot forge page structure."""
    if not isinstance(value, str):
        raise TypeError("requester fields are text")
    return "".join(ch for ch in value if unicodedata.category(ch)[0] != "C").strip()


def matching_code(randbelow=secrets.randbelow) -> str:
    letters = "".join(MATCHING_ALPHABET[randbelow(len(MATCHING_ALPHABET))] for _ in range(8))
    return letters[:4] + "-" + letters[4:]


class Broker:
    def __init__(self, store, config: BrokerConfig, *, clock=time.time, token=secrets.token_urlsafe, randbelow=secrets.randbelow):
        self.store, self.config = store, config
        self.clock, self.token, self.randbelow = clock, token, randbelow

    def now(self) -> int:
        return int(self.clock())

    # --- function URL ----------------------------------------------------------------------------------------

    def start(self, body: dict[str, Any], caller: str) -> tuple[int, dict[str, Any]]:
        if not throttle.allowed(self.store, "start", caller, throttle.START, self.now()):
            return 429, {"error": "too_many_requests", "retry_after": throttle.START.window_seconds}
        try:
            if body.get("protocol") != PROTOCOL_VERSION:
                return 400, {"error": "unsupported_protocol", "protocol": PROTOCOL_VERSION}
            if body.get("client_id") != self.config.client_id:
                return 400, {"error": "invalid_client"}
            if body.get("target") not in self.config.targets:
                return 400, {"error": "invalid_target"}
            if body.get("code_challenge_method") != "S256" or not CHALLENGE.fullmatch(str(body.get("code_challenge", ""))):
                return 400, {"error": "invalid_request", "field": "code_challenge"}
            if not HEX64.fullmatch(str(body.get("poll_secret_hash", ""))):
                return 400, {"error": "invalid_request", "field": "poll_secret_hash"}
            if not NONCE.fullmatch(str(body.get("nonce", ""))):
                return 400, {"error": "invalid_request", "field": "nonce"}
            requester = body.get("requester")
            if not isinstance(requester, dict) or set(requester) - {"host", "version", "note"}:
                return 400, {"error": "invalid_request", "field": "requester"}
            label = {key: _text(value) for key, value in requester.items()}
            if not label.get("host") or not label.get("version"):
                return 400, {"error": "invalid_request", "field": "requester"}
        except (ValueError, TypeError):
            return 400, {"error": "invalid_request"}
        now = self.now()
        item = {
            "id": self.token(16),
            "state": PENDING,
            "client_id": self.config.client_id,
            "target": body["target"],
            "code_challenge": body["code_challenge"],
            "poll_hash": body["poll_secret_hash"],
            "nonce": body["nonce"],
            "requester": label,
            "matching_code": matching_code(self.randbelow),
            "created_at": now,
            "expires_at": now + LIFETIME_SECONDS,
            "interval": INTERVAL_SECONDS,
        }
        if not self.store.create(item):
            return 503, {"error": "temporarily_unavailable"}
        return 200, {
            "protocol": PROTOCOL_VERSION,
            "transaction": item["id"],
            "matching_code": item["matching_code"],
            "approval_url": f"{self.config.approval_url}?t={item['id']}",
            "interval": INTERVAL_SECONDS,
            "expires_at": item["expires_at"],
        }

    def poll(self, body: dict[str, Any], caller: str) -> tuple[int, dict[str, Any]]:
        now = self.now()
        if not throttle.allowed(self.store, "poll", caller, throttle.POLL, now):
            return 429, {"error": "too_many_requests", "retry_after": throttle.POLL.window_seconds}
        transaction, secret = body.get("transaction"), body.get("poll_secret")
        if not isinstance(transaction, str) or not TRANSACTION.fullmatch(transaction) or not isinstance(secret, str):
            return 400, {"error": "invalid_request"}
        item = self.store.get(transaction)
        # A wrong poll secret reads exactly like a transaction that does not exist.
        if item is None or not hmac.compare_digest(item["poll_hash"], sha256_hex(secret)):
            return 400, {"error": "expired_token", "protocol": PROTOCOL_VERSION}
        if item["expires_at"] <= now:
            return 400, {"error": "expired_token", "protocol": PROTOCOL_VERSION}
        last = item.get("last_poll_at")
        if last is not None and now - last < item["interval"]:
            slower = item["interval"] + SLOW_DOWN_SECONDS
            self.store.transition(transaction, [PENDING, BOUND, APPROVED, DENIED], {"interval": slower, "last_poll_at": now},
                                  expect={"last_poll_at": last})
            return 400, {"error": "slow_down", "interval": slower, "protocol": PROTOCOL_VERSION}
        if item["state"] == APPROVED:
            taken = self.store.take(transaction)
            if taken is None:
                return 400, {"error": "expired_token", "protocol": PROTOCOL_VERSION}
            return 200, {"protocol": PROTOCOL_VERSION, "code": taken["code"], "redirect_uri": self.config.callback_uri}
        if item["state"] == DENIED:
            return 400, {"error": "access_denied", "protocol": PROTOCOL_VERSION}
        self.store.transition(transaction, [PENDING, BOUND], {"last_poll_at": now}, expect={"last_poll_at": last})
        return 400, {"error": "authorization_pending", "interval": item["interval"], "protocol": PROTOCOL_VERSION}

    # --- direct invocation (IAM) ------------------------------------------------------------------------------

    def _live(self, transaction: Any, states) -> dict[str, Any] | None:
        if not isinstance(transaction, str) or not TRANSACTION.fullmatch(transaction):
            return None
        item = self.store.get(transaction)
        if item is None or item["state"] not in states or item["expires_at"] <= self.now():
            return None
        return item

    def describe(self, event: dict[str, Any]) -> dict[str, Any]:
        item = self._live(event.get("transaction"), [PENDING])
        if item is None:
            return {"ok": False, "error": "unavailable"}
        return {
            "ok": True,
            "protocol": PROTOCOL_VERSION,
            "client_id": item["client_id"],
            "target": item["target"],
            "requester": item["requester"],
            "matching_code": item["matching_code"],
            "code_challenge": item["code_challenge"],
            "nonce": item["nonce"],
            "redirect_uri": self.config.callback_uri,
            "expires_at": item["expires_at"],
        }

    def bind(self, event: dict[str, Any]) -> dict[str, Any]:
        nonce_hash = event.get("nonce_hash")
        if self._live(event.get("transaction"), [PENDING]) is None or not HEX64.fullmatch(str(nonce_hash or "")):
            return {"ok": False, "error": "unavailable"}
        bound = self.store.transition(event["transaction"], [PENDING], {"state": BOUND, "nonce_hash": nonce_hash})
        return {"ok": True} if bound else {"ok": False, "error": "unavailable"}

    def complete(self, event: dict[str, Any]) -> dict[str, Any]:
        item = self._live(event.get("transaction"), [BOUND])
        nonce, code = event.get("nonce"), event.get("code")
        if item is None or not isinstance(nonce, str) or not isinstance(code, str) or not code:
            return {"ok": False, "error": "unavailable"}
        if not hmac.compare_digest(item["nonce_hash"], sha256_hex(nonce)):
            return {"ok": False, "error": "unavailable"}
        done = self.store.transition(item["id"], [BOUND], {"state": APPROVED, "code": code}, expect={"nonce_hash": item["nonce_hash"]})
        return {"ok": True} if done else {"ok": False, "error": "unavailable"}

    def deny(self, event: dict[str, Any]) -> dict[str, Any]:
        if self._live(event.get("transaction"), [PENDING, BOUND]) is None:
            return {"ok": False, "error": "unavailable"}
        denied = self.store.transition(event["transaction"], [PENDING, BOUND], {"state": DENIED})
        return {"ok": True} if denied else {"ok": False, "error": "unavailable"}

    # --- dispatch ---------------------------------------------------------------------------------------------

    def handle(self, event: dict[str, Any]) -> dict[str, Any]:
        http = (event.get("requestContext") or {}).get("http")
        if http is not None:
            return self._http(event, http)
        operation = {"describe": self.describe, "bind": self.bind, "complete": self.complete, "deny": self.deny}.get(
            event.get("operation")
        )
        return operation(event) if operation else {"ok": False, "error": "unknown_operation"}

    def _http(self, event: dict[str, Any], http: dict[str, Any]) -> dict[str, Any]:
        route = {"/start": self.start, "/poll": self.poll}.get(event.get("rawPath"))
        if http.get("method") != "POST" or route is None:
            return _response(404, {"error": "not_found"})
        try:
            raw = event.get("body") or ""
            if event.get("isBase64Encoded"):
                raw = base64.b64decode(raw).decode()
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return _response(400, {"error": "invalid_request"})
        if not isinstance(body, dict):
            return _response(400, {"error": "invalid_request"})
        status, answer = route(body, str(http.get("sourceIp") or "unknown"))
        return _response(status, answer)


def _response(status: int, body: dict[str, Any]) -> dict[str, Any]:
    headers = {"content-type": "application/json", "cache-control": "no-store"}
    if status == 429:
        headers["retry-after"] = str(body.get("retry_after", 60))
    return {"statusCode": status, "headers": headers, "body": json.dumps(body)}


_broker: Broker | None = None


def lambda_handler(event, context):  # pragma: no cover - wiring only; Broker is specified directly
    global _broker
    if _broker is None:
        import boto3

        from .transactions import DynamoTransactions

        _broker = Broker(DynamoTransactions(boto3.client("dynamodb"), os.environ["BROKER_TABLE"]), BrokerConfig.from_environment())
    return _broker.handle(event)
