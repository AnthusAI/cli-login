import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass

import pytest

from anthus_cli_login.broker.handler import Broker, BrokerConfig, sha256_hex
from anthus_cli_login.broker.transactions import MemoryTransactions
from anthus_cli_login.remote import RemoteLoginError, remote_login

API = "https://api.example.test/graphql"
BROKER = "https://broker.example.test"
TOKEN = "https://auth.example.test/oauth2/token"


@dataclass(frozen=True)
class Target:
    client_id: str = "client-1"
    api_endpoint: str = API
    broker_endpoint: str | None = BROKER
    token_endpoint: str = TOKEN


def jwt(claims):
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{body}.signature"


class World:
    """A real broker in-process, an approver who acts on the Nth poll, and a fake token endpoint."""

    def __init__(self, *, approve_on_poll=2, deny=False):
        self.now = 1000.0
        self.broker = Broker(
            MemoryTransactions(),
            BrokerConfig("client-1", (API,), "https://app.example.test/cli/approve", "https://app.example.test/cli/callback"),
            clock=lambda: self.now,
        )
        self.approve_on_poll, self.deny = approve_on_poll, deny
        self.polls, self.exchanges, self.printed, self.transaction = 0, [], [], None
        self.issued_nonce = None

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def approver(self):
        described = self.broker.describe({"transaction": self.transaction})
        self.issued_nonce = described["nonce"]
        self.challenge = described["code_challenge"]
        if self.deny:
            self.broker.deny({"transaction": self.transaction})
            return
        self.broker.bind({"transaction": self.transaction, "nonce_hash": sha256_hex("browser")})
        self.broker.complete({"transaction": self.transaction, "nonce": "browser", "code": "auth-code"})

    def http(self, method, url, *, json_body=None, form=None, timeout=30):
        if url == BROKER + "/start":
            status, answer = self.broker.start(json_body, "198.51.100.1")
            self.transaction = answer.get("transaction")
            return status, answer, {}
        if url == BROKER + "/poll":
            self.polls += 1
            if self.polls == self.approve_on_poll:
                self.approver()
            status, answer = self.broker.poll(json_body, "198.51.100.1")
            return status, answer, {}
        if url == TOKEN:
            self.exchanges.append(form)
            verifier_ok = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=") == self.challenge
            if form["code"] != "auth-code" or not verifier_ok:
                return 400, {"error": "invalid_grant"}, {}
            return 200, {"id_token": jwt({"nonce": self.issued_nonce}), "access_token": "access", "refresh_token": "refresh", "expires_in": 3600}, {}
        raise AssertionError(url)

    def login(self, target=None, stored=None):
        target = target or Target()
        stored = [] if stored is None else stored
        return remote_login(target, lambda tokens: stored.append(tokens) or "record", http=self.http, out=self.printed.append,
                            clock=self.clock, sleep=self.sleep, host="cloud-box")


def test_an_approved_remote_sign_in_stores_the_token_response_once():
    world, stored = World(), []
    assert world.login(stored=stored) == "record"
    assert len(stored) == 1 and stored[0]["refresh_token"] == "refresh"
    exchange = world.exchanges[0]
    assert exchange["redirect_uri"] == "https://app.example.test/cli/callback" and exchange["grant_type"] == "authorization_code"


def test_only_the_approval_url_and_matching_code_are_printed():
    world = World()
    world.login()
    printed = "\n".join(world.printed)
    assert "https://app.example.test/cli/approve?t=" in printed
    assert re.search(r"code [B-Z]{4}-[B-Z]{4}\.", printed)
    for secret in (world.exchanges[0]["code_verifier"], "auth-code", "refresh", "access"):
        assert secret not in printed


def test_a_denied_sign_in_stores_nothing():
    world, stored = World(deny=True), []
    with pytest.raises(RemoteLoginError) as raised:
        world.login(stored=stored)
    assert raised.value.code == "access_denied" and stored == []


def test_an_approval_that_never_comes_expires():
    world, stored = World(approve_on_poll=10_000), []
    with pytest.raises(RemoteLoginError) as raised:
        world.login(stored=stored)
    assert raised.value.code == "expired_token" and stored == []


def test_tokens_for_another_request_are_refused_and_nothing_is_stored():
    world, stored = World(), []
    original = world.http

    def swapped(method, url, **kwargs):
        status, body, headers = original(method, url, **kwargs)
        if url == TOKEN and status == 200:
            body["id_token"] = jwt({"nonce": "someone-elses"})
        return status, body, headers

    world.http = swapped
    with pytest.raises(RemoteLoginError) as raised:
        world.login(stored=stored)
    assert raised.value.code == "nonce_mismatch" and stored == []


def test_slow_down_lengthens_the_interval():
    world = World(approve_on_poll=4)
    intervals = []
    original_sleep = world.sleep

    def sleep(seconds):
        intervals.append(seconds)
        if len(intervals) == 2:  # poll again too soon once
            seconds = 1
        original_sleep(seconds)

    world.sleep = sleep
    world.login()
    assert max(intervals) > 5


def test_a_network_failure_while_polling_is_retried():
    world = World(approve_on_poll=3)
    original, failed = world.http, []

    def flaky(method, url, **kwargs):
        if url.endswith("/poll") and not failed:
            failed.append(1)
            raise OSError("reset")
        return original(method, url, **kwargs)

    world.http = flaky
    assert world.login() == "record"


def test_a_failed_exchange_is_not_retried():
    world, stored = World(), []
    original = world.http

    def broken(method, url, **kwargs):
        if url == TOKEN:
            raise OSError("reset")
        return original(method, url, **kwargs)

    world.http = broken
    with pytest.raises(RemoteLoginError) as raised:
        world.login(stored=stored)
    assert raised.value.code == "exchange_uncertain" and stored == []


def test_a_target_without_a_broker_cannot_sign_in_remotely():
    with pytest.raises(RemoteLoginError) as raised:
        World().login(target=Target(broker_endpoint=None))
    assert raised.value.code == "remote_unavailable"


def test_a_broker_that_is_not_https_is_refused():
    with pytest.raises(RemoteLoginError):
        World().login(target=Target(broker_endpoint="http://broker.example.test"))


def test_a_rate_limited_start_says_to_wait():
    world = World()
    world.http = lambda method, url, **kwargs: (429, {"error": "too_many_requests"}, {})
    with pytest.raises(RemoteLoginError) as raised:
        world.login()
    assert raised.value.transient and raised.value.code == "too_many_requests"


@pytest.mark.skipif(sys.platform == "win32", reason="locks are POSIX only until the Windows story")
def test_a_remote_sign_in_is_saved_by_the_session_under_the_targets_key(tmp_path):
    from anthus_cli_login.session import Session
    from anthus_cli_login.testing import FakeClock, FakeStore, make_id_token, make_target

    world = World()
    target = make_target(api_endpoint=API, broker_endpoint=BROKER, token_endpoint=TOKEN,
                         callback_uri="https://app.example.test/cli/callback")
    clock, store = FakeClock(world.now), FakeStore()
    session = Session(target, store=store, clock=clock, state_dir=tmp_path)
    original = world.http

    def provider(method, url, **kwargs):
        status, body, headers = original(method, url, **kwargs)
        if url == TOKEN and status == 200:
            claims = json.loads(base64.urlsafe_b64decode(make_id_token(clock()).split(".")[1] + "==="))
            body["id_token"] = jwt({**claims, "nonce": world.issued_nonce})
        return status, body, headers

    world.http = provider
    record = remote_login(target, session.store_token_set, http=world.http, out=world.printed.append,
                          clock=world.clock, sleep=world.sleep, host="cloud-box")
    assert record["subject"] == "person-1"
    assert store.data and "refresh" in json.dumps(list(store.data.values()))


def test_a_broker_callback_that_differs_from_the_targets_is_refused():
    from anthus_cli_login.testing import make_target

    target = make_target(api_endpoint=API, broker_endpoint=BROKER, token_endpoint=TOKEN,
                         callback_uri="https://other.example.test/cli/callback")
    with pytest.raises(RemoteLoginError) as raised:
        World().login(target=target)
    assert raised.value.code == "invalid_broker_answer"
