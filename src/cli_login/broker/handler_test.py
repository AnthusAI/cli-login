import base64
import json

from cli_login.broker import throttle
from cli_login.broker.handler import Broker, BrokerConfig, matching_code, sha256_hex
from cli_login.broker.transactions import MemoryTransactions

CHALLENGE = "a" * 43
SECRET = "poll-secret-value"
NONCE = "nonce-nonce-nonce-1"


class Clock:
    def __init__(self, now=1000):
        self.now = now

    def __call__(self):
        return self.now


def broker(clock=None):
    config = BrokerConfig(
        client_id="client-1",
        targets=("https://app.example.test",),
        approval_url="https://app.example.test/cli/approve",
        callback_uri="https://app.example.test/cli/callback",
    )
    tokens = iter(f"{n:022d}" for n in range(1, 1000))
    return Broker(MemoryTransactions(), config, clock=clock or Clock(), token=lambda _n: next(tokens), randbelow=lambda n: 0)


def start_body(**overrides):
    body = {
        "protocol": 1,
        "client_id": "client-1",
        "target": "https://app.example.test",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "poll_secret_hash": sha256_hex(SECRET),
        "nonce": NONCE,
        "requester": {"host": "cloud-box", "version": "1.2.3", "note": "nightly report"},
    }
    body.update(overrides)
    return body


def started(b):
    status, answer = b.start(start_body(), "198.51.100.1")
    assert status == 200
    return answer["transaction"]


def approve(b, transaction, nonce="browser-nonce", code="auth-code"):
    assert b.bind({"transaction": transaction, "nonce_hash": sha256_hex(nonce)}) == {"ok": True}
    assert b.complete({"transaction": transaction, "nonce": nonce, "code": code}) == {"ok": True}


def test_start_answers_a_transaction_a_matching_code_and_the_approval_url():
    status, answer = broker().start(start_body(), "198.51.100.1")
    assert status == 200
    assert answer == {
        "protocol": 1,
        "transaction": "0000000000000000000001",
        "matching_code": "BBBB-BBBB",
        "approval_url": "https://app.example.test/cli/approve?t=0000000000000000000001",
        "interval": 5,
        "expires_at": 1600,
    }


def test_start_refuses_another_client_target_or_a_malformed_challenge():
    b = broker()
    assert b.start(start_body(client_id="other"), "ip")[1]["error"] == "invalid_client"
    assert b.start(start_body(target="https://elsewhere.example.test"), "ip")[1]["error"] == "invalid_target"
    assert b.start(start_body(code_challenge_method="plain"), "ip")[1]["field"] == "code_challenge"
    assert b.start(start_body(poll_secret_hash="plain-secret"), "ip")[1]["field"] == "poll_secret_hash"
    assert b.start(start_body(protocol=2), "ip")[1]["error"] == "unsupported_protocol"
    assert b.start(start_body(requester={"host": "h"}), "ip")[1]["field"] == "requester"


def test_requester_text_loses_control_characters():
    b = broker()
    transaction = b.start(start_body(requester={"host": "box\n<b>", "version": "1\x00.0"}), "ip")[1]["transaction"]
    assert b.describe({"transaction": transaction})["requester"] == {"host": "box<b>", "version": "1.0"}


def test_matching_codes_use_only_the_unambiguous_alphabet():
    code = matching_code()
    assert len(code) == 9 and code[4] == "-"
    assert set(code.replace("-", "")) <= set("BCDFGHJKLMNPQRSTVWXZ")


def test_start_is_rate_limited_per_caller():
    b = broker()
    answers = [b.start(start_body(), "198.51.100.1")[0] for _ in range(throttle.START.calls + 1)]
    assert answers[-1] == 429 and set(answers[:-1]) == {200}
    assert b.start(start_body(), "198.51.100.2")[0] == 200


def test_poll_is_pending_until_approval_and_then_hands_the_code_over_once():
    clock = Clock()
    b = broker(clock)
    transaction = started(b)
    assert b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")[1]["error"] == "authorization_pending"
    approve(b, transaction)
    clock.now += 5
    status, answer = b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")
    assert (status, answer) == (200, {"protocol": 1, "code": "auth-code", "redirect_uri": "https://app.example.test/cli/callback"})
    clock.now += 5
    assert b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")[1]["error"] == "expired_token"


def test_a_wrong_poll_secret_reads_like_a_missing_transaction():
    b = broker()
    transaction = started(b)
    approve(b, transaction)
    assert b.poll({"transaction": transaction, "poll_secret": "guess"}, "ip")[1]["error"] == "expired_token"
    assert b.poll({"transaction": "0" * 22, "poll_secret": SECRET}, "ip")[1]["error"] == "expired_token"


def test_polling_faster_than_the_interval_answers_slow_down_and_lengthens_it():
    clock = Clock()
    b = broker(clock)
    transaction = started(b)
    b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")
    clock.now += 1
    assert b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")[1] == {"error": "slow_down", "interval": 10, "protocol": 1}
    clock.now += 10
    assert b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")[1]["error"] == "authorization_pending"


def test_poll_is_rate_limited_per_caller():
    clock = Clock()
    b = broker(clock)
    statuses = []
    for _ in range(throttle.POLL.calls + 1):
        statuses.append(b.poll({"transaction": "0" * 22, "poll_secret": SECRET}, "203.0.113.9")[0])
    assert statuses[-1] == 429


def test_an_expired_transaction_yields_nothing():
    clock = Clock()
    b = broker(clock)
    transaction = started(b)
    approve(b, transaction)
    clock.now += 600
    assert b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")[1]["error"] == "expired_token"


def test_a_denied_transaction_yields_nothing():
    b = broker()
    transaction = started(b)
    assert b.deny({"transaction": transaction}) == {"ok": True}
    assert b.poll({"transaction": transaction, "poll_secret": SECRET}, "ip")[1]["error"] == "access_denied"
    assert b.bind({"transaction": transaction, "nonce_hash": sha256_hex("n")})["ok"] is False


def test_a_transaction_binds_once_and_completes_only_with_its_own_nonce():
    b = broker()
    transaction = started(b)
    assert b.bind({"transaction": transaction, "nonce_hash": sha256_hex("first")}) == {"ok": True}
    assert b.bind({"transaction": transaction, "nonce_hash": sha256_hex("second")})["ok"] is False
    assert b.complete({"transaction": transaction, "nonce": "second", "code": "attacker"})["ok"] is False
    assert b.complete({"transaction": transaction, "nonce": "first", "code": "real"}) == {"ok": True}
    assert b.complete({"transaction": transaction, "nonce": "first", "code": "again"})["ok"] is False


def test_describe_shows_a_pending_transaction_only():
    b = broker()
    transaction = started(b)
    described = b.describe({"transaction": transaction})
    assert described["matching_code"] == "BBBB-BBBB" and described["code_challenge"] == CHALLENGE
    assert described["nonce"] == NONCE and described["redirect_uri"] == "https://app.example.test/cli/callback"
    b.bind({"transaction": transaction, "nonce_hash": sha256_hex("n")})
    assert b.describe({"transaction": transaction}) == {"ok": False, "error": "unavailable"}


def function_url(path, body, method="POST", encoded=False):
    raw = json.dumps(body)
    return {
        "rawPath": path,
        "body": base64.b64encode(raw.encode()).decode() if encoded else raw,
        "isBase64Encoded": encoded,
        "requestContext": {"http": {"method": method, "sourceIp": "198.51.100.7"}},
    }


def test_the_function_url_serves_start_and_poll_only():
    b = broker()
    answer = b.handle(function_url("/start", start_body(), encoded=True))
    assert answer["statusCode"] == 200 and answer["headers"]["cache-control"] == "no-store"
    transaction = json.loads(answer["body"])["transaction"]
    assert b.handle(function_url("/poll", {"transaction": transaction, "poll_secret": SECRET}))["statusCode"] == 400
    for path in ("/bind", "/complete", "/describe", "/deny"):
        assert b.handle(function_url(path, {"transaction": transaction}))["statusCode"] == 404
    assert b.handle(function_url("/start", start_body(), method="GET"))["statusCode"] == 404


def test_a_function_url_request_cannot_reach_a_private_operation_through_its_body():
    b = broker()
    transaction = started(b)
    event = function_url("/start", {"operation": "bind", "transaction": transaction, "nonce_hash": sha256_hex("x")})
    event["operation"] = "bind"
    b.handle(event)
    assert b.describe({"transaction": transaction})["ok"] is True


def test_direct_invocations_dispatch_by_operation():
    b = broker()
    transaction = started(b)
    assert b.handle({"cli_login": "private-v1", "operation": "describe", "transaction": transaction})["ok"] is True
    assert b.handle({"cli_login": "private-v1", "operation": "unknown"}) == {"ok": False, "error": "unknown_operation"}


def test_a_private_operation_needs_its_marker_and_no_request_context():
    b = broker()
    transaction = started(b)
    assert b.handle({"operation": "describe", "transaction": transaction})["ok"] is False
    shaped = {"cli_login": "private-v1", "operation": "deny", "transaction": transaction, "requestContext": {}}
    assert b.handle(shaped)["statusCode"] == 404
    assert b.describe({"transaction": transaction})["ok"] is True


def test_ipv6_callers_share_a_bucket_per_64_and_ipv4_mapped_callers_count_as_ipv4():
    from cli_login.broker.handler import caller_bucket

    assert caller_bucket("2001:db8:1:2::1") == caller_bucket("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
    assert caller_bucket("2001:db8:1:3::1") != caller_bucket("2001:db8:1:2::1")
    assert caller_bucket("::ffff:198.51.100.7") == caller_bucket("198.51.100.7") == "198.51.100.7"
    assert caller_bucket("not-an-address") == "not-an-address"


def test_malformed_input_answers_400_rather_than_failing():
    b = broker()
    transaction = started(b)
    lone_surrogate = json.dumps({"transaction": transaction, "poll_secret": "\ud800"})
    event = function_url("/poll", {})
    event["body"] = lone_surrogate
    assert b.handle(event)["statusCode"] == 400
    deep = function_url("/start", {})
    deep["body"] = "[" * 100000 + "]" * 100000
    assert b.handle(deep)["statusCode"] == 400
    assert b.handle(function_url("/start", start_body(requester={"host": 5, "version": "1"})))["statusCode"] == 400


def test_a_request_over_the_stores_item_size_answers_400():
    class TooLarge(Exception):
        def __init__(self):
            super().__init__("too large")
            self.response = {"Error": {"Code": "ValidationException", "Message": "Item size has exceeded the maximum allowed size"}}

    b = broker()
    b.store.create = lambda item: (_ for _ in ()).throw(TooLarge())
    assert b.start(start_body(), "ip") == (400, {"error": "invalid_request", "field": "requester"})


def test_every_json_answer_forbids_sniffing():
    assert broker().handle(function_url("/start", start_body()))["headers"]["x-content-type-options"] == "nosniff"


def test_a_rate_limited_answer_says_when_to_retry():
    b = broker()
    for _ in range(throttle.START.calls):
        b.handle(function_url("/start", start_body()))
    answer = b.handle(function_url("/start", start_body()))
    assert answer["statusCode"] == 429 and answer["headers"]["retry-after"] == "60"


def test_the_config_requires_its_client_targets_and_https_pages():
    import pytest

    with pytest.raises(ValueError):
        BrokerConfig("", ("t",), "https://a.example.test/cli/approve", "https://a.example.test/cli/callback")
    with pytest.raises(ValueError):
        BrokerConfig("c", (), "https://a.example.test/cli/approve", "https://a.example.test/cli/callback")
    with pytest.raises(ValueError):
        BrokerConfig("c", ("t",), "http://a.example.test/cli/approve", "https://a.example.test/cli/callback")
    config = BrokerConfig.from_environment({
        "BROKER_CLIENT_ID": "c",
        "BROKER_TARGETS": '["https://a.example.test"]',
        "BROKER_APPROVAL_URL": "https://a.example.test/cli/approve",
        "BROKER_CALLBACK_URI": "https://a.example.test/cli/callback",
    })
    assert config.targets == ("https://a.example.test",)
