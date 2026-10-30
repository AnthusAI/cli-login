import base64
import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from behave import given, then, when

from anthus_cli_login.broker import throttle
from anthus_cli_login.broker.handler import Broker, BrokerConfig, sha256_hex
from anthus_cli_login.broker.pages import CSRF_COOKIE, NONCE_COOKIE, ApprovalPages
from anthus_cli_login.broker.transactions import MemoryTransactions
from anthus_cli_login.remote import RemoteLoginError, remote_login

API = "https://api.example.test/graphql"
BROKER = "https://broker.example.test"
TOKEN = "https://auth.example.test/oauth2/token"
AUTHORIZE = "https://auth.example.test/oauth2/authorize"


@dataclass(frozen=True)
class Target:
    client_id: str = "client-1"
    api_endpoint: str = API
    broker_endpoint: str = BROKER
    token_endpoint: str = TOKEN
    remote_callback_uri: str | None = "https://app.example.test/cli/callback"


def jwt(claims):
    return "h." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".s"


class Product:
    """The broker, the product's approval pages and a fake sign-in provider, all in-process."""

    def __init__(self):
        self.now = 1000.0
        self.broker = Broker(
            MemoryTransactions(),
            BrokerConfig("client-1", (API,), "https://app.example.test/cli/approve", "https://app.example.test/cli/callback"),
            clock=lambda: self.now,
        )
        self.pages = ApprovalPages(self.broker.handle, authorize_endpoint=AUTHORIZE, product="Example", privileges="Act as you.")
        self.issued = {}  # authorization code -> (challenge, nonce) the provider issued it for
        self.wrong_nonce = False
        self.approver_email = "person@example.test"

    # the person's browser ------------------------------------------------------------------------------------

    def open_approval(self, url):
        transaction = parse_qs(urlsplit(url).query)["t"][0]
        page = self.pages.approve("GET", {"t": transaction}, {}, {})
        csrf = next((v.split(";")[0].split("=", 1)[1] for k, v in page.headers if k == "Set-Cookie" and v.startswith(CSRF_COOKIE)), None)
        return transaction, page, csrf

    def approve(self, url, *, other_browser=False):
        transaction, page, csrf = self.open_approval(url)
        if page.status != 200:
            return page
        page = self.pages.approve("POST", {}, {"t": transaction, "csrf": csrf, "action": "approve", "confirm": "yes"}, {CSRF_COOKIE: csrf})
        if page.status != 303:
            return page
        headers = dict(page.headers)
        nonce_cookie = next(v.split(";")[0].split("=", 1)[1] for k, v in page.headers if k == "Set-Cookie" and v.startswith(NONCE_COOKIE))
        authorize = {k: v[0] for k, v in parse_qs(urlsplit(headers["Location"]).query).items()}
        code = "code-" + str(len(self.issued))
        self.issued[code] = (authorize["code_challenge"], authorize["nonce"])
        cookies = {} if other_browser else {NONCE_COOKIE: nonce_cookie}
        return self.pages.callback({"state": authorize["state"], "code": code}, cookies)

    def deny(self, url):
        transaction, _, csrf = self.open_approval(url)
        return self.pages.approve("POST", {}, {"t": transaction, "csrf": csrf, "action": "deny"}, {CSRF_COOKIE: csrf})

    # the CLI's network ---------------------------------------------------------------------------------------

    def http(self, method, url, *, json_body=None, form=None, timeout=30):
        if url == BROKER + "/start":
            status, answer = self.broker.start(json_body, "198.51.100.1")
            return status, answer, {}
        if url == BROKER + "/poll":
            self.on_poll(self)
            status, answer = self.broker.poll(json_body, "198.51.100.1")
            return status, answer, {}
        if url == TOKEN:
            challenge, nonce = self.issued.get(form["code"], (None, None))
            proof = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode().rstrip("=")
            if challenge is None or proof != challenge:
                return 400, {"error": "invalid_grant"}, {}
            del self.issued[form["code"]]
            claims = {"nonce": "another" if self.wrong_nonce else nonce, "email": self.approver_email, "sub": "person-1"}
            return 200, {"id_token": jwt(claims), "access_token": "access-token",
                         "refresh_token": "refresh-token", "expires_in": 3600}, {}
        raise AssertionError(url)


def run_cli(context, on_poll):
    product = context.product
    fired = []

    def once(p):
        if not fired:
            fired.append(1)
            on_poll(p, context.printed[0].split()[5])

    product.on_poll = once
    context.printed, context.stored, context.error = [], [], None

    def sleep(seconds):
        product.now += seconds

    try:
        remote_login(Target(), context.stored.append, http=product.http, out=context.printed.append,
                     clock=lambda: product.now, sleep=sleep, host="cloud-box",
                     expected_email=getattr(context, "expected_email", None))
    except RemoteLoginError as error:
        context.error = error


@given("a product with a broker and its approval pages")
def step_product(context):
    context.product = Product()
    context.actions = []


@given("the CLI expects to be signed in as {email}")
def step_expect(context, email):
    context.expected_email = email


@when("the CLI starts a remote sign-in")
def step_start(context):
    context.actions = []


@when("{email} approves it first")
@when("{email} approves it")
def step_someone_approves(context, email):
    context.product.approver_email = email
    context.actions.append(lambda product, url: product.approve(url))
    finish(context)


@then("the CLI reports that someone else approved the sign-in")
def step_someone_else(context):
    assert context.error.code == "unexpected_identity"


@then("the CLI printed that it is signed in as {email}")
def step_signed_in_as(context, email):
    assert context.printed[-1] == f"Signed in as {email}."


def finish(context):
    def act(product, url):
        for action in context.actions:
            action(product, url)
    run_cli(context, act)


@when("the person approves it in their browser after checking the code")
def step_approve(context):
    context.actions.append(lambda product, url: product.approve(url))
    finish(context)


@when("the person denies it on the approval page")
def step_deny(context):
    context.actions.append(lambda product, url: product.deny(url))
    finish(context)


@when("nobody approves it for ten minutes")
def step_nobody(context):
    finish(context)


@when("someone else binds the link before the person approves")
def step_hijack(context):
    def hijack(product, url):
        transaction = parse_qs(urlsplit(url).query)["t"][0]
        product.broker.bind({"transaction": transaction, "nonce_hash": sha256_hex("attacker")})
    context.actions.append(hijack)


@when("the person tries to approve it")
def step_try_approve(context):
    context.actions.append(lambda product, url: setattr(context, "page", product.approve(url)))
    finish(context)


@when("the person approves it and the sign-in returns to a different browser")
def step_other_browser(context):
    def act(product, url):
        context.page = product.approve(url, other_browser=True)
        context.transaction = parse_qs(urlsplit(url).query)["t"][0]
    context.actions.append(act)
    finish(context)


@when("the person approves it but the sign-in provider answers tokens for a different nonce")
def step_wrong_nonce(context):
    context.product.wrong_nonce = True
    context.actions.append(lambda product, url: product.approve(url))
    finish(context)


@given("a remote sign-in that was approved and collected")
def step_collected(context):
    context.actions = [lambda product, url: setattr(context, "url", url) or product.approve(url)]
    finish(context)
    assert len(context.stored) == 1


@when("someone opens the same approval link")
def step_reopen(context):
    _, context.page, _ = context.product.open_approval(context.url)


@given("a remote sign-in the person has approved")
def step_approved_manually(context):
    product = context.product
    context.secret = "the-poll-secret"
    _, started = product.broker.start({
        "protocol": 1, "client_id": "client-1", "target": API, "code_challenge": "c" * 43, "code_challenge_method": "S256",
        "poll_secret_hash": sha256_hex(context.secret), "nonce": "n" * 16, "requester": {"host": "h", "version": "1"},
    }, "198.51.100.1")
    context.transaction = started["transaction"]
    product.approve(started["approval_url"])


@when("a poll without the poll secret asks for it")
def step_poll_without_secret(context):
    context.answer = context.product.broker.poll({"transaction": context.transaction, "poll_secret": "guess"}, "203.0.113.5")


@when("a CLI starts a remote sign-in for another target")
def step_other_target(context):
    context.answer = context.product.broker.start({
        "protocol": 1, "client_id": "client-1", "target": "https://other.example.test", "code_challenge": "c" * 43,
        "code_challenge_method": "S256", "poll_secret_hash": sha256_hex("p"), "nonce": "n" * 16,
        "requester": {"host": "h", "version": "1"},
    }, "198.51.100.1")


@when("one caller starts more sign-ins than the broker allows in a minute")
def step_too_many(context):
    body = {"protocol": 1, "client_id": "client-1", "target": API, "code_challenge": "c" * 43, "code_challenge_method": "S256",
            "poll_secret_hash": sha256_hex("p"), "nonce": "n" * 16, "requester": {"host": "h", "version": "1"}}
    event = {"rawPath": "/start", "body": json.dumps(body), "requestContext": {"http": {"method": "POST", "sourceIp": "198.51.100.9"}}}
    answers = [context.product.broker.handle(event) for _ in range(throttle.START.calls + 1)]
    context.answer = answers[-1]


@then("the CLI stores one session")
def step_stored(context):
    assert context.error is None, context.error
    assert len(context.stored) == 1 and context.stored[0]["refresh_token"] == "refresh-token"


@then("the CLI printed only the approval URL and the matching code")
def step_printed(context):
    printed = "\n".join(context.printed)
    assert re.search(r"open https://app\.example\.test/cli/approve\?t=\S+", printed)
    assert re.search(r"code [B-Z]{4}-[B-Z]{4}\.", printed)
    for secret in ("access-token", "refresh-token", "code-0"):
        assert secret not in printed


@then("no session is stored")
def step_nothing(context):
    assert context.stored == []


@then("the CLI reports that the sign-in was denied")
def step_denied(context):
    assert context.error.code == "access_denied"


@then("the CLI reports that the approval link expired")
def step_expired(context):
    assert context.error.code == "expired_token"


@then("the CLI reports that the tokens were for a different request")
def step_nonce(context):
    assert context.error.code == "nonce_mismatch"


@then("the page says the link is no longer valid")
def step_gone(context):
    assert context.page.status == 410, context.page.status


@then("the callback page refuses it")
def step_refused(context):
    assert context.page.status == 400


@then("the broker holds no code for the sign-in")
def step_no_code(context):
    item = context.product.broker.store.get(context.transaction)
    assert item is None or not item.get("code")


@then("that poll is told the sign-in does not exist")
def step_told_missing(context):
    assert context.answer[1]["error"] == "expired_token"


@then("the CLI's own poll receives the code exactly once")
def step_once(context):
    broker = context.product.broker
    context.product.now += 10
    first = broker.poll({"transaction": context.transaction, "poll_secret": context.secret}, "198.51.100.1")
    context.product.now += 10
    second = broker.poll({"transaction": context.transaction, "poll_secret": context.secret}, "198.51.100.1")
    assert first[0] == 200 and first[1]["code"]
    assert second[1]["error"] == "expired_token"


@then("the broker refuses to start it")
def step_refused_start(context):
    assert context.answer[1]["error"] == "invalid_target"


@then("the broker refuses the extra one and says when to retry")
def step_retry(context):
    assert context.answer["statusCode"] == 429 and context.answer["headers"]["retry-after"] == "60"
