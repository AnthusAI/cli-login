from urllib.parse import parse_qs, urlsplit

from cli_login.broker.handler import Broker, BrokerConfig, sha256_hex
from cli_login.broker.pages import CSRF_COOKIE, NONCE_COOKIE, ApprovalPages
from cli_login.broker.transactions import MemoryTransactions

AUTHORIZE = "https://auth.example.test/oauth2/authorize"


def world():
    broker = Broker(
        MemoryTransactions(),
        BrokerConfig("client-1", ("https://api.example.test",), "https://app.example.test/cli/approve", "https://app.example.test/cli/callback"),
        clock=lambda: 1000,
    )
    tokens = iter(f"token{n:02d}" for n in range(100))
    pages = ApprovalPages(broker.handle, authorize_endpoint=AUTHORIZE, product="Example", privileges="Read and write as you.",
                          identity_provider="Google", token=lambda _n: next(tokens))
    _, started = broker.start({
        "protocol": 1, "client_id": "client-1", "target": "https://api.example.test", "code_challenge": "c" * 43,
        "code_challenge_method": "S256", "poll_secret_hash": sha256_hex("p"), "nonce": "oidc-nonce-0000001",
        "requester": {"host": "cloud-box", "version": "1.0", "note": "<script>alert(1)</script>"},
    }, "198.51.100.1")
    return broker, pages, started["transaction"]


def cookie(page, name):
    for key, value in page.headers:
        if key == "Set-Cookie" and value.startswith(name + "="):
            return value.split(";")[0].split("=", 1)[1]
    return None


def header(page, name):
    return dict(page.headers)[name]


def test_the_approval_page_shows_the_request_and_escapes_requester_text():
    _, pages, transaction = world()
    page = pages.approve("GET", {"t": transaction}, {}, {})
    assert page.status == 200
    assert "cloud-box" in page.body and "https://api.example.test" in page.body and "Read and write as you." in page.body
    assert "<script>" not in page.body and "&lt;script&gt;" in page.body
    assert cookie(page, CSRF_COOKIE) == "token00"
    assert header(page, "X-Frame-Options") == "DENY" and header(page, "Cache-Control") == "no-store"


def test_an_unknown_or_used_link_shows_that_it_is_no_longer_valid():
    _, pages, _ = world()
    assert pages.approve("GET", {"t": "0" * 22}, {}, {}).status == 410


def test_approving_needs_the_csrf_cookie_and_the_code_confirmation():
    _, pages, transaction = world()
    pages.approve("GET", {"t": transaction}, {}, {})
    assert pages.approve("POST", {}, {"t": transaction, "csrf": "token00", "action": "approve", "confirm": "yes"}, {}).status == 403
    assert pages.approve("POST", {}, {"t": transaction, "csrf": "token00", "action": "approve"}, {CSRF_COOKIE: "token00"}).status == 400


def approved(pages, transaction):
    pages.approve("GET", {"t": transaction}, {}, {})
    return pages.approve("POST", {}, {"t": transaction, "csrf": "token00", "action": "approve", "confirm": "yes"}, {CSRF_COOKIE: "token00"})


def test_approving_binds_the_transaction_and_sends_the_browser_to_sign_in():
    broker, pages, transaction = world()
    page = approved(pages, transaction)
    assert page.status == 303
    location = urlsplit(header(page, "Location"))
    query = {key: value[0] for key, value in parse_qs(location.query).items()}
    assert f"{location.scheme}://{location.netloc}{location.path}" == AUTHORIZE
    assert query == {
        "client_id": "client-1", "response_type": "code", "redirect_uri": "https://app.example.test/cli/callback",
        "scope": "openid email profile", "state": f"{transaction}.token01", "nonce": "oidc-nonce-0000001",
        "code_challenge": "c" * 43, "code_challenge_method": "S256", "identity_provider": "Google",
    }
    assert cookie(page, NONCE_COOKIE) == "token01"
    assert broker.describe({"transaction": transaction})["ok"] is False  # bound: nobody else can approve it


def test_the_callback_hands_the_code_to_the_broker_only_from_the_approving_browser():
    broker, pages, transaction = world()
    approved(pages, transaction)
    state = f"{transaction}.token01"
    assert pages.callback({"state": state, "code": "auth-code"}, {}).status == 400
    assert pages.callback({"state": f"{transaction}.forged", "code": "auth-code"}, {NONCE_COOKIE: "forged"}).status == 410
    page = pages.callback({"state": state, "code": "auth-code"}, {NONCE_COOKIE: "token01"})
    assert page.status == 200 and "approved" in page.body
    assert broker.store.get(transaction)["code"] == "auth-code"


def test_cancelling_at_the_sign_in_provider_denies_the_transaction():
    broker, pages, transaction = world()
    approved(pages, transaction)
    page = pages.callback({"state": f"{transaction}.token01", "error": "access_denied"}, {NONCE_COOKIE: "token01"})
    assert "cancelled" in page.body
    assert broker.store.get(transaction)["state"] == "denied"


def test_deny_on_the_approval_page_denies_the_transaction():
    broker, pages, transaction = world()
    pages.approve("GET", {"t": transaction}, {}, {})
    pages.approve("POST", {}, {"t": transaction, "csrf": "token00", "action": "deny"}, {CSRF_COOKIE: "token00"})
    assert broker.store.get(transaction)["state"] == "denied"


def test_the_approval_page_allows_the_sign_in_provider_as_a_form_target_and_forbids_sniffing():
    _, pages, transaction = world()
    page = pages.approve("GET", {"t": transaction}, {}, {})
    csp = header(page, "Content-Security-Policy")
    assert "form-action 'self' https://auth.example.test;" in csp and "frame-ancestors 'none'" in csp
    assert header(page, "X-Content-Type-Options") == "nosniff"
    assert header(approved(pages, transaction), "Content-Security-Policy") == csp


def test_the_cookies_are_secure_prefixed_and_scoped():
    _, pages, transaction = world()
    page = pages.approve("GET", {"t": transaction}, {}, {})
    csrf = next(v for k, v in page.headers if k == "Set-Cookie")
    assert csrf.startswith("__Secure-") and "Secure" in csrf and "HttpOnly" in csrf and "SameSite=Strict" in csrf
    nonce = next(v for k, v in approved(pages, transaction).headers if k == "Set-Cookie" and v.startswith(NONCE_COOKIE))
    assert "Path=/cli/callback" in nonce and "SameSite=Lax" in nonce


def test_the_approval_page_says_the_cli_will_be_signed_in_as_the_approver():
    _, pages, transaction = world()
    assert "The CLI will be signed in as you." in pages.approve("GET", {"t": transaction}, {}, {}).body


def test_every_private_call_carries_the_marker():
    calls = []
    pages = ApprovalPages(lambda payload: calls.append(payload) or {"ok": False}, authorize_endpoint=AUTHORIZE, product="Example",
                          privileges="Act as you.")
    pages.approve("GET", {"t": "x"}, {}, {})
    assert calls and all(call["cli_login"] == "private-v1" for call in calls)
