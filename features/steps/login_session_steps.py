import json
import tempfile

from behave import given, then, when

from cli_login.errors import AuthError, OAuthError
from cli_login.session import Session
from cli_login.testing import FakeClock, FakeProvider, FakeStore, make_id_token, make_target


def new_session(context, receive=None):
    return Session(
        context.target,
        store=context.store,
        provider=context.provider,
        clock=context.clock,
        receive=receive or context.receive,
        state_dir=context.state_dir,
        login_command="tool login",
    )


@given("a target with an isolated provider and secure store")
def isolated(context):
    temporary = tempfile.TemporaryDirectory()
    context.add_cleanup(temporary.cleanup)
    context.state_dir = temporary.name
    context.target = make_target()
    context.clock = FakeClock()
    context.store = FakeStore()
    context.provider = FakeProvider(context.clock)
    context.browsers = []

    def receive(callback, url, state, timeout):
        context.browsers.append("browser")
        context.authorize_url, context.state = url, state
        return "fixture-code"

    context.receive = receive
    context.session = new_session(context)


@given("the person has signed in")
def signed_in(context):
    context.session.login()
    context.browsers.clear()
    context.saved = context.store.get(context.target.key)


@when("the person completes the local sign-in")
def local_sign_in(context):
    context.identity = context.session.login()


@then("the tool reports the person's identity")
def identity(context):
    assert context.identity["subject"] == "person-1"


@then("the report contains no token")
def no_token(context):
    assert "refresh-secret" not in json.dumps(context.identity)


@then("the secure store holds the session")
def holds(context):
    assert json.loads(context.store.get(context.target.key))["subject"] == "person-1"


@when("a restarted tool is used after 25 simulated hours")
def restarted(context):
    context.clock.advance(25 * 3600)
    context.session = new_session(context, receive=lambda *a: context.browsers.append("unexpected browser"))
    context.session.headers(context.target.api_endpoint)


@then("it renews with the stored refresh token and opens no browser")
def renewed(context):
    assert context.provider.calls[-1][1]["grant_type"] == "refresh_token"
    assert context.browsers == []


@then("this evidence is labelled simulated rather than elapsed live testing")
def simulated(context):
    assert isinstance(context.clock, FakeClock)


def attempt_renewal(context):
    context.clock.advance(4000)
    context.session = new_session(context)
    try:
        context.session.headers(context.target.api_endpoint)
        context.error = None
    except AuthError as error:
        context.error = error


@when("the provider is unavailable at renewal time")
def unavailable(context):
    context.provider.failure = OAuthError("temporarily_unavailable", transient=True)
    attempt_renewal(context)


@then("the tool reports a temporary failure")
def temporary(context):
    assert context.error.transient


@then("the stored session is unchanged")
def unchanged(context):
    assert context.store.get(context.target.key) == context.saved


@when("the provider says the refresh token was revoked")
def revoked(context):
    context.provider.failure = OAuthError("invalid_grant")
    attempt_renewal(context)


@then("the tool asks the person to sign in again")
def asks(context):
    assert "tool login" in str(context.error)


@then("the stored session is removed")
def removed(context):
    assert context.store.get(context.target.key) is None


@when("the provider returns a token for a different subject")
def other_subject(context):
    context.provider.subject = "someone-else"
    attempt_renewal(context)


@then("nothing new is saved")
def nothing_new(context):
    assert isinstance(context.error, AuthError)
    assert context.store.get(context.target.key) == context.saved


@when("the provider returns a token for another issuer")
def other_issuer(context):
    response = {
        "id_token": make_id_token(context.clock(), issuer="https://evil.example.test"),
        "refresh_token": "refresh-secret",
        "expires_in": 3600,
    }
    try:
        context.session.store_token_set(response)
    except AuthError as error:
        context.error = error


@then("nothing is saved")
def nothing_saved(context):
    assert context.store.data == {} and "refresh-secret" not in str(context.error)


@when("the person signs out while the provider is unreachable")
def offline_logout(context):
    context.provider.revocation_failure = True
    context.logout = new_session(context).logout()


@when("the person signs out while the provider is reachable")
def online_logout(context):
    context.logout = new_session(context).logout()


@then("the local session is removed")
def local_removed(context):
    assert context.logout["local_session_removed"] and context.store.get(context.target.key) is None


@then("remote revocation is reported as unconfirmed")
def unconfirmed(context):
    assert context.logout["remote_revocation"] == "unconfirmed"


@then("remote revocation is reported as confirmed")
def confirmed(context):
    assert context.logout["remote_revocation"] == "confirmed"


@when("the secure store is locked")
def locked(context):
    context.store.locked = True
    context.calls_before = len(context.provider.calls)
    try:
        new_session(context).headers(context.target.api_endpoint)
    except AuthError as error:
        context.error = error


@then("asking for headers fails with recovery guidance")
def guidance(context):
    assert "unlock" in str(context.error)


@then("the provider is not contacted")
def not_contacted(context):
    assert len(context.provider.calls) == context.calls_before


@then("the sign-in request carries no nonce")
def carries_no_nonce(context):
    assert "nonce" not in context.authorize_url


@given("the product prepares an enrollment with a nonce")
def product_prepares(context):
    context.enroll_log = {}
    context.provider.nonce = "product-nonce"
    context.fail_enroll = False

    def prepare(state):
        context.enroll_log["prepare_state"] = state
        return "product-nonce", {"opaque": "enrollment"}

    def enroll(tokens, state, enrollment):
        context.enroll_log.update(state=state, enrollment=enrollment, stored=context.store.get(context.target.key))
        if context.fail_enroll:
            raise RuntimeError("enrollment failed")

    context.prepare, context.enroll = prepare, enroll

    def receive(callback, url, state, timeout):
        context.authorize_url, context.state = url, state
        return "fixture-code"

    context.session = Session(
        context.target,
        store=context.store,
        provider=context.provider,
        clock=context.clock,
        receive=receive,
        state_dir=context.state_dir,
        login_command="tool login",
    )


@given("the provider answers tokens for a different nonce")
def different_nonce(context):
    context.provider.nonce = "someone-elses-nonce"


@given("enrollment will fail")
def enrollment_fails(context):
    context.fail_enroll = True


@when("the person completes the local sign-in with enrollment")
def sign_in_with_enrollment(context):
    context.identity = context.session.login(prepare=context.prepare, enroll=context.enroll)


@when("the person tries the local sign-in with enrollment")
def try_sign_in_with_enrollment(context):
    try:
        context.session.login(prepare=context.prepare, enroll=context.enroll)
    except (AuthError, RuntimeError) as error:  # the scenario asserts which error
        context.refusal = error
        context.refusal_code = getattr(error, "code", None) or str(error)


@then("the sign-in request carries the product's nonce")
def carries_nonce(context):
    assert "nonce=product-nonce" in context.authorize_url


@then("enrollment ran with the raw state and the opaque enrollment")
def enrollment_ran(context):
    assert context.enroll_log["state"] == context.enroll_log["prepare_state"] == context.state
    assert context.enroll_log["enrollment"] == {"opaque": "enrollment"}


@then("the secure store held nothing while enrolling")
def nothing_while_enrolling(context):
    assert context.enroll_log["stored"] is None


@then('the sign-in is refused with "{code}"')
def refused_with(context, code):
    assert code in context.refusal_code


@then("the secure store holds no session")
def holds_no_session(context):
    assert context.store.get(context.target.key) is None


@then("the refresh token was revoked")
def refresh_revoked(context):
    url, fields = context.provider.calls[-1]
    assert url == context.target.revoke_endpoint and fields["token"].startswith("refresh-secret")
