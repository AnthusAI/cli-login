import json

import pytest

from .errors import AuthError, OAuthError
from .session import Session
from .testing import FakeClock, FakeProvider, FakeStore, make_id_token, make_target


@pytest.fixture
def world(tmp_path):
    clock, store = FakeClock(), FakeStore()
    provider = FakeProvider(clock)
    target = make_target()
    seen = {}

    def receive(callback, url, state, timeout):
        seen.update(callback=callback, url=url, state=state)
        return "one-time-code"

    def new(**kw):
        return Session(
            target,
            store=store,
            provider=provider,
            clock=clock,
            receive=kw.pop("receive", receive),
            state_dir=tmp_path / "state",
            login_command="tool login",
            **kw,
        )

    return target, clock, store, provider, seen, new


def test_login_exchanges_the_code_with_pkce_and_reports_no_token(world):
    target, _clock, store, provider, seen, new = world
    identity = new().login()
    fields = provider.calls[0][1]
    assert fields["code"] == "one-time-code" and fields["redirect_uri"] == target.callback_uri
    assert fields["code_verifier"] not in seen["url"]
    assert identity["subject"] == "person-1" and identity["created_at"] == 1000.0
    assert "refresh" not in json.dumps(identity)
    assert json.loads(store.get(target.key))["refresh_token"] == "refresh-secret-1"


def test_a_remote_style_callback_cannot_use_local_login(tmp_path):
    target = make_target(callback_uri="https://app.example.test/cli/callback")
    session = Session(target, store=FakeStore(), provider=FakeProvider(FakeClock()), state_dir=tmp_path)
    with pytest.raises(AuthError, match="loopback"):
        session.login()


def test_renewal_after_25_hours_in_a_fresh_process_needs_no_browser(world):
    target, clock, _store, provider, _seen, new = world
    new().login()
    clock.advance(25 * 3600)
    restarted = new(receive=lambda *a: pytest.fail("interactive login"))
    headers = restarted.headers(target.api_endpoint)
    assert headers["Authorization"] == make_id_token(clock())
    assert provider.calls[-1][1]["grant_type"] == "refresh_token"
    assert restarted.status()["elapsed_session_seconds"] == 25 * 3600


def test_a_cached_token_is_renewed_before_it_expires(world):
    target, clock, _store, provider, _seen, new = world
    session = new()
    session.login()
    calls = len(provider.calls)
    session.headers(target.api_endpoint)
    assert len(provider.calls) == calls  # still fresh
    clock.advance(3600 - 30)  # inside the 60 second renewal window
    session.headers(target.api_endpoint)
    assert len(provider.calls) == calls + 1


def test_refresh_rotation_is_saved_before_the_next_process_uses_it(world):
    target, clock, store, provider, _seen, new = world
    new().login()
    clock.advance(4000)
    new().headers(target.api_endpoint)
    rotated = json.loads(store.get(target.key))["refresh_token"]
    new().headers(target.api_endpoint)  # fresh process, cached nothing -> uses the rotated one
    clock.advance(4000)
    new().headers(target.api_endpoint)
    assert provider.calls[-1][1]["refresh_token"] != "refresh-secret-1"
    assert rotated.startswith("refresh-secret-")


def test_a_transient_error_keeps_the_session(world):
    target, clock, store, provider, _seen, new = world
    new().login()
    before = store.get(target.key)
    clock.advance(4000)
    provider.failure = OAuthError("temporarily_unavailable", transient=True)
    with pytest.raises(OAuthError) as caught:
        new().headers(target.api_endpoint)
    assert caught.value.transient and store.get(target.key) == before


def test_invalid_grant_clears_the_session_and_names_the_login_command(world):
    target, clock, store, provider, _seen, new = world
    new().login()
    clock.advance(4000)
    provider.failure = OAuthError("invalid_grant")
    with pytest.raises(OAuthError, match="tool login"):
        new().headers(target.api_endpoint)
    assert store.get(target.key) is None


def test_a_subject_mismatch_on_renewal_is_refused_and_nothing_is_saved(world):
    target, clock, store, provider, _seen, new = world
    new().login()
    before = store.get(target.key)
    clock.advance(4000)
    provider.subject = "someone-else"
    with pytest.raises(AuthError):
        new().headers(target.api_endpoint)
    assert store.get(target.key) == before


@pytest.mark.parametrize(
    "override",
    [{"issuer": "https://evil.example.test"}, {"audience": "other-client"}, {"token_use": "access"}, {"lifetime": -5}],
)
def test_store_token_set_refuses_a_mismatched_token_and_saves_nothing(world, override):
    _target, clock, store, _provider, _seen, new = world
    response = {"id_token": make_id_token(clock(), **override), "refresh_token": "refresh-secret", "expires_in": 3600}
    with pytest.raises(AuthError) as caught:
        new().store_token_set(response)
    assert store.data == {} and "refresh-secret" not in str(caught.value)


def test_store_token_set_keeps_the_previous_refresh_token_when_none_is_returned(world):
    target, clock, store, _provider, _seen, new = world
    previous = {"subject": "person-1", "label": "x", "refresh_token": "kept-refresh", "created_at": 5.0}
    response = {"id_token": make_id_token(clock()), "expires_in": 3600}
    result = new().store_token_set(response, previous=previous)
    assert result == {"subject": "person-1", "label": "person@example.test", "created_at": 5.0}
    assert json.loads(store.get(target.key))["refresh_token"] == "kept-refresh"


def test_store_token_set_works_inside_and_outside_the_lock(world):
    _target, clock, _store, _provider, _seen, new = world
    session = new()
    response = {"id_token": make_id_token(clock()), "refresh_token": "r", "expires_in": 3600}
    session.store_token_set(response)
    with session._hold():
        session.store_token_set(response)  # re-entrant: no deadlock


def test_headers_refuse_another_endpoint_before_any_request(world):
    _target, _clock, _store, provider, _seen, new = world
    new().login()
    calls = len(provider.calls)
    with pytest.raises(AuthError):
        new().headers("https://other.example.test/graphql")
    assert len(provider.calls) == calls


def test_logout_reports_confirmed_revocation(world):
    target, _clock, store, provider, _seen, new = world
    new().login()
    assert new().logout() == {"local_session_removed": True, "remote_revocation": "confirmed"}
    assert store.get(target.key) is None
    assert provider.calls[-1][0] == "https://auth.example.test/oauth2/revoke"


def test_logout_offline_is_honest(world):
    target, _clock, store, provider, _seen, new = world
    new().login()
    provider.revocation_failure = True
    assert new().logout() == {"local_session_removed": True, "remote_revocation": "unconfirmed"}
    assert store.get(target.key) is None


def test_logout_without_a_session_needs_no_revocation(world):
    assert world[5]().logout()["remote_revocation"] == "not_needed"


def test_logout_in_another_process_beats_a_cached_token(world):
    target, _clock, _store, _provider, _seen, new = world
    first = new()
    first.login()
    new().logout()
    with pytest.raises(AuthError, match="tool login"):
        first.headers(target.api_endpoint)


def test_a_locked_store_fails_closed_without_contacting_the_provider(world):
    target, _clock, store, provider, _seen, new = world
    new().login()
    calls = len(provider.calls)
    store.locked = True
    session = new()
    with pytest.raises(AuthError):
        session.headers(target.api_endpoint)
    with pytest.raises(AuthError):
        session.status()  # an unreadable store is an error, not "signed out"
    assert len(provider.calls) == calls


def test_status_when_signed_out(world):
    assert world[5]().status() == {"signed_in": False}


def test_tokens_never_appear_in_status_or_errors(world):
    target, clock, _store, provider, _seen, new = world
    new().login()
    clock.advance(4000)
    provider.failure = OAuthError("invalid_grant")
    session = new()
    with pytest.raises(AuthError) as caught:
        session.headers(target.api_endpoint)
    assert "refresh-secret" not in str(caught.value)
    provider.failure = None
    new().login()
    assert "refresh-secret" not in json.dumps(new().status())


def test_a_corrupt_stored_record_is_an_error_with_guidance(world):
    target, _clock, store, _provider, _seen, new = world
    store.data[target.key] = "not json"
    with pytest.raises(AuthError, match="tool login"):
        new().headers(target.api_endpoint)


def test_by_default_headers_hand_out_the_bare_id_token_exactly_as_in_0_1_0(world):
    target, _clock, _store, _provider, _seen, new = world
    session = new()
    session.login()
    headers = session.headers(target.api_endpoint)
    assert headers == {"content-type": "application/json", "Authorization": session._token}
    assert json.loads(__import__("base64").urlsafe_b64decode(headers["Authorization"].split(".")[1] + "==="))["token_use"] == "id"


def test_an_access_token_api_gets_the_access_token_with_its_scheme(world):
    target, _clock, _store, _provider, _seen, new = world
    session = new(api_token="access", authorization_scheme="Bearer")
    session.login()
    scheme, _, token = session.headers(target.api_endpoint)["Authorization"].partition(" ")
    claims = json.loads(__import__("base64").urlsafe_b64decode(token.split(".")[1] + "==="))
    assert scheme == "Bearer" and claims["token_use"] == "access" and claims["client_id"] == target.client_id


def test_the_access_token_is_never_stored(world):
    target, _clock, store, _provider, _seen, new = world
    session = new(api_token="access", authorization_scheme="Bearer")
    session.login()
    record = json.loads(store.data[target.key])
    assert set(record) == {"subject", "label", "refresh_token", "created_at"}
    assert session._token not in store.data[target.key]


@pytest.mark.parametrize("change", [{"client_id": "other"}, {"token_use": "id"}, {"issuer": "https://elsewhere.example.test/p"},
                                    {"subject": "someone-else"}])
def test_a_mismatched_access_token_is_refused_and_nothing_is_saved(world, change):
    from .testing import make_access_token

    _target, clock, store, _provider, _seen, new = world
    session = new(api_token="access")
    response = {"id_token": make_id_token(clock()), "access_token": make_access_token(clock(), **change),
                "refresh_token": "r", "expires_in": 3600}
    with pytest.raises(AuthError):
        session.store_token_set(response)
    assert store.data == {}


def test_a_short_lived_access_token_is_renewed_before_it_lapses(world):
    from .testing import make_access_token

    _target, clock, _store, _provider, _seen, new = world
    session = new(api_token="access")
    session.store_token_set({"id_token": make_id_token(clock()), "access_token": make_access_token(clock(), lifetime=300),
                             "refresh_token": "r", "expires_in": 3600})
    assert session._expires == clock() + 300


def test_a_session_names_only_known_token_choices():
    from .testing import make_target

    with pytest.raises(ValueError):
        Session(make_target(), store=FakeStore(), api_token="refresh")
    with pytest.raises(ValueError):
        Session(make_target(), store=FakeStore(), authorization_scheme="Basic")
