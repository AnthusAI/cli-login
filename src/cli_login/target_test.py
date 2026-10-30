import dataclasses

import pytest

from .errors import AuthError
from .target import Target
from .testing import make_target


def test_a_valid_target_normalises_the_oauth_origin():
    assert make_target(oauth_domain="https://auth.example.test/").oauth_domain == "https://auth.example.test"


def test_the_target_has_exactly_the_agreed_fields():
    assert list(Target.__dataclass_fields__) == [
        "issuer",
        "client_id",
        "oauth_domain",
        "token_endpoint",
        "api_endpoint",
        "key",
        "namespace",
        "callback_uri",
        "broker_endpoint",
        "remote_callback_uri",
    ]
    assert make_target().broker_endpoint is None
    assert make_target().remote_callback_uri is None


@pytest.mark.parametrize("field", ["issuer", "oauth_domain", "token_endpoint", "api_endpoint"])
def test_plain_http_endpoints_are_refused(field):
    with pytest.raises(AuthError):
        make_target(**{field: "http://insecure.example.test"})


BROKER = {
    "broker_endpoint": "https://broker.example.test/",
    "remote_callback_uri": "https://app.example.test/cli/callback",
}


def test_a_broker_target_carries_its_own_https_remote_callback():
    target = make_target(**BROKER)
    assert target.remote_callback_uri == "https://app.example.test/cli/callback"
    assert target.has_loopback_callback, "local sign-in keeps its loopback callback beside the remote one"


@pytest.mark.parametrize("field", ["broker_endpoint", "remote_callback_uri"])
def test_plain_http_broker_settings_are_refused(field):
    with pytest.raises(AuthError):
        make_target(**{**BROKER, field: "http://insecure.example.test/cli/callback"})


def test_a_broker_without_a_remote_callback_is_refused():
    with pytest.raises(AuthError, match="remote callback"):
        make_target(broker_endpoint="https://broker.example.test/")


def test_a_remote_callback_without_a_broker_is_refused():
    with pytest.raises(AuthError, match="broker"):
        make_target(remote_callback_uri="https://app.example.test/cli/callback")


def test_endpoints_with_credentials_query_or_fragment_are_refused():
    for bad in ("https://u:p@api.example.test/g", "https://api.example.test/g?x=1", "https://api.example.test/g#f"):
        with pytest.raises(AuthError):
            make_target(api_endpoint=bad)


def test_a_loopback_callback_needs_a_fixed_unprivileged_port():
    assert make_target(callback_uri="http://localhost:3001/").has_loopback_callback
    for bad in ("http://localhost/", "http://localhost:80/", "http://example.test:3001/", "http://0.0.0.0:3001/"):
        with pytest.raises(AuthError):
            make_target(callback_uri=bad)


def test_an_https_callback_is_allowed_for_remote_sign_in():
    target = make_target(callback_uri="https://app.example.test/cli/callback")
    assert not target.has_loopback_callback


def test_unsafe_key_or_namespace_is_refused():
    for field in ("key", "namespace"):
        with pytest.raises(AuthError):
            make_target(**{field: "../escape"})


def test_a_target_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        make_target().key = "other"
