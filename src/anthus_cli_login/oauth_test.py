import base64
import hashlib
import io
import urllib.error
import urllib.parse
from unittest.mock import patch

import pytest

from .errors import AuthError, OAuthError
from .oauth import HTTPProvider, _NoRedirect, authorization_url, pkce_pair
from .testing import make_target


def test_pkce_challenge_is_s256_of_the_verifier():
    verifier, challenge = pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert challenge == expected and "=" not in challenge


def test_authorization_url_carries_pkce_and_state_but_not_the_verifier():
    verifier, challenge = pkce_pair()
    url = authorization_url(make_target(), state="st", challenge=challenge, identity_provider="Google")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert url.startswith("https://auth.example.test/oauth2/authorize?")
    assert query["code_challenge"] == [challenge] and query["code_challenge_method"] == ["S256"]
    assert query["state"] == ["st"] and query["identity_provider"] == ["Google"]
    assert verifier not in url


def http_error(status, body=b"{}"):
    return urllib.error.HTTPError("https://x", status, "err", {}, io.BytesIO(body))


class Opener:
    def __init__(self, error):
        self.error = error

    def open(self, request, timeout):
        raise self.error


def post_with(error):
    with patch("urllib.request.build_opener", return_value=Opener(error)):
        return HTTPProvider().post("https://auth.example.test/oauth2/token", {"refresh_token": "secret-value"})


def test_invalid_grant_is_a_permanent_session_error():
    with pytest.raises(OAuthError) as caught:
        post_with(http_error(400, b'{"error": "invalid_grant"}'))
    assert caught.value.code == "invalid_grant" and not caught.value.transient


@pytest.mark.parametrize("status", [429, 500, 503])
def test_throttling_and_server_errors_are_transient(status):
    with pytest.raises(OAuthError) as caught:
        post_with(http_error(status))
    assert caught.value.transient


def test_network_failure_is_transient():
    with pytest.raises(OAuthError) as caught:
        post_with(OSError("down"))
    assert caught.value.transient


def test_other_rejections_are_not_retried_and_do_not_leak():
    with pytest.raises(AuthError) as caught:
        post_with(http_error(400, b'{"error": "invalid_client", "echo": "secret-value"}'))
    assert not isinstance(caught.value, OAuthError) and "secret-value" not in str(caught.value)


def test_redirects_are_refused():
    assert _NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example.test") is None


def test_plain_http_is_refused_before_any_request():
    with patch("urllib.request.build_opener") as build, pytest.raises(AuthError):
        HTTPProvider().post("http://auth.example.test/oauth2/token", {})
    build.assert_not_called()
