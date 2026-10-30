import io
import urllib.error
from unittest.mock import patch

from behave import given, then, when

from anthus_cli_login.errors import AuthError, OAuthError
from anthus_cli_login.oauth import HTTPProvider


class Opener:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def open(self, request, timeout):
        raise urllib.error.HTTPError("https://x", self.status, "err", {}, io.BytesIO(self.body))


def serve(context, status, body=b"{}"):
    context.opener = Opener(status, body)


@given("a provider endpoint that redirects")
def redirects(context):
    serve(context, 302)


@given("a provider that answers invalid_grant")
def invalid_grant(context):
    serve(context, 400, b'{"error": "invalid_grant"}')


@given("a provider that answers with status 503")
def unavailable(context):
    serve(context, 503)


def post(context, url):
    context.error = None
    with patch("urllib.request.build_opener", return_value=context.opener):
        try:
            HTTPProvider().post(url, {"refresh_token": "secret-value"})
        except AuthError as error:
            context.error = error


@when("the tool posts a refresh request")
def refresh(context):
    post(context, "https://auth.example.test/oauth2/token")


@when("the tool posts to a plain HTTP endpoint")
def plain(context):
    context.opener = Opener(200, b"{}")
    post(context, "http://auth.example.test/oauth2/token")


@then("the request is rejected and the redirect is not followed")
def rejected(context):
    assert isinstance(context.error, AuthError) and not isinstance(context.error, OAuthError)


@then("the failure is a permanent session error")
def permanent(context):
    assert isinstance(context.error, OAuthError) and not context.error.transient


@then("the failure is transient")
def transient(context):
    assert context.error.transient


@then("the request is rejected")
def plain_rejected(context):
    assert isinstance(context.error, AuthError) and "HTTPS" in str(context.error)
