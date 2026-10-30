from .errors import AuthError, OAuthError


def test_oauth_error_is_an_auth_error_with_code_and_transience():
    error = OAuthError("invalid_grant", login_command="tool login")
    assert isinstance(error, AuthError) and isinstance(error, ValueError)
    assert error.code == "invalid_grant" and error.transient is False
    assert "tool login" in str(error)


def test_transient_oauth_error_says_to_retry():
    error = OAuthError("temporarily_unavailable", transient=True)
    assert error.transient and "retry" in str(error)
