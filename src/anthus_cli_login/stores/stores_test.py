import pytest

from ..errors import AuthError
from ..testing import make_target
from . import open_store


def test_an_unsupported_platform_fails_closed(monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    with pytest.raises(AuthError, match="plaintext"):
        open_store(make_target())
