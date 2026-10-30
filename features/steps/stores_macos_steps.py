from behave import given, then, when

from cli_login.errors import AuthError
from cli_login.stores.macos import MacOSKeychain, MacOSKeychainStore


class FakeKeychain(MacOSKeychain):
    def __init__(self, items=None, broken=False):
        self.items = dict(items or {})
        self.broken = broken

    def get_password(self, service, account):
        if self.broken:
            raise RuntimeError("raw failure naming secret-value")
        return self.items.get((service, account))


@given('a Keychain holding a session under service "{service}" and key "{key}"')
def holding(context, service, key):
    context.keychain = FakeKeychain({(service, key): "stored-session"})


@given("a Keychain that cannot be read")
def broken(context):
    context.keychain = FakeKeychain(broken=True)


@when('a store is opened for the namespace "{namespace}"')
def opened(context, namespace):
    context.store = MacOSKeychainStore(namespace, context.keychain)


@then('reading "{key}" returns that session')
def returns(context, key):
    assert context.store.get(key) == "stored-session"


@then('reading "{key}" returns nothing')
def nothing(context, key):
    assert context.store.get(key) is None


@then("reading fails with recovery guidance and no secret text")
def fails(context):
    try:
        context.store.get("k")
    except AuthError as error:
        assert "unlock" in str(error) and "secret-value" not in str(error)
    else:
        raise AssertionError("expected failure")
