import sys

from behave import given, then, when

from cli_login.stores.secret_service import SecretServiceStore
from cli_login.testing import FakeSecretStorage


def use(context, fake):
    context.fake = fake
    context.make_store = lambda namespace: SecretServiceStore(namespace, module=fake)


@given("an unlocked Secret Service keyring")
def unlocked(context):
    use(context, FakeSecretStorage())


@given("a locked Secret Service keyring")
def locked(context):
    use(context, FakeSecretStorage(locked=True))


@given("a machine with no Secret Service")
def no_bus(context):
    use(context, FakeSecretStorage(no_bus=True))


@given("the secretstorage package is not installed")
def not_installed(context):
    context.make_store = lambda namespace: SecretServiceStore(namespace)
    context.hidden = sys.modules.pop("secretstorage", None)
    sys.modules["secretstorage"] = None  # makes `import secretstorage` raise ImportError
    context.add_cleanup(lambda: sys.modules.pop("secretstorage", None))
    context.add_cleanup(lambda: context.hidden and sys.modules.__setitem__("secretstorage", context.hidden))


@when('a Secret Service store is opened for the namespace "{namespace}"')
def opened(context, namespace):
    context.store = context.make_store(namespace)


@when("a Secret Service store is probed")
def probed(context):
    from cli_login.errors import StoreUnavailable

    context.error = None
    try:
        context.store = context.make_store("example-product")
        context.store.probe()
    except StoreUnavailable as error:
        context.error = error


@when("the keyring becomes locked")
def becomes_locked(context):
    context.fake.locked = True


@then('the keyring item is labelled "{label}"')
def labelled(context, label):
    assert context.fake.labels == [label]
