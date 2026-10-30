import errno

from behave import given, then, when

from cli_login.errors import StoreUnavailable
from cli_login.stores.kernel_keyring import KernelKeyringStore
from cli_login.testing import FakeKeyctl


def use(context, fake):
    context.fake = fake
    context.make_store = lambda namespace: KernelKeyringStore(namespace, backend=fake)


@given("a working kernel keyring")
def working(context):
    use(context, FakeKeyctl())


@given("a kernel keyring without persistent keyrings")
def no_persistent(context):
    use(context, FakeKeyctl(persistent=False))


@given("a kernel keyring blocked with {name}")
def blocked(context, name):
    use(context, FakeKeyctl(blocked=getattr(errno, name)))


@when('a kernel keyring store is opened for the namespace "{namespace}"')
def opened(context, namespace):
    context.store = context.make_store(namespace)


@when("a kernel keyring store is probed")
def probed(context):
    context.error = None
    context.store = context.make_store("example-product")
    try:
        context.store.probe()
    except StoreUnavailable as error:
        context.error = error


@then("the keyring holds {count:d} session")
@then("the keyring holds {count:d} sessions")
def holds(context, count):
    assert len(context.fake.keys) == count, context.fake.keys
