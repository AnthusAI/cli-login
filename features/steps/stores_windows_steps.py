from behave import given, then, when

from anthus_cli_login.errors import AuthError
from anthus_cli_login.stores.windows import WindowsCredentialStore
from anthus_cli_login.testing import FakeCredentialManager

OLD = "o" * 7000
NEW = "n" * 7000


@given("an empty Credential Manager")
def empty(context):
    context.fake = FakeCredentialManager()
    context.make_store = lambda namespace: WindowsCredentialStore(namespace, backend=context.fake)


@given("a Credential Manager that refuses access")
def refuses(context):
    context.fake = FakeCredentialManager(broken=True)
    context.make_store = lambda namespace: WindowsCredentialStore(namespace, backend=context.fake)


@when('a Windows store is opened for the namespace "{namespace}"')
def opened(context, namespace):
    context.store = context.make_store(namespace)


@when("a session of {size:d} characters is saved under the key \"{key}\"")
def save_long(context, size, key):
    context.long = ("abcdefghij" * (size // 10 + 1))[:size]
    context.store.set(key, context.long)


@when("a session of {size:d} two-byte characters is saved under the key \"{key}\"")
def save_wide(context, size, key):
    context.long = "é" * size
    context.store.set(key, context.long)


@when("a save of a different 7000-character session is interrupted after {writes:d} writes")
def interrupted(context, writes):
    context.old = context.long
    context.fake.fail_after_writes = context.fake.writes + writes
    try:
        context.store.set("key-1", "z" * 7000)
    except AuthError:
        pass
    context.fake.fail_after_writes = None


@when("one stored chunk is altered")
def alter(context):
    chunk = next(t for t in context.fake.items if "#" in t)
    context.fake.items[chunk] = b"x" * len(context.fake.items[chunk])


@then("reading \"{key}\" returns the long session")
def returns_long(context, key):
    assert context.store.get(key) == context.long


@then('reading "{key}" returns either the old or the new session, whole')
def old_or_new(context, key):
    assert context.store.get(key) in (context.old, "z" * 7000)


@then('the credential "{target}" exists')
def exists(context, target):
    assert target in context.fake.items


@then("the Credential Manager holds {count:d} credential")
@then("the Credential Manager holds {count:d} credentials")
def holds(context, count):
    assert len(context.fake.items) == count, sorted(context.fake.items)


@then("no credential holds more than {limit:d} bytes")
def limit(context, limit):
    assert all(len(blob) <= limit for blob in context.fake.items.values())


@then('reading "{key}" fails saying the session is damaged')
def damaged(context, key):
    try:
        context.store.get(key)
    except AuthError as error:
        assert "damaged" in str(error)
    else:
        raise AssertionError("expected failure")


@then('reading "{key}" fails with guidance and no secret text')
def fails(context, key):
    try:
        context.store.get(key)
    except AuthError as error:
        assert "retry" in str(error) and "access denied" not in str(error)
    else:
        raise AssertionError("expected failure")
