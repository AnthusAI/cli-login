"""Steps shared by every store feature. A Given sets ``context.store`` and ``context.make_store(namespace)``."""

from behave import then, when

from cli_login.errors import AuthError, StoreUnavailable


@when('the session "{value}" is saved under the key "{key}"')
def save(context, value, key):
    context.store.set(key, value)


@when('the key "{key}" is deleted')
def delete(context, key):
    context.store.delete(key)


@then('reading "{key}" returns "{value}"')
def returns(context, key, value):
    assert context.store.get(key) == value


@then('a store for the namespace "{namespace}" reading "{key}" returns nothing')
def other_namespace(context, namespace, key):
    assert context.make_store(namespace).get(key) is None


@then('it is unavailable with guidance mentioning "{text}"')
def unavailable(context, text):
    assert isinstance(context.error, StoreUnavailable), context.error
    assert text in str(context.error), str(context.error)


@then("the guidance contains no backend text")
def no_backend_text(context):
    assert "secret-value" not in str(context.error)


@then('reading "{key}" fails with guidance mentioning "{text}"')
def read_fails(context, key, text):
    try:
        context.store.get(key)
    except AuthError as error:
        assert text in str(error) and "secret-value" not in str(error), str(error)
    else:
        raise AssertionError("expected failure")

