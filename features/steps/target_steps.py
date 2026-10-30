from behave import given, then

from cli_login.errors import AuthError
from cli_login.testing import make_target

BROKER = "https://broker.example.test/"
REMOTE = "https://app.example.test/cli/callback"


def _build(context, **fields):
    context.target, context.error = None, None
    try:
        context.target = make_target(**fields)
    except AuthError as error:
        context.error = error


@given("a target with a broker and an HTTPS remote callback")
def step_broker_and_remote(context):
    _build(context, broker_endpoint=BROKER, remote_callback_uri=REMOTE)


@given("a target with a broker and no remote callback")
def step_broker_only(context):
    _build(context, broker_endpoint=BROKER)


@given("a target with a remote callback and no broker")
def step_remote_only(context):
    _build(context, remote_callback_uri=REMOTE)


@given("a target with a broker and a plain HTTP remote callback")
def step_plain_http_remote(context):
    _build(context, broker_endpoint=BROKER, remote_callback_uri="http://app.example.test/cli/callback")


@then("the target is accepted")
def step_accepted(context):
    assert context.error is None and context.target is not None
    assert context.target.remote_callback_uri == REMOTE


@then("it keeps its loopback callback for local sign-in")
def step_keeps_loopback(context):
    assert context.target.has_loopback_callback


@then("the target is refused because it needs a remote callback")
def step_needs_remote(context):
    assert context.error is not None and "remote callback" in str(context.error)


@then("the target is refused because it needs a broker")
def step_needs_broker(context):
    assert context.error is not None and "broker" in str(context.error)


@then("the target is refused")
def step_refused(context):
    assert context.error is not None
