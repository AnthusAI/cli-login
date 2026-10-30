"""The broker template keeps its security-relevant properties. Read as text: CloudFormation tags need no YAML loader."""

import re
from pathlib import Path

TEMPLATE = (Path(__file__).parent / "broker.yaml").read_text()


def resource(name):
    match = re.search(rf"^  {name}:\n((?:    .*\n|\n)+)", TEMPLATE, re.MULTILINE)
    assert match, name
    return match.group(1)


def test_the_public_invoke_permission_only_covers_calls_through_the_function_url():
    public = resource("PublicUrlInvokePermission")
    assert 'Principal: "*"' in public and "InvokedViaFunctionUrl: true" in public


def test_only_the_products_role_may_invoke_the_private_operations():
    assert "Principal: !Ref InvokerRoleArn" in resource("PagesInvokePermission")
    assert TEMPLATE.count("Action: lambda:InvokeFunction\n") == 2


def test_the_function_url_takes_no_credentials_and_the_broker_is_bounded():
    assert "AuthType: NONE" in resource("BrokerUrl")
    broker = resource("Broker")
    assert "ReservedConcurrentExecutions: !Ref ReservedConcurrency" in broker and "LogGroup: !Ref BrokerLogs" in broker


def test_the_broker_may_only_read_and_write_its_own_table():
    assert "Resource: !GetAtt Transactions.Arn" in resource("BrokerRole")
    assert "AttributeName: expires_at" in resource("Transactions")
