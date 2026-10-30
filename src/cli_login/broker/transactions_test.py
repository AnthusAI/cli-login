import threading

import pytest

from cli_login.broker.transactions import (
    APPROVED,
    BOUND,
    DENIED,
    PENDING,
    DynamoTransactions,
    MemoryTransactions,
    _decode,
    _encode,
)


def pending(transaction_id="t1"):
    return {"id": transaction_id, "state": PENDING, "expires_at": 1600, "interval": 5}


def test_a_transaction_is_created_only_once():
    store = MemoryTransactions()
    assert store.create(pending())
    assert not store.create(pending())


def test_a_transition_happens_only_from_the_expected_state():
    store = MemoryTransactions()
    store.create(pending())
    assert store.transition("t1", [PENDING], {"state": BOUND, "nonce_hash": "h"})["state"] == BOUND
    assert store.transition("t1", [PENDING], {"state": BOUND, "nonce_hash": "other"}) is None
    assert store.get("t1")["nonce_hash"] == "h"


def test_a_transition_can_require_field_values():
    store = MemoryTransactions()
    store.create(pending())
    assert store.transition("t1", [PENDING], {"last_poll_at": 10}, expect={"last_poll_at": 5}) is None
    assert store.transition("t1", [PENDING], {"last_poll_at": 10}, expect={"last_poll_at": None})["last_poll_at"] == 10


def test_an_approved_code_is_taken_exactly_once_even_by_racing_callers():
    store = MemoryTransactions()
    store.create(pending())
    store.transition("t1", [PENDING], {"state": APPROVED, "code": "c"})
    results = []
    threads = [threading.Thread(target=lambda: results.append(store.take("t1"))) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert [r["code"] for r in results if r] == ["c"]
    assert store.get("t1") is None


def test_a_transaction_that_is_not_approved_cannot_be_taken():
    store = MemoryTransactions()
    store.create(pending())
    assert store.take("t1") is None
    store.transition("t1", [PENDING], {"state": DENIED})
    assert store.take("t1") is None


def test_calls_are_counted_per_key_and_window():
    store = MemoryTransactions()
    assert [store.count("start#a", 100, 60) for _ in range(3)] == [1, 2, 3]
    assert store.count("start#b", 100, 60) == 1
    assert store.count("start#a", 180, 60) == 1


def test_attributes_round_trip_through_the_dynamodb_encoding():
    value = {"s": "x", "n": 3, "b": True, "none": None, "m": {"inner": "y"}}
    assert {key: _decode(_encode(item)) for key, item in value.items()} == value
    with pytest.raises(TypeError):
        _encode(1.5)


class ConditionalCheckFailed(Exception):
    def __init__(self):
        super().__init__("conditional check failed")
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class RecordingClient:
    def __init__(self, fail=False, answer=None):
        self.calls, self.fail, self.answer = [], fail, answer or {}

    def __getattr__(self, name):
        def call(**kwargs):
            self.calls.append((name, kwargs))
            if self.fail:
                raise ConditionalCheckFailed()
            return self.answer
        return call


def test_the_dynamodb_store_creates_with_a_not_exists_condition():
    client = RecordingClient()
    assert DynamoTransactions(client, "table").create(pending())
    name, call = client.calls[0]
    assert name == "put_item" and call["ConditionExpression"] == "attribute_not_exists(pk)"
    assert call["Item"]["pk"] == {"S": "tx#t1"} and call["Item"]["expires_at"] == {"N": "1600"}
    assert not DynamoTransactions(RecordingClient(fail=True), "table").create(pending())


def test_the_dynamodb_store_conditions_a_transition_on_its_state_and_expected_fields():
    client = RecordingClient(answer={"Attributes": {"pk": {"S": "tx#t1"}, "state": {"S": BOUND}}})
    item = DynamoTransactions(client, "table").transition("t1", [PENDING], {"state": BOUND}, expect={"last_poll_at": None})
    call = client.calls[0][1]
    assert item == {"state": BOUND}
    assert call["ConditionExpression"] == "attribute_exists(pk) AND #state IN (:s0) AND attribute_not_exists(#e0)"
    assert call["ExpressionAttributeValues"][":s0"] == {"S": PENDING}
    assert DynamoTransactions(RecordingClient(fail=True), "table").transition("t1", [PENDING], {"state": BOUND}) is None


def test_the_dynamodb_store_takes_a_code_with_a_conditional_delete():
    client = RecordingClient(answer={"Attributes": {"pk": {"S": "tx#t1"}, "state": {"S": APPROVED}, "code": {"S": "c"}}})
    assert DynamoTransactions(client, "table").take("t1") == {"state": APPROVED, "code": "c"}
    assert client.calls[0][1]["ConditionExpression"] == "#state = :approved AND attribute_exists(code)"
    assert DynamoTransactions(RecordingClient(fail=True), "table").take("t1") is None


def test_the_dynamodb_store_raises_errors_that_are_not_failed_conditions():
    class Broken:
        def get_item(self, **kwargs):
            raise RuntimeError("network")

        def put_item(self, **kwargs):
            raise RuntimeError("network")

    with pytest.raises(RuntimeError):
        DynamoTransactions(Broken(), "table").create(pending())
