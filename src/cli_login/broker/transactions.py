"""Remote sign-in transactions: create once, change state conditionally, hand the code over exactly once.

Two stores share one interface: ``MemoryTransactions`` for specs and local runs, and ``DynamoTransactions`` for the
deployed broker, whose table expires items through TTL on ``expires_at``. Every change is conditional on the state
it expects, so two callers racing for the same transition cannot both win.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Iterable, Mapping
from typing import Any

PENDING, BOUND, APPROVED, DENIED = "pending", "bound", "approved", "denied"
STATES = (PENDING, BOUND, APPROVED, DENIED)


class MemoryTransactions:
    """In-process store with the same conditional semantics as the DynamoDB one."""

    def __init__(self):
        self._items: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self, item: Mapping[str, Any]) -> bool:
        with self._lock:
            if item["id"] in self._items:
                return False
            self._items[item["id"]] = dict(item)
            return True

    def get(self, transaction_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._items.get(transaction_id)
            return copy.deepcopy(item) if item else None

    def transition(
        self,
        transaction_id: str,
        from_states: Iterable[str],
        changes: Mapping[str, Any],
        *,
        expect: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Apply ``changes`` only when the state is one of ``from_states`` and every ``expect`` field matches."""
        with self._lock:
            item = self._items.get(transaction_id)
            if item is None or item["state"] not in tuple(from_states):
                return None
            if any(item.get(key) != value for key, value in (expect or {}).items()):
                return None
            item.update(changes)
            return copy.deepcopy(item)

    def take(self, transaction_id: str) -> dict[str, Any] | None:
        """Delete an approved transaction and return it; None when it is not approved or another caller took it."""
        with self._lock:
            item = self._items.get(transaction_id)
            if item is None or item["state"] != APPROVED or not item.get("code"):
                return None
            return self._items.pop(transaction_id)

    def count(self, key: str, now: int, window_seconds: int) -> int:
        """Count one call against ``key`` in the current window and return the window's total."""
        window = now // window_seconds
        with self._lock:
            counter = self._items.setdefault(f"rate#{key}#{window}", {"count": 0})
            counter["count"] += 1
            return counter["count"]


def _failed_condition(error: Exception) -> bool:
    # The client's ConditionalCheckFailedException, recognised by its code so no AWS import is needed.
    response = getattr(error, "response", None) or {}
    return (response.get("Error") or {}).get("Code") == "ConditionalCheckFailedException"


def _encode(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, str):
        return {"S": value}
    if value is None:
        return {"NULL": True}
    if isinstance(value, Mapping):
        return {"M": {key: _encode(item) for key, item in value.items()}}
    raise TypeError(f"unsupported attribute type {type(value).__name__}")


def _decode(attribute: Mapping[str, Any]) -> Any:
    (kind, value), = attribute.items()
    if kind == "N":
        return int(value)
    if kind == "M":
        return {key: _decode(item) for key, item in value.items()}
    if kind == "NULL":
        return None
    return value


def _item(raw: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not raw:
        return None
    return {key: _decode(value) for key, value in raw.items() if key != "pk"}


class DynamoTransactions:
    """The deployed store: one table keyed by ``pk``, with TTL on ``expires_at``.

    ``client`` is a low-level DynamoDB client (``boto3.client("dynamodb")``); specs pass a recording fake.
    """

    def __init__(self, client, table: str):
        self.client = client
        self.table = table

    @staticmethod
    def _key(transaction_id: str) -> dict[str, Any]:
        return {"pk": {"S": "tx#" + transaction_id}}

    def create(self, item: Mapping[str, Any]) -> bool:
        try:
            self.client.put_item(
                TableName=self.table,
                Item={**self._key(item["id"]), **{key: _encode(value) for key, value in item.items()}},
                ConditionExpression="attribute_not_exists(pk)",
            )
            return True
        except Exception as error:
            if _failed_condition(error):
                return False
            raise

    def get(self, transaction_id: str) -> dict[str, Any] | None:
        result = self.client.get_item(TableName=self.table, Key=self._key(transaction_id), ConsistentRead=True)
        return _item(result.get("Item"))

    def transition(self, transaction_id, from_states, changes, *, expect=None):
        names, values, sets = {"#state": "state"}, {}, []
        for index, (key, value) in enumerate(changes.items()):
            names[f"#c{index}"] = key
            values[f":c{index}"] = _encode(value)
            sets.append(f"#c{index} = :c{index}")
        allowed = []
        for index, state in enumerate(from_states):
            values[f":s{index}"] = _encode(state)
            allowed.append(f":s{index}")
        conditions = [f"#state IN ({', '.join(allowed)})"]
        for index, (key, value) in enumerate((expect or {}).items()):
            names[f"#e{index}"] = key
            if value is None:
                conditions.append(f"attribute_not_exists(#e{index})")
            else:
                values[f":e{index}"] = _encode(value)
                conditions.append(f"#e{index} = :e{index}")
        try:
            result = self.client.update_item(
                TableName=self.table,
                Key=self._key(transaction_id),
                UpdateExpression="SET " + ", ".join(sets),
                ConditionExpression="attribute_exists(pk) AND " + " AND ".join(conditions),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
            )
        except Exception as error:
            if _failed_condition(error):
                return None
            raise
        return _item(result.get("Attributes"))

    def take(self, transaction_id: str) -> dict[str, Any] | None:
        try:
            result = self.client.delete_item(
                TableName=self.table,
                Key=self._key(transaction_id),
                ConditionExpression="#state = :approved AND attribute_exists(code)",
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={":approved": _encode(APPROVED)},
                ReturnValues="ALL_OLD",
            )
        except Exception as error:
            if _failed_condition(error):
                return None
            raise
        return _item(result.get("Attributes"))

    def count(self, key: str, now: int, window_seconds: int) -> int:
        window = now // window_seconds
        result = self.client.update_item(
            TableName=self.table,
            Key={"pk": {"S": f"rate#{key}#{window}"}},
            UpdateExpression="ADD #count :one SET expires_at = if_not_exists(expires_at, :expires)",
            ExpressionAttributeNames={"#count": "count"},
            ExpressionAttributeValues={":one": {"N": "1"}, ":expires": {"N": str((window + 2) * window_seconds)}},
            ReturnValues="UPDATED_NEW",
        )
        return int(result["Attributes"]["count"]["N"])
