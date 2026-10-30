"""Rate limits for the broker's public routes.

The broker's ``/start`` and ``/poll`` take calls from anyone who can reach the function URL, so each caller (its
source address, or its IPv6 /64) gets a fixed number of calls per window. Starts also have one ceiling across all
callers, for a flood spread over many addresses; real use is a handful of sign-ins a day. A CLI that polls one
transaction faster than its interval is told ``slow_down`` separately, by the poll itself.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Limit:
    calls: int
    window_seconds: int


START = Limit(calls=10, window_seconds=60)
POLL = Limit(calls=120, window_seconds=60)
ALL_STARTS = Limit(calls=100, window_seconds=60)
EVERYONE = "*"  # the caller name the ceiling across all callers is counted under; never a real address


def allowed(store, route: str, caller: str, limit: Limit, now: int) -> bool:
    """Count this call and say whether the caller is still within the route's limit."""
    return store.count(f"{route}#{caller}", now, limit.window_seconds) <= limit.calls
