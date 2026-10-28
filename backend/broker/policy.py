"""Policy engine: loads broker/policy.json and applies it.

policy.json holds the visibility and permission rules as DATA (SPEC.md
"Visibility rules" and "Broker API"):

- permissions: which roles may call which action.
- visibility:  which event types each role sees; which message gets masked.
- hidden_message: replacement text for masked messages.

Policy is re-read from disk on every use so tests and operators can swap the
file without restarting the broker; it is a few hundred bytes, this is cheap.
"""

import json
import os
from functools import lru_cache
from time import perf_counter

DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy.json")

# Reload at most once per second so a hot /events poll stays cheap.
_RELOAD_INTERVAL_S = 1.0
_cache: dict = {"stamp": 0.0, "data": None}


def _path() -> str:
    return os.environ.get("POLICY_PATH", DEFAULT_POLICY_PATH)


def load_policy() -> dict:
    """Load policy.json (env POLICY_PATH overrides the location)."""
    now = perf_counter()
    if _cache["data"] is None or now - _cache["stamp"] > _RELOAD_INTERVAL_S:
        with open(_path(), "r", encoding="utf-8") as f:
            _cache["data"] = json.load(f)
        _cache["stamp"] = now
    return _cache["data"]


def reload_policy() -> None:
    """Force the next load_policy() to re-read the file (used by tests)."""
    _cache["data"] = None
    _cache["stamp"] = 0.0


def role_allowed(action: str, role: str) -> bool:
    """True if `role` may call `action` per policy.json permissions."""
    perms = load_policy().get("permissions", {})
    return role in perms.get(action, [])


def _rule_for(role: str) -> dict:
    visibility = load_policy().get("visibility", {})
    return visibility.get(role, {"types": [], "mask": []})


def event_visible(event: dict, role: str) -> bool:
    """Does `role` see this event at all?"""
    rule = _rule_for(role)
    types = rule.get("types", [])
    if types == "*":
        return True
    if event.get("type") not in types:
        return False
    if event.get("type") == "attack":
        allowed_sources = rule.get("attack_sources")
        if allowed_sources is not None and event.get("source") not in allowed_sources:
            return False
    return True


def filter_event(event: dict, role: str) -> dict | None:
    """Apply visibility + masking for `role`; None if the event is hidden."""
    if not event_visible(event, role):
        return None
    rule = _rule_for(role)
    if event.get("type") in rule.get("mask", []):
        masked = dict(event)
        masked["message"] = load_policy().get("hidden_message", "[hidden by policy]")
        return masked
    return dict(event)


def filter_events(events, role: str) -> list[dict]:
    """Filter and mask a list of events for `role`, preserving order."""
    out = []
    for event in events:
        filtered = filter_event(event, role)
        if filtered is not None:
            out.append(filtered)
    return out
