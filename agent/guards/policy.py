"""Cedar policy decision point. Default deny; if Cedar is not installed every call is denied."""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml

try:
    import cedarpy
except ImportError:  # optional extra
    cedarpy = None

POLICY_DIR = Path(__file__).parent / "policies"


@cache
def _policies() -> str:
    return (POLICY_DIR / "helpdesk.cedar").read_text(encoding="utf-8")


@cache
def _tier0() -> dict[str, list[str]]:
    return yaml.safe_load((POLICY_DIR / "tier0.yaml").read_text(encoding="utf-8"))


def authorize(requester: dict[str, Any], action: str, resource_type: str, resource_name: str) -> tuple[bool, str]:
    """`resource_name` must be the canonical directory name, resolved before this call."""
    if cedarpy is None:
        return False, "policy engine unavailable (cedarpy not installed)"
    if not requester.get("upn"):
        return False, "no authenticated requester for this session"
    principal = {"type": "User", "id": requester["upn"]}
    resource = {"type": resource_type, "id": resource_name}
    tier0 = resource_name in _tier0().get(resource_type, [])
    entities = [
        {"uid": principal, "attrs": {}, "parents": [{"type": "Team", "id": g} for g in requester.get("groups", [])]},
        {"uid": resource, "attrs": {"tier0": tier0}, "parents": []},
    ]
    request = {"principal": principal, "action": {"type": "Action", "id": action}, "resource": resource, "context": {}}
    result = cedarpy.is_authorized(request, _policies(), entities)
    return result.allowed, "allowed" if result.allowed else f"Cedar policy does not permit {action} here"
