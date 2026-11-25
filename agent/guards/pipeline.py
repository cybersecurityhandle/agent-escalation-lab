"""Checks that run in code, between the model's decision to call a tool and the call itself."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent.config import ALLOWED_DOMAINS, Controls
from agent.guards import policy
from agent.guards.approval import NEEDS_APPROVAL, SimulatedApprover


class Denied(Exception):
    def __init__(self, control: str, reason: str, outcome: str = "denied") -> None:
        super().__init__(reason)
        self.control, self.reason, self.outcome = control, reason, outcome


@dataclass
class PreparedCall:
    """A tool call after names were resolved and destinations parsed. Guards and the tool use these values only."""

    tool: str
    args: dict[str, Any]
    resource_type: str = "Service"
    resource_name: str = "helpdesk"
    domains: list[str] = field(default_factory=list)  # where data would go outside the process
    external: bool = False  # e-mail leaving the tenant
    third_party: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def off_allowlist(self) -> list[str]:
        return [domain for domain in self.domains if domain not in ALLOWED_DOMAINS]

    def summary(self) -> str:
        return f"{self.tool} on {self.resource_type} {self.resource_name} {self.args}"


def enforce(call: PreparedCall, controls: Controls, requester: dict[str, Any], approver: SimulatedApprover) -> None:
    if controls.policy_engine:
        action = "third_party_tool" if call.third_party else call.tool
        allowed, reason = policy.authorize(requester, action, call.resource_type, call.resource_name)
        if not allowed:
            raise Denied("policy_engine", reason)
    if controls.least_privilege_scopes and call.tool == "add_to_group":
        raise Denied("least_privilege_scopes", "group change queued for an administrator", outcome="queued")
    if controls.human_approval and (call.tool in NEEDS_APPROVAL or call.external):
        if not approver.decide(call.summary()):
            raise Denied("human_approval", "approver rejected the request")
    if controls.egress_allowlist and call.off_allowlist:
        raise Denied("egress_allowlist", f"destination not allowed: {', '.join(call.off_allowlist)}")
