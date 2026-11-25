"""Agent configuration: the mode files and the eight independently toggleable controls."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

import yaml

from lab import net

CONFIG_DIR = Path(__file__).parent
ALLOWED_DOMAINS = frozenset({net.TENANT_DOMAIN, net.INTRANET_HOST, net.PARTNER_DOMAIN})

_ALL_PERMISSIONS = {"User.ReadWrite.All", "Group.ReadWrite.All", "Mail.Send", "Sites.Read.All", "Mail.Read"}


@dataclass(frozen=True)
class Controls:
    delegated_auth: bool = False
    least_privilege_scopes: bool = False
    human_approval: bool = False
    spotlighting: bool = False
    egress_allowlist: bool = False
    tool_pinning: bool = False
    secret_isolation: bool = False
    policy_engine: bool = False

    @classmethod
    def names(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    @classmethod
    def only(cls, *names: str) -> Controls:
        return cls().toggled(dict.fromkeys(names, True))

    def toggled(self, changes: dict[str, bool]) -> Controls:
        unknown = set(changes) - set(self.names())
        if unknown:
            raise ValueError(f"unknown control: {', '.join(sorted(unknown))}")
        return replace(self, **changes)

    def enabled(self) -> list[str]:
        return [name for name, on in asdict(self).items() if on]


@dataclass(frozen=True)
class AgentConfig:
    mode: str
    controls: Controls

    @property
    def per_ticket_sessions(self) -> bool:
        """Controls that depend on who is asking need one requester per session, so tickets cannot mix."""
        return self.controls.delegated_auth or self.controls.policy_engine


def load_config(mode: str) -> AgentConfig:
    path = CONFIG_DIR / f"{mode}.yaml"
    if mode not in {"vulnerable", "hardened"}:
        raise ValueError(f"unknown mode: {mode}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return AgentConfig(data["mode"], Controls(**data["controls"]))


def consent_for(controls: Controls) -> dict[str, list[str]]:
    """The Graph permissions an admin has consented to for this configuration."""
    roles, scopes = set(_ALL_PERMISSIONS), set(_ALL_PERMISSIONS)
    if controls.least_privilege_scopes:
        roles.discard("Group.ReadWrite.All")
        scopes.discard("Group.ReadWrite.All")
    if controls.delegated_auth:
        roles = {"Mail.Read"}  # only enough to see the ticket queue; everything else is on-behalf-of
    return {"app_roles": sorted(roles), "delegated_scopes": sorted(scopes)}
