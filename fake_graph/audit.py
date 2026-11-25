"""Audit log shaped loosely on Entra's AuditLogs and sign-in log tables."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fake_graph.auth import Principal
from lab.jsonl import JsonlLog, utcnow


def target(kind: str, object_id: str, name: str) -> dict[str, Any]:
    return {"type": kind, "id": object_id, "displayName": name}


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.log = JsonlLog(path)

    def activity(
        self,
        principal: Principal,
        activity: str,
        targets: list[dict[str, Any]],
        result: str,
        reason: str = "",
        *,
        target_privileged: bool = False,
        **details: Any,
    ) -> None:
        """One directory operation.

        `targetPrivileged` is lab enrichment. Real Entra logs do not say whether a target is tier 0:
        a detection has to join on a watchlist.
        """
        self.log.append(
            {
                "timestamp": utcnow(),
                "product": "fake_graph",
                "category": "AuditLogs",
                "activityDisplayName": activity,
                "authType": principal.auth_type,
                "initiatedBy": {
                    "app": {"appId": principal.app_id, "displayName": principal.app_name},
                    "user": {"id": principal.oid, "userPrincipalName": principal.upn} if principal.oid else None,
                },
                "ipAddress": principal.ip,
                "correlationId": principal.correlation_id,
                "targetResources": targets,
                "targetPrivileged": target_privileged,
                "result": result,
                "resultReason": reason,
                "additionalDetails": details,
            }
        )

    def sign_in(
        self,
        category: str,
        *,
        app_id: str,
        app_name: str,
        upn: str | None,
        ip: str,
        grant: str,
        result: str,
        reason: str = "",
        correlation_id: str = "",
    ) -> None:
        self.log.append(
            {
                "timestamp": utcnow(),
                "product": "fake_graph",
                "category": category,
                "activityDisplayName": "Sign-in activity",
                "appId": app_id,
                "appDisplayName": app_name,
                "userPrincipalName": upn,
                "ipAddress": ip,
                "grantType": grant,
                "correlationId": correlation_id,
                "result": result,
                "resultReason": reason,
            }
        )
