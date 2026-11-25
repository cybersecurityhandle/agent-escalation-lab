"""Token issuance and authorization rules.

Two kinds of token matter in this lab, and the difference between them is the point of it:

* app-only (client credentials): carries `roles`. Nobody is signed in. Rights are whatever the app was granted.
* delegated (on-behalf-of): carries `scp` and a user `oid`. Rights are the intersection of the app's delegated
  scopes and what that user may do anyway.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from fake_graph.models import App, Directory, Group, User
from lab import net

SIGNING_KEY = (os.environ.get("LAB_SIGNING_KEY") or secrets.token_hex(32)).encode()
TOKEN_LIFETIME = 3600


class AuthError(Exception):
    """Token is missing, malformed, expired or meant for another audience (HTTP 401)."""


class Forbidden(Exception):
    """Token is valid but does not allow the operation (HTTP 403)."""


# --- JWT (HS256, standard library only) --------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_jwt(claims: dict[str, Any]) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(claims).encode())
    signature = hmac.new(SIGNING_KEY, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64(signature)}"


def verify_jwt(token: str, audience: str) -> dict[str, Any]:
    try:
        header, body, signature = token.split(".")
        alg = json.loads(_unb64(header)).get("alg")
        expected = hmac.new(SIGNING_KEY, f"{header}.{body}".encode(), hashlib.sha256).digest()
        valid = alg == "HS256" and hmac.compare_digest(_unb64(signature), expected)
        claims = json.loads(_unb64(body))
    except (ValueError, AttributeError, UnicodeDecodeError) as exc:
        raise AuthError("malformed token") from exc
    if not valid:
        raise AuthError("bad signature")
    if claims.get("iss") != net.ISSUER or claims.get("exp", 0) < time.time():
        raise AuthError("expired or wrong issuer")
    if claims.get("aud") != audience:
        raise AuthError("wrong audience")
    return claims


def _base_claims(audience: str, app: App) -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": net.ISSUER,
        "aud": audience,
        "iat": now,
        "exp": now + TOKEN_LIFETIME,
        "appid": app.app_id,
        "app_displayname": app.name,
    }


def issue_app_token(app: App) -> str:
    return sign_jwt(
        {**_base_claims(net.GRAPH_AUDIENCE, app), "idtyp": "app", "oid": app.app_id, "roles": sorted(app.app_roles)}
    )


def issue_user_token(app: App, user: User, audience: str, scopes: set[str] | frozenset[str]) -> str:
    return sign_jwt(
        {
            **_base_claims(audience, app),
            "idtyp": "user",
            "oid": user.id,
            "upn": user.upn,
            "groups": list(user.groups),
            "scp": " ".join(sorted(scopes)),
        }
    )


# --- request principal ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    auth_type: str  # "app" or "delegated"
    app_id: str
    app_name: str
    oid: str | None
    upn: str | None
    permissions: frozenset[str]
    ip: str
    correlation_id: str

    @property
    def is_app(self) -> bool:
        return self.auth_type == "app"


def principal_from_token(token: str, ip: str, correlation_id: str) -> Principal:
    claims = verify_jwt(token, net.GRAPH_AUDIENCE)
    is_app = claims["idtyp"] == "app"
    granted = claims["roles"] if is_app else claims["scp"].split()
    return Principal(
        "app" if is_app else "delegated",
        claims["appid"],
        claims["app_displayname"],
        None if is_app else claims["oid"],
        None if is_app else claims["upn"],
        frozenset(granted),
        ip,
        correlation_id,
    )


# --- authorization rules -------------------------------------------------------------------------------


class Authorizer:
    """Answers "may this principal do this?" from the token plus current directory state."""

    def __init__(self, directory: Directory) -> None:
        self.directory = directory

    def require(self, principal: Principal, *any_of: str) -> None:
        if not principal.permissions.intersection(any_of):
            kind = "application permission" if principal.is_app else "delegated scope"
            raise Forbidden(f"missing {kind}: {' or '.join(any_of)}")

    def directory_roles(self, principal: Principal) -> frozenset[str]:
        """Roles are read live, not from the token, so a role gained a second ago already counts."""
        if principal.is_app:
            app = self.directory.app(principal.app_id)
            return app.roles if app else frozenset()
        user = self.directory.user(principal.oid or "")
        return user.roles if user else frozenset()

    def reset_password(self, principal: Principal, user: User) -> None:
        """Graph needs a permission and a directory role, for app-only callers as well."""
        self.require(principal, "User.ReadWrite.All", "User-PasswordProfile.ReadWrite.All")
        roles = self.directory_roles(principal)
        if roles & {"Global Administrator", "Privileged Authentication Administrator"}:
            return
        if user.roles:
            raise Forbidden("caller may not reset the password of a user who holds a directory role")
        if not roles & {"Helpdesk Administrator", "User Administrator"}:
            raise Forbidden("caller holds no directory role that can reset passwords")

    def update_profile(self, principal: Principal, user: User) -> None:
        if not principal.is_app and principal.oid == user.id:
            self.require(principal, "User.ReadWrite.All", "User.ReadWrite")
            return
        self.require(principal, "User.ReadWrite.All")
        if not principal.is_app and not self.directory_roles(principal) & {
            "Global Administrator",
            "User Administrator",
        }:
            raise Forbidden("signed-in user may only edit their own profile")

    def add_group_member(self, principal: Principal, group: Group) -> None:
        self.require(principal, "Group.ReadWrite.All", "GroupMember.ReadWrite.All")
        roles = self.directory_roles(principal)
        if group.role_assignable:
            self.require(principal, "RoleManagement.ReadWrite.Directory")
            if not roles & {"Global Administrator", "Privileged Role Administrator"}:
                raise Forbidden("role-assignable group needs a privileged role")
            return
        if principal.is_app:
            return  # app-only Group.ReadWrite.All reaches every group that is not role-assignable
        if group.privileged and "Global Administrator" not in roles:
            raise Forbidden("signed-in user may not manage a privileged group")
        if not roles & {"Global Administrator", "Groups Administrator"}:
            raise Forbidden("signed-in user may not manage group membership")

    def send_mail(self, principal: Principal, sender: User) -> None:
        self.require(principal, "Mail.Send")
        if not principal.is_app and principal.oid != sender.id:
            raise Forbidden("delegated Mail.Send covers the signed-in user's own mailbox only")

    def read_mailbox(self, principal: Principal, owner: User) -> None:
        self.require(principal, "Mail.Read")
        if principal.is_app:
            app = self.directory.app(principal.app_id)
            if app is None or owner.name not in app.mailbox_scope:
                raise Forbidden("mailbox is outside the application's scope")
        elif principal.oid != owner.id:
            raise Forbidden("delegated Mail.Read covers the signed-in user's own mailbox only")
