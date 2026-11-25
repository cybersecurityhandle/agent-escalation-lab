"""fake-graph: a small mock of the parts of Microsoft Graph and Entra ID this lab needs.

Not a clone and not connected to anything. See docs/threat-model.md for where it differs from the real service.
"""

from __future__ import annotations

import hmac
import os
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from fake_graph import auth
from fake_graph.audit import AuditLog, target
from fake_graph.auth import AuthError, Authorizer, Forbidden, Principal
from fake_graph.models import App, Directory, Document, Group, User, check_password
from lab import net

OBO_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
MailRelay = Callable[[dict[str, Any]], None]


class Consent(BaseModel):
    app_roles: list[str]
    delegated_scopes: list[str]


def user_json(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "userPrincipalName": user.upn,
        "displayName": user.display,
        "jobTitle": user.title,
        "mobilePhone": user.mobile,
    }


def group_json(group: Group) -> dict[str, Any]:
    return {
        "id": group.id,
        "displayName": group.name,
        "description": group.description,
        "isAssignableToRole": group.role_assignable,
        "securityEnabled": True,
    }


def create_app(data_dir: Path, *, lab_key: str, mail_relay: MailRelay, db_path: str = ":memory:") -> FastAPI:
    directory = Directory(db_path)
    audit = AuditLog(data_dir / "audit.jsonl")
    authz = Authorizer(directory)
    app = FastAPI(title="fake-graph", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.directory = directory

    # --- plumbing --------------------------------------------------------------------------------

    @app.exception_handler(AuthError)
    def unauthorized(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse({"error": {"code": "InvalidAuthenticationToken", "message": str(exc)}}, 401)

    @app.exception_handler(Forbidden)
    def forbidden(_: Request, exc: Forbidden) -> JSONResponse:
        return JSONResponse({"error": {"code": "Authorization_RequestDenied", "message": str(exc)}}, 403)

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def caller(
        request: Request, authorization: str = Header(default=""), client_request_id: str = Header(default="")
    ) -> Principal:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError("bearer token required")
        return auth.principal_from_token(token, client_ip(request), client_request_id or str(uuid.uuid4()))

    def lab_admin(x_lab_key: str = Header(default="")) -> None:
        if not hmac.compare_digest(x_lab_key.encode(), lab_key.encode()):
            raise HTTPException(403, "lab key required")

    def need_user(key: str) -> User:
        user = directory.user(key)
        if user is None:
            raise HTTPException(404, "user not found")
        return user

    def guarded(
        principal: Principal,
        activity: str,
        targets: list[dict[str, Any]],
        check: Callable[[], None],
        *,
        target_privileged: bool = False,
        **details: Any,
    ) -> None:
        """Run an authorization check and write the audit record for a denial."""
        try:
            check()
        except Forbidden as exc:
            audit.activity(
                principal, activity, targets, "failure", str(exc), target_privileged=target_privileged, **details
            )
            raise

    # --- tokens ----------------------------------------------------------------------------------

    @app.post("/oauth2/v2.0/token")
    async def token(request: Request) -> JSONResponse:
        form = _parse_form(await request.body())
        ip = client_ip(request)
        grant = str(form.get("grant_type", ""))
        correlation_id = request.headers.get("client-request-id", "")
        client = directory.app(str(form.get("client_id", "")))
        if client is None:
            return _oauth_error("invalid_client", "unknown client")

        def log(category: str, result: str, upn: str | None = None, reason: str = "") -> None:
            audit.sign_in(
                category,
                app_id=client.app_id,
                app_name=client.name,
                upn=upn,
                ip=ip,
                grant=grant,
                result=result,
                reason=reason,
                correlation_id=correlation_id,
            )

        if grant == "password":
            return _password_grant(client, form, log)
        category = "ServicePrincipalSignInLogs" if grant == "client_credentials" else "NonInteractiveUserSignInLogs"
        presented = str(form.get("client_secret", ""))
        if not client.secret or not hmac.compare_digest(presented.encode(), client.secret.encode()):
            log(category, "failure", reason="invalid client secret")
            return _oauth_error("invalid_client", "invalid client secret")
        if grant == "client_credentials":
            log(category, "success")
            return _token_response(auth.issue_app_token(client))
        if grant == OBO_GRANT:
            return _obo_grant(client, form, log)
        return _oauth_error("unsupported_grant_type", grant)

    def _password_grant(client: App, form: dict[str, Any], log: Callable[..., None]) -> JSONResponse:
        """Lab stand-in for interactive sign-in. Real tenants should have this flow turned off."""
        user = directory.user(str(form.get("username", "")))
        if not client.public or user is None or not check_password(str(form.get("password", "")), user.password):
            log("SignInLogs", "failure", user.upn if user else None, "invalid username or password")
            return _oauth_error("invalid_grant", "invalid username or password")
        log("SignInLogs", "success", user.upn)
        if form.get("scope") == f"{net.COPILOT_AUDIENCE}/access_as_user":
            return _token_response(auth.issue_user_token(client, user, net.COPILOT_AUDIENCE, {"access_as_user"}))
        return _token_response(auth.issue_user_token(client, user, net.GRAPH_AUDIENCE, client.scopes))

    def _obo_grant(client: App, form: dict[str, Any], log: Callable[..., None]) -> JSONResponse:
        if form.get("requested_token_use") != "on_behalf_of":
            return _oauth_error("invalid_request", "requested_token_use must be on_behalf_of")
        try:
            claims = auth.verify_jwt(str(form.get("assertion", "")), client.audience or "none")
            if claims.get("idtyp") != "user":
                raise AuthError("on-behalf-of works for user tokens only")
        except AuthError as exc:
            log("NonInteractiveUserSignInLogs", "failure", reason=str(exc))
            return _oauth_error("invalid_grant", str(exc))
        user = directory.user(claims["oid"])
        if user is None:
            return _oauth_error("invalid_grant", "unknown user")
        log("NonInteractiveUserSignInLogs", "success", user.upn)
        return _token_response(auth.issue_user_token(client, user, net.GRAPH_AUDIENCE, client.scopes))

    @app.post("/oauth2/v2.0/introspect")
    def introspect(body: dict[str, str]) -> dict[str, Any]:
        """Lab stand-in for JWKS validation: checks a user token meant for the copilot and returns its claims."""
        claims = auth.verify_jwt(body.get("token", ""), net.COPILOT_AUDIENCE)
        return {"oid": claims["oid"], "upn": claims["upn"], "groups": claims["groups"]}

    # --- users -----------------------------------------------------------------------------------

    @app.get("/v1.0/me")
    def me(principal: Principal = Depends(caller)) -> dict[str, Any]:
        if principal.is_app:
            raise HTTPException(400, "/me requires a delegated token")
        user = need_user(principal.oid or "")
        return {**user_json(user), "memberOf": list(user.groups), "directoryRoles": sorted(user.roles)}

    @app.get("/v1.0/users")
    def list_users(principal: Principal = Depends(caller)) -> dict[str, Any]:
        authz.require(principal, "User.ReadWrite.All", "User.Read.All")
        return {"value": [user_json(user) for user in directory.users()]}

    @app.get("/v1.0/users/{user_id}")
    def get_user(user_id: str, principal: Principal = Depends(caller)) -> dict[str, Any]:
        authz.require(principal, "User.ReadWrite.All", "User.Read.All")
        return user_json(need_user(user_id))

    @app.patch("/v1.0/users/{user_id}", status_code=204)
    def patch_user(user_id: str, body: dict[str, Any], principal: Principal = Depends(caller)) -> None:
        user = need_user(user_id)
        targets = [target("User", user.id, user.upn)]
        unknown = set(body) - {"passwordProfile", "displayName", "jobTitle", "mobilePhone"}
        if unknown:
            raise HTTPException(400, f"unsupported properties: {sorted(unknown)}")
        if "passwordProfile" in body:
            password = str((body["passwordProfile"] or {}).get("password", ""))
            guarded(
                principal,
                "Reset user password",
                targets,
                lambda: authz.reset_password(principal, user),
                target_privileged=user.privileged,
            )
            if len(password) < 12:
                raise HTTPException(400, "password does not meet policy")
            directory.set_password(user.id, password)
            audit.activity(principal, "Reset user password", targets, "success", target_privileged=user.privileged)
        profile = {key: body[key] for key in ("displayName", "jobTitle", "mobilePhone") if key in body}
        if profile:
            guarded(
                principal,
                "Update user",
                targets,
                lambda: authz.update_profile(principal, user),
                target_privileged=user.privileged,
            )
            directory.set_profile(
                user.id, profile.get("jobTitle"), profile.get("mobilePhone"), profile.get("displayName")
            )
            audit.activity(
                principal,
                "Update user",
                targets,
                "success",
                target_privileged=user.privileged,
                modifiedProperties=sorted(profile),
            )

    # --- groups ----------------------------------------------------------------------------------

    @app.get("/v1.0/groups")
    def list_groups(principal: Principal = Depends(caller)) -> dict[str, Any]:
        authz.require(principal, "Group.ReadWrite.All", "Group.Read.All", "User.ReadWrite.All", "User.Read.All")
        return {"value": [group_json(group) for group in directory.groups()]}

    @app.post("/v1.0/groups/{group_id}/members/$ref", status_code=204)
    def add_member(group_id: str, body: dict[str, str], principal: Principal = Depends(caller)) -> None:
        group = directory.group(group_id)
        if group is None:
            raise HTTPException(404, "group not found")
        user = need_user(body.get("@odata.id", "").rstrip("/").rsplit("/", 1)[-1])
        targets = [target("Group", group.id, group.name), target("User", user.id, user.upn)]
        guarded(
            principal,
            "Add member to group",
            targets,
            lambda: authz.add_group_member(principal, group),
            target_privileged=group.privileged,
        )
        if not directory.add_member(group.id, user.id):
            raise HTTPException(400, "already a member")
        audit.activity(principal, "Add member to group", targets, "success", target_privileged=group.privileged)

    # --- mail ------------------------------------------------------------------------------------

    def mailbox_json(owner: User, include_assertion: bool) -> dict[str, Any]:
        items = []
        for row in directory.mailbox(owner.upn):
            item = {
                "id": row["id"],
                "subject": row["subject"],
                "receivedDateTime": row["received"],
                "from": {"emailAddress": {"address": row["sender"]}},
                "body": {"contentType": "html", "content": row["body"]},
            }
            if include_assertion:
                item["labUserAssertion"] = row["assertion"]
            items.append(item)
        return {"value": items}

    @app.get("/v1.0/me/messages")
    def my_messages(principal: Principal = Depends(caller)) -> dict[str, Any]:
        if principal.is_app:
            raise HTTPException(400, "/me requires a delegated token")
        owner = need_user(principal.oid or "")
        authz.read_mailbox(principal, owner)
        return mailbox_json(owner, include_assertion=False)

    @app.get("/v1.0/users/{user_id}/messages")
    def user_messages(user_id: str, principal: Principal = Depends(caller)) -> dict[str, Any]:
        owner = need_user(user_id)
        targets = [target("Mailbox", owner.id, owner.upn)]
        guarded(principal, "MailItemsAccessed", targets, lambda: authz.read_mailbox(principal, owner))
        audit.activity(principal, "MailItemsAccessed", targets, "success")
        return mailbox_json(owner, include_assertion=principal.is_app and principal.app_name == net.COPILOT_APP)

    @app.post("/v1.0/users/{user_id}/sendMail", status_code=202)
    def send_mail(user_id: str, body: dict[str, Any], principal: Principal = Depends(caller)) -> None:
        sender = need_user(user_id)
        message = body.get("message", {})
        recipients = [str(r["emailAddress"]["address"]).strip().lower() for r in message.get("toRecipients", [])]
        content = str(message.get("body", {}).get("content", ""))
        subject = str(message.get("subject", ""))
        external = [r for r in recipients if r.rpartition("@")[2] != directory.domain]
        targets = [target("Mailbox", sender.id, sender.upn)]
        details = {"recipients": recipients, "externalRecipients": external}
        guarded(principal, "Send mail", targets, lambda: authz.send_mail(principal, sender), **details)
        if not recipients:
            raise HTTPException(400, "no recipients")
        for recipient in recipients:
            if recipient in external:
                mail_relay({"from": sender.upn, "to": recipient, "subject": subject, "body": content})
            elif directory.user(recipient) is not None:
                directory.deliver(
                    recipient, sender.upn, subject, content, _ticket_assertion(principal, sender, recipient)
                )
        audit.activity(principal, "Send mail", targets, "success", **details)

    def _ticket_assertion(principal: Principal, sender: User, recipient: str) -> str | None:
        """Model a ticket portal: a ticket filed by a signed-in user carries a token for the copilot.

        Entra has no on-behalf-of for e-mail. Mail sent app-only (so, possibly spoofed) gets no assertion.
        """
        if recipient != net.HELPDESK_MAILBOX or principal.is_app:
            return None
        client = directory.app(principal.app_id)
        return auth.issue_user_token(client, sender, net.COPILOT_AUDIENCE, {"access_as_user"}) if client else None

    # --- knowledge base --------------------------------------------------------------------------

    @app.get("/v1.0/sites/kb/documents")
    def list_documents(search: str = "", principal: Principal = Depends(caller)) -> dict[str, Any]:
        authz.require(principal, "Sites.Read.All", "Sites.ReadWrite.All")
        found = [doc for doc in directory.documents() if _visible(principal, doc) and _matches(doc, search)]
        for doc in found:
            if doc.sensitive:
                audit.activity(
                    principal,
                    "FileAccessed",
                    [target("File", doc.id, doc.title)],
                    "success",
                    sensitivityLabel=doc.label,
                )
        return {
            "value": [
                {"id": d.id, "title": d.title, "sensitivityLabel": d.label, "content": d.content, "author": d.author}
                for d in found
            ]
        }

    @app.post("/v1.0/sites/kb/documents", status_code=201)
    def create_document(body: dict[str, str], principal: Principal = Depends(caller)) -> dict[str, str]:
        authz.require(principal, "Sites.ReadWrite.All")
        doc = directory.add_document(
            body["title"], body["content"], "General", ["All Staff"], principal.upn or principal.app_name
        )
        audit.activity(principal, "FileUploaded", [target("File", doc.id, doc.title)], "success")
        return {"id": doc.id}

    def _visible(principal: Principal, doc: Document) -> bool:
        """App-only Sites.Read.All sees everything. Delegated access is trimmed to the user's groups."""
        if principal.is_app:
            return True
        return bool(doc.allowed_groups.intersection(need_user(principal.oid or "").groups))

    # --- applications ----------------------------------------------------------------------------

    @app.get("/v1.0/servicePrincipals")
    def service_principals(principal: Principal = Depends(caller)) -> dict[str, Any]:
        authz.require(principal, "Application.Read.All")
        return {
            "value": [
                {
                    "appId": a.app_id,
                    "displayName": a.name,
                    "appRoles": sorted(a.app_roles),
                    "directoryRoles": sorted(a.roles),
                }
                for a in directory.apps()
            ]
        }

    @app.get("/v1.0/applications/{app_id}")
    def application(app_id: str, principal: Principal = Depends(caller)) -> dict[str, Any]:
        authz.require(principal, "Application.Read.All")
        found = directory.app(app_id)
        if found is None:
            raise HTTPException(404, "application not found")
        audit.activity(
            principal,
            "Read application credentials metadata",
            [target("Application", found.app_id, found.name)],
            "success",
        )
        credentials = [{"hint": found.secret[:3], "secretText": None}] if found.secret else []
        return {"appId": found.app_id, "displayName": found.name, "passwordCredentials": credentials}

    # --- lab-only --------------------------------------------------------------------------------

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/intranet/status", response_class=PlainTextResponse)
    def intranet() -> str:
        return "All services operational."

    @app.get("/admin/audit", dependencies=[Depends(lab_admin)])
    def read_audit() -> dict[str, Any]:
        return {"value": audit.log.read()}

    @app.get("/admin/state", dependencies=[Depends(lab_admin)])
    def state() -> dict[str, Any]:
        return {
            "groups": {g.name: [u.name for u in directory.members(g.id)] for g in directory.groups()},
            "passwordChanges": {u.name: u.password_changes for u in directory.users()},
        }

    @app.post("/admin/reset", dependencies=[Depends(lab_admin)])
    def reset() -> dict[str, str]:
        directory.seed()
        audit.log.clear()
        return {"status": "reset"}

    @app.post("/admin/consent", dependencies=[Depends(lab_admin)])
    def consent(body: Consent) -> dict[str, str]:
        """Apply the permissions an admin consented to for the copilot in the configuration under test."""
        copilot = directory.app(net.COPILOT_APP)
        assert copilot is not None
        directory.set_consent(copilot.app_id, body.app_roles, body.delegated_scopes)
        return {"status": "updated"}

    return app


def _parse_form(body: bytes) -> dict[str, str]:
    return dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))


def _token_response(token: str) -> JSONResponse:
    return JSONResponse({"token_type": "Bearer", "expires_in": auth.TOKEN_LIFETIME, "access_token": token})


def _oauth_error(code: str, description: str) -> JSONResponse:
    return JSONResponse({"error": code, "error_description": description}, 400)


def _matches(doc: Document, query: str) -> bool:
    words = [word for word in query.lower().split() if len(word) > 2]
    haystack = f"{doc.title} {doc.content}".lower()
    return not words or any(word in haystack for word in words)


def http_relay(url: str) -> MailRelay:
    """Deliver external mail to the attacker container, the only external mail host in the lab."""

    def relay(message: dict[str, Any]) -> None:
        if message["to"].endswith(f"@{net.ATTACKER_DOMAIN}"):
            httpx.post(url, json=message, timeout=5, trust_env=False)

    return relay


def from_env() -> FastAPI:
    return create_app(
        Path(os.environ.get("LAB_DATA", "runs")),
        lab_key=os.environ["LAB_ADMIN_KEY"],
        mail_relay=http_relay(os.environ.get("MAIL_RELAY_URL", "http://attacker:9000/smtp")),
    )
