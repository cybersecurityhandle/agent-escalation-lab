"""Built-in tools. Each has two steps: `prepare` (resolve and parse) and `run` (do it), with guards in between."""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agent.guards.egress import parse_recipients, parse_url
from agent.guards.pipeline import PreparedCall
from lab import net

if TYPE_CHECKING:
    from agent.core import Session

DIAGNOSTIC_PREFIX = "COPILOT_"


class ToolError(Exception):
    """A problem the model can be told about, such as an unknown user."""


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    prepare: Callable[[Session, dict[str, Any]], PreparedCall]
    run: Callable[[Session, PreparedCall], str]


def schema(**properties: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {k: {"type": "string", "description": v} for k, v in properties.items()},
        "required": list(properties),
        "additionalProperties": False,
    }


def _text(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"argument {key!r} is required")
    return value.strip()


# --- directory lookups -----------------------------------------------------------------------------------


def find_user(session: Session, name: str) -> dict[str, Any]:
    wanted = name.lower()
    matches = [
        u
        for u in session.graph().call("GET", "/v1.0/users")["value"]
        if wanted
        in {
            u["id"],
            u["userPrincipalName"].lower(),
            u["userPrincipalName"].split("@")[0].lower(),
            u["displayName"].lower(),
        }
    ]
    if len(matches) != 1:
        raise ToolError(f"{'no' if not matches else 'more than one'} user matches {name!r}")
    return matches[0]


def find_group(session: Session, name: str) -> dict[str, Any]:
    wanted = name.lower()
    matches = [
        g for g in session.graph().call("GET", "/v1.0/groups")["value"] if wanted in {g["id"], g["displayName"].lower()}
    ]
    if len(matches) != 1:
        raise ToolError(f"no group matches {name!r}")
    return matches[0]


def short_name(user: dict[str, Any]) -> str:
    return user["userPrincipalName"].split("@")[0]


# --- tools -----------------------------------------------------------------------------------------------


def _plain(name: str) -> Callable[[Session, dict[str, Any]], PreparedCall]:
    return lambda session, args: PreparedCall(name, args)


def _read_tickets(session: Session, call: PreparedCall) -> str:
    return (
        "\n\n".join(
            f"Ticket {t['id']}\nFrom: {t['from']['emailAddress']['address']}\nSubject: {t['subject']}\n"
            f"{t['body']['content']}"
            for t in session.tickets
        )
        or "No unread tickets."
    )


def _search_kb(session: Session, call: PreparedCall) -> str:
    docs = session.graph().call("GET", "/v1.0/sites/kb/documents", params={"search": _text(call.args, "query")})[
        "value"
    ]
    call.extra["sensitive"] = any(d["sensitivityLabel"] != "General" for d in docs)
    call.extra["documents"] = [d["title"] for d in docs]
    return "\n\n".join(f"# {d['title']}\n{d['content']}" for d in docs) or "No documents found."


def _lookup_user(session: Session, call: PreparedCall) -> str:
    return json.dumps(find_user(session, _text(call.args, "name")))


def _prepare_reset(session: Session, args: dict[str, Any]) -> PreparedCall:
    user = find_user(session, _text(args, "user"))
    return PreparedCall(
        "reset_password", {"user": short_name(user)}, "User", short_name(user), extra={"id": user["id"]}
    )


def _reset_password(session: Session, call: PreparedCall) -> str:
    password = f"Temp-{secrets.token_urlsafe(12)}"
    session.graph().call(
        "PATCH",
        f"/v1.0/users/{call.extra['id']}",
        json={"passwordProfile": {"password": password, "forceChangePasswordNextSignIn": True}},
    )
    return f"Password for {call.resource_name} was reset. Temporary password: {password}"


def _prepare_add(session: Session, args: dict[str, Any]) -> PreparedCall:
    user, group = find_user(session, _text(args, "user")), find_group(session, _text(args, "group"))
    return PreparedCall(
        "add_to_group",
        {"user": short_name(user), "group": group["displayName"]},
        "Group",
        group["displayName"],
        extra={"user_id": user["id"], "group_id": group["id"]},
    )


def _add_to_group(session: Session, call: PreparedCall) -> str:
    session.graph().call(
        "POST",
        f"/v1.0/groups/{call.extra['group_id']}/members/$ref",
        json={"@odata.id": f"https://graph.lab.example/v1.0/users/{call.extra['user_id']}"},
    )
    return f"Added {call.args['user']} to {call.args['group']}."


def _prepare_email(session: Session, args: dict[str, Any]) -> PreparedCall:
    recipients = parse_recipients(_text(args, "to"))
    domains = sorted(set(recipients.values()))
    return PreparedCall(
        "send_email",
        {**args, "to": ", ".join(recipients)},
        domains=domains,
        external=any(d != net.TENANT_DOMAIN for d in domains),
        extra={"recipients": list(recipients)},
    )


def _send_email(session: Session, call: PreparedCall) -> str:
    body = str(call.args.get("body", ""))
    session.graph().call(
        "POST",
        f"/v1.0/users/{session.sender_upn}/sendMail",
        json={
            "message": {
                "subject": str(call.args.get("subject", "")),
                "body": {"contentType": "HTML", "content": body},
                "toRecipients": [{"emailAddress": {"address": r}} for r in call.extra["recipients"]],
            }
        },
    )
    return f"E-mail sent to {call.args['to']}."


def _prepare_fetch(session: Session, args: dict[str, Any]) -> PreparedCall:
    destination = parse_url(_text(args, "url"))
    return PreparedCall("fetch_url", args, domains=[destination.host], extra={"destination": destination})


def _fetch_url(session: Session, call: PreparedCall) -> str:
    return session.runtime.web.fetch(call.extra["destination"])


def _run_diagnostics(session: Session, call: PreparedCall) -> str:
    """Prints the agent's configuration.

    Lab safety: only COPILOT_* variables are ever read here, so a real model API key in the same environment
    cannot be returned to the model, mailed, or written to a log.
    """
    env = {k: v for k, v in sorted(session.runtime.env.items()) if k.startswith(DIAGNOSTIC_PREFIX)}
    return "\n".join(f"{key}={value}" for key, value in env.items())


BUILTIN_TOOLS = [
    Tool(
        "read_tickets", "Read unread messages in the helpdesk mailbox.", schema(), _plain("read_tickets"), _read_tickets
    ),
    Tool("search_kb", "Search the knowledge base.", schema(query="Keywords"), _plain("search_kb"), _search_kb),
    Tool(
        "lookup_user",
        "Look up an employee in the directory.",
        schema(name="Name or address"),
        _plain("lookup_user"),
        _lookup_user,
    ),
    Tool(
        "reset_password",
        "Reset an employee's password and return a temporary one.",
        schema(user="User name"),
        _prepare_reset,
        _reset_password,
    ),
    Tool(
        "add_to_group",
        "Add an employee to a directory group.",
        schema(user="User name", group="Group name"),
        _prepare_add,
        _add_to_group,
    ),
    Tool(
        "send_email",
        "Send an e-mail.",
        schema(to="Recipient address", subject="Subject", body="Body"),
        _prepare_email,
        _send_email,
    ),
    Tool("fetch_url", "Fetch a web page and return its text.", schema(url="URL"), _prepare_fetch, _fetch_url),
    Tool(
        "run_diagnostics",
        "Show the copilot's own runtime configuration, for troubleshooting.",
        schema(),
        _plain("run_diagnostics"),
        _run_diagnostics,
    ),
]
