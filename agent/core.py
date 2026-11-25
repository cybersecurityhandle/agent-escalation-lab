"""The agent loop: sessions, tool execution and where each control takes effect."""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent.config import AgentConfig
from agent.graph import Credential, GraphClient, GraphError, Http
from agent.guards import spotlighting
from agent.guards.approval import SimulatedApprover
from agent.guards.egress import BadDestination, parse_url
from agent.guards.pipeline import Denied, PreparedCall, enforce
from agent.llm import LLM, LLMError, Message, ToolCall, ToolResult, ToolSpec
from agent.tools import BUILTIN_TOOLS, Tool, ToolError
from agent.tools.registry import DEFAULT_THIRD_PARTY, load_third_party
from agent.trace import Trace
from agent.web import LabWeb, WebError
from lab import net
from lab.jsonl import JsonlLog

MAX_TURNS = 12
SYSTEM_PROMPT = (Path(__file__).parent / "prompts" / "system.md").read_text(encoding="utf-8")
_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)")


@dataclass
class Runtime:
    """Everything a session needs. Built by agent/main.py for Compose and by scenarios/harness.py in-process."""

    config: AgentConfig
    graph_http: Http
    credential: Credential
    web: LabWeb
    trace_log: JsonlLog
    llm_factory: Callable[[], LLM]
    env: dict[str, str]
    approver: SimulatedApprover = field(default_factory=SimulatedApprover)
    third_party: list[Path] = field(default_factory=lambda: [DEFAULT_THIRD_PARTY])

    def chat(self, assertion: str, message: str) -> str:
        requester = self._introspect(assertion)
        if requester is None:
            raise GraphError(401, "sign-in required")
        return Session(self, requester, assertion, "chat").run(message)

    def process_tickets(self) -> list[str]:
        listing = str(uuid.uuid4())
        app_graph = GraphClient(self.graph_http, self.credential.app_token(listing), listing)
        tickets = app_graph.call("GET", f"/v1.0/users/{net.HELPDESK_MAILBOX}/messages")["value"]
        if not tickets:
            return []
        prompt = "There are unread helpdesk tickets. Please process them."
        if not self.config.per_ticket_sessions:
            return [Session(self, {}, None, "tickets", tickets).run(prompt)]
        return [self._process_one(ticket, prompt) for ticket in tickets]

    def _process_one(self, ticket: dict[str, Any], prompt: str) -> str:
        assertion = ticket.get("labUserAssertion")
        requester = self._introspect(assertion) or {}
        session = Session(self, requester, assertion, "tickets", [ticket])
        if self.config.controls.delegated_auth and not requester:
            session.trace.event(
                "tool_call",
                tool="process_ticket",
                args={},
                outcome="denied",
                control="delegated_auth",
                reason="ticket has no authenticated sender",
            )
            return "Ticket skipped: the sender is not authenticated."
        return session.run(prompt)

    def _introspect(self, assertion: str | None) -> dict[str, Any] | None:
        if not assertion:
            return None
        response = self.graph_http.request("POST", "/oauth2/v2.0/introspect", json={"token": assertion})
        return response.json() if response.status_code == 200 else None


class Session:
    """One conversation, with at most one authenticated requester."""

    def __init__(
        self,
        runtime: Runtime,
        requester: dict[str, Any],
        assertion: str | None,
        channel: str,
        tickets: list[dict[str, Any]] | None = None,
    ) -> None:
        self.runtime, self.requester, self.channel = runtime, requester, channel
        self.controls = runtime.config.controls
        self.tickets = tickets or []
        self.id = str(uuid.uuid4())
        self._assertion = assertion
        self._graph: GraphClient | None = None
        self.trace = Trace(
            runtime.trace_log,
            self.id,
            runtime.config.mode,
            {"upn": requester.get("upn"), "groups": requester.get("groups", [])},
        )

    # --- identity --------------------------------------------------------------------------------

    def graph(self) -> GraphClient:
        """The line that decides whose rights the agent uses."""
        if self._graph is None:
            credential = self.runtime.credential
            if self.controls.delegated_auth:
                token = credential.obo_token(self._assertion or "", self.id)
            else:
                token = credential.app_token(self.id)
            self._graph = GraphClient(self.runtime.graph_http, token, self.id)
        return self._graph

    @property
    def sender_upn(self) -> str:
        return self.requester["upn"] if self.controls.delegated_auth else net.HELPDESK_MAILBOX

    # --- loop ------------------------------------------------------------------------------------

    def run(self, prompt: str) -> str:
        llm = self.runtime.llm_factory()
        tools = self._load_tools()
        specs = [ToolSpec(t.name, t.description, t.parameters) for t in tools.values()]
        system = SYSTEM_PROMPT + (spotlighting.SYSTEM_NOTE if self.controls.spotlighting else "")
        self.trace.event(
            "session_start", channel=self.channel, backend=llm.name, controls=self.controls.enabled(), prompt=prompt
        )
        messages = [Message("user", prompt)]
        final = "Stopped: too many steps."
        for _ in range(MAX_TURNS):
            try:
                reply = llm.complete(system, messages, specs)
            except LLMError as exc:
                self.trace.event("llm_error", error=str(exc))
                raise
            self.trace.event(
                "llm_turn",
                text=reply.text,
                refused=reply.refused,
                tool_calls=[{"tool": c.name, "args": c.args} for c in reply.tool_calls],
            )
            if not reply.tool_calls:
                final = reply.text
                break
            messages.append(Message("assistant", reply.text, reply.tool_calls, raw=reply.raw))
            messages.append(Message("tool", results=[self._execute(tools, call) for call in reply.tool_calls]))
        final = self._render_images(final)
        self.trace.event("session_end", final=final)
        return final

    def _load_tools(self) -> dict[str, Tool]:
        tools = {tool.name: tool for tool in BUILTIN_TOOLS}
        for path in self.runtime.third_party:
            loaded = load_third_party(path)
            refused = self.controls.tool_pinning and loaded.pin_status != "pinned"
            self.trace.event(
                "tool_loaded",
                tool=loaded.tool.name,
                source="third_party",
                sha256=loaded.sha256,
                pinStatus=loaded.pin_status,
                outcome="denied" if refused else "ok",
                control="tool_pinning" if refused else None,
            )
            if not refused:
                tools[loaded.tool.name] = loaded.tool
        return tools

    # --- tool execution --------------------------------------------------------------------------

    def _execute(self, tools: dict[str, Tool], call: ToolCall) -> ToolResult:
        tool = tools.get(call.name)
        if tool is None:
            self.trace.event("tool_call", tool=call.name, args=call.args, outcome="error", reason="unknown tool")
            return ToolResult(call.id, call.name, "Unknown tool.", True)
        prepared: PreparedCall | None = None
        record: dict[str, Any] = {"tool": call.name, "args": call.args}
        try:
            prepared = tool.prepare(self, call.args)
            record |= self._facts(prepared)
            enforce(prepared, self.controls, self.requester, self.runtime.approver)
            content = tool.run(self, prepared)
            record |= {"outcome": "ok", **self._facts(prepared)}
            self.trace.event("tool_call", **record, result=content)
            return ToolResult(call.id, call.name, spotlighting.wrap(content) if self.controls.spotlighting else content)
        except Denied as exc:
            record |= {"outcome": exc.outcome, "control": exc.control, "reason": exc.reason}
        except GraphError as exc:
            record |= {
                "outcome": "denied" if exc.status == 403 else "error",
                "reason": str(exc),
                "httpStatus": exc.status,
                "control": self._identity_control() if exc.status == 403 else None,
            }
        except (ToolError, BadDestination, WebError) as exc:
            record |= {"outcome": "error", "reason": str(exc)}
        self.trace.event("tool_call", **record)
        return ToolResult(call.id, call.name, f"{record['outcome']}: {record['reason']}", True)

    def _facts(self, call: PreparedCall) -> dict[str, Any]:
        return {
            "args": call.args,
            "resource": {"type": call.resource_type, "name": call.resource_name},
            "domains": call.domains,
            "egress": bool(call.off_allowlist),
            "external": call.external,
            "sensitive": bool(call.extra.get("sensitive")),
        }

    def _identity_control(self) -> str | None:
        """Which identity control explains a 403 from Graph."""
        if self.controls.delegated_auth:
            return "delegated_auth"
        return "least_privilege_scopes" if self.controls.least_privilege_scopes else None

    def _render_images(self, text: str) -> str:
        """The chat client loads markdown images by itself. That is a second way out, with no tool call."""

        def render(match: re.Match[str]) -> str:
            url = match.group(1)
            record: dict[str, Any] = {"tool": "render_image", "args": {"url": url}}
            try:
                destination = parse_url(url)
                prepared = PreparedCall("render_image", {"url": url}, domains=[destination.host])
                record |= self._facts(prepared)
                if self.controls.egress_allowlist and prepared.off_allowlist:
                    raise Denied("egress_allowlist", f"destination not allowed: {destination.host}")
                self.runtime.web.fetch(destination)
                self.trace.event("tool_call", **record, outcome="ok")
                return match.group(0)
            except Denied as exc:
                self.trace.event("tool_call", **record, outcome="denied", control=exc.control, reason=exc.reason)
            except (BadDestination, WebError) as exc:
                self.trace.event("tool_call", **record, outcome="error", reason=str(exc))
            return "[image blocked]"

        return _IMAGE.sub(render, text)
