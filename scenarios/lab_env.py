"""Two ways to run the same lab: in one process (tests, development) or against Docker Compose.

Both expose the same small surface to scenarios, so a scenario does not know which one it is running on.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi.testclient import TestClient

from agent.config import AgentConfig, consent_for
from agent.core import Runtime
from agent.graph import Http, SecretCredential, SidecarCredential
from agent.guards.approval import SimulatedApprover
from agent.llm import LLMSettings, make_llm
from agent.sidecar import create_sidecar
from agent.tools.registry import DEFAULT_THIRD_PARTY
from agent.web import LabWeb
from attacker.listener import Listener, create_listener_app
from fake_graph.app import create_app
from fake_graph.models import SEED_FILE, stable_id
from lab import net
from lab.jsonl import JsonlLog, read_jsonl


def upn(name: str) -> str:
    return f"{name}@{net.TENANT_DOMAIN}"


@dataclass
class RunOptions:
    config: AgentConfig
    llm: LLMSettings = field(default_factory=LLMSettings)
    approve: bool = False
    third_party: Path = DEFAULT_THIRD_PARTY


class GraphUser:
    """A person (or the attacker) talking to fake-graph directly, without the agent."""

    def __init__(self, http: Http, token: str) -> None:
        self._http, self._token = http, token

    def call(self, method: str, path: str, **kwargs: Any) -> Any:
        return self._http.request(method, path, headers={"Authorization": f"Bearer {self._token}"}, **kwargs)

    def send_mail(self, sender: str, to: str, subject: str, html: str) -> Any:
        return self.call(
            "POST",
            f"/v1.0/users/{upn(sender)}/sendMail",
            json={
                "message": {
                    "subject": subject,
                    "body": {"contentType": "HTML", "content": html},
                    "toRecipients": [{"emailAddress": {"address": to}}],
                }
            },
        )

    def inbox(self) -> list[dict[str, Any]]:
        return self.call("GET", "/v1.0/me/messages").json()["value"]


class Lab:
    """Common surface. Subclasses provide the transports."""

    graph_http: Http  # as seen from an employee's machine
    attacker_http: Http  # as seen from the attacker's machine
    data_dir: Path
    agent_ips: frozenset[str] = frozenset({net.AGENT_VULNERABLE_IP, net.AGENT_HARDENED_IP, net.SIDECAR_IP})

    # --- identities ------------------------------------------------------------------------------

    def _password_grant(self, http: Http, name: str, scope: str, password: str | None) -> str | None:
        password = password or f"Lab-{name}-2026!"
        response = http.request(
            "POST",
            "/oauth2/v2.0/token",
            data={
                "grant_type": "password",
                "client_id": net.PUBLIC_CLIENT,
                "username": upn(name),
                "password": password,
                "scope": scope,
            },
        )
        return response.json().get("access_token")

    def sign_in(self, name: str, password: str | None = None, *, attacker: bool = False) -> GraphUser | None:
        http = self.attacker_http if attacker else self.graph_http
        token = self._password_grant(http, name, ".default", password)
        return GraphUser(http, token) if token else None

    def must_sign_in(self, name: str, *, attacker: bool = False) -> GraphUser:
        user = self.sign_in(name, attacker=attacker)
        if user is None:
            raise RuntimeError(f"could not sign in as {name}; run `make reset`")
        return user

    def copilot_token(self, name: str) -> str:
        token = self._password_grant(self.graph_http, name, f"{net.COPILOT_AUDIENCE}/access_as_user", None)
        if token is None:
            raise RuntimeError(f"could not sign in as {name}")
        return token

    # --- implemented by subclasses ---------------------------------------------------------------

    def chat(self, name: str, message: str) -> str:
        raise NotImplementedError

    def process_tickets(self) -> list[str]:
        raise NotImplementedError

    def state(self) -> dict[str, Any]:
        raise NotImplementedError

    def hits(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def sidecar_request_from_attacker(self) -> int | None:
        """HTTP status of an attempt to use the token sidecar from the attacker's machine, None if unreachable."""
        raise NotImplementedError

    def audit(self) -> list[dict[str, Any]]:
        return read_jsonl(self.data_dir / "audit.jsonl")

    def trace(self) -> list[dict[str, Any]]:
        return read_jsonl(self.data_dir / "agent_trace.jsonl")


def seed_secret() -> str:
    data = yaml.safe_load(SEED_FILE.read_text(encoding="utf-8"))
    return next(app["secret"] for app in data["applications"] if app["name"] == net.COPILOT_APP)


class InProcessLab(Lab):
    """Every service in this process. Requests still carry the source IP each container would have."""

    def __init__(self, data_dir: Path, options: RunOptions) -> None:
        self.data_dir = data_dir
        self._key = secrets.token_hex(16)
        listener = Listener(data_dir / "listener.jsonl")
        self._listener = listener
        graph_app = create_app(data_dir, lab_key=self._key, mail_relay=listener.mail)
        listener_app = create_listener_app(listener, self._key)
        self.graph_http = TestClient(graph_app, client=(net.USER_IP, 50000))
        self.attacker_http = TestClient(graph_app, client=(net.ATTACKER_IP, 50000))
        hardened = options.config.mode == "hardened"
        agent_ip = net.AGENT_HARDENED_IP if hardened else net.AGENT_VULNERABLE_IP
        agent_graph = TestClient(graph_app, client=(agent_ip, 50000))
        self._admin("POST", "/admin/consent", json=consent_for(options.config.controls))

        client_id, secret = stable_id("app", net.COPILOT_APP), seed_secret()
        sidecar = create_sidecar(TestClient(graph_app, client=(net.SIDECAR_IP, 50000)), client_id, secret, {agent_ip})
        self._attacker_to_sidecar = TestClient(sidecar, client=(net.ATTACKER_IP, 50000))
        env = {"COPILOT_CLIENT_ID": client_id, "COPILOT_GRAPH_URL": "http://fake-graph:8000"}
        if options.config.controls.secret_isolation:
            env["COPILOT_SIDECAR_URL"] = "http://sidecar:8002"
            credential: Any = SidecarCredential(TestClient(sidecar, client=(agent_ip, 50000)))
        else:
            env["COPILOT_CLIENT_SECRET"] = secret
            credential = SecretCredential(agent_graph, client_id, secret)
        routes: dict[str, Http] = {
            net.EXFIL_HOST: TestClient(listener_app, client=(agent_ip, 50000)),
            net.INTRANET_HOST: TestClient(graph_app, base_url="http://intranet"),
        }
        self._runtime = Runtime(
            options.config,
            agent_graph,
            credential,
            LabWeb(routes),
            JsonlLog(data_dir / "agent_trace.jsonl"),
            lambda: make_llm(options.llm),
            env,
            SimulatedApprover(options.approve),
            [options.third_party],
        )

    def _admin(self, method: str, path: str, **kwargs: Any) -> Any:
        return self.graph_http.request(method, path, headers={"X-Lab-Key": self._key}, **kwargs).json()

    def chat(self, name: str, message: str) -> str:
        return self._runtime.chat(self.copilot_token(name), message)

    def process_tickets(self) -> list[str]:
        return self._runtime.process_tickets()

    def state(self) -> dict[str, Any]:
        return self._admin("GET", "/admin/state")

    def hits(self) -> list[dict[str, Any]]:
        return self._listener.log.read()

    def sidecar_request_from_attacker(self) -> int | None:
        return self._attacker_to_sidecar.request("POST", "/token", json={"kind": "app"}).status_code


class ComposeLab(Lab):
    """Runs inside the attacker container, so its requests really come from the attacker's address.

    The same process is also the referee: the lab key lets it reset the lab and read ground truth. The attack steps
    themselves never use that key.
    """

    def __init__(self, options: RunOptions) -> None:
        self.data_dir = Path(os.environ.get("LAB_DATA", "/data"))
        self._headers = {"X-Lab-Key": os.environ["LAB_ADMIN_KEY"]}
        self.graph_http = self.attacker_http = _client("http://fake-graph:8000")
        self._agent = _client(f"http://agent-{options.config.mode}:8001", timeout=600)
        self._listener = _client("http://localhost:9000")
        self._admin(self.graph_http, "POST", "/admin/reset")
        self._admin(self.graph_http, "POST", "/admin/consent", json=consent_for(options.config.controls))
        self._admin(self._listener, "POST", "/lab/clear")
        self._admin(
            self._agent,
            "POST",
            "/lab/configure",
            json={
                "backend": options.llm.backend,
                "model": options.llm.model,
                "script": str(options.llm.script) if options.llm.script else None,
                "assume_compromised": options.llm.assume_compromised,
                "approve": options.approve,
                "third_party": str(options.third_party),
            },
        )

    def _admin(self, client: Http, method: str, path: str, **kwargs: Any) -> Any:
        response = client.request(method, path, headers=self._headers, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f"{path}: {response.status_code} {response.text}")
        return response.json()

    def chat(self, name: str, message: str) -> str:
        response = self._agent.request(
            "POST", "/chat", json={"message": message}, headers={"Authorization": f"Bearer {self.copilot_token(name)}"}
        )
        if response.status_code >= 400:
            raise RuntimeError(f"agent: {response.status_code} {response.text}")
        return response.json()["reply"]

    def process_tickets(self) -> list[str]:
        return self._admin(self._agent, "POST", "/tickets/process")["replies"]

    def state(self) -> dict[str, Any]:
        return self._admin(self.graph_http, "GET", "/admin/state")

    def hits(self) -> list[dict[str, Any]]:
        return self._admin(self._listener, "GET", "/lab/hits")["value"]

    def sidecar_request_from_attacker(self) -> int | None:
        try:
            return _client("http://sidecar:8002", timeout=3).request("POST", "/token", json={"kind": "app"}).status_code
        except httpx.HTTPError:
            return None


def _client(base_url: str, timeout: float = 30) -> httpx.Client:
    return httpx.Client(base_url=base_url, timeout=timeout, trust_env=False)
