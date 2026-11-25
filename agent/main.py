"""The copilot as a service. Docker Compose runs one instance per mode."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from agent.config import load_config
from agent.core import Runtime
from agent.graph import Credential, GraphError, SecretCredential, SidecarCredential
from agent.guards.approval import SimulatedApprover
from agent.llm import LLMError, LLMSettings, make_llm
from agent.web import LabWeb
from lab import net
from lab.jsonl import JsonlLog


class ChatRequest(BaseModel):
    message: str


class LabConfig(BaseModel):
    backend: str
    model: str = ""
    script: str | None = None
    assume_compromised: bool = False
    approve: bool = False
    third_party: str


def build_runtime(env: dict[str, str]) -> Runtime:
    config = load_config(env["LAB_MODE"])
    graph = _client(env["COPILOT_GRAPH_URL"])
    if config.controls.secret_isolation:
        credential: Credential = SidecarCredential(_client(env["COPILOT_SIDECAR_URL"]))
    else:
        credential = SecretCredential(graph, env["COPILOT_CLIENT_ID"], env["COPILOT_CLIENT_SECRET"])
    web = LabWeb(
        {
            net.EXFIL_HOST: _client(f"http://{net.EXFIL_HOST}:9000"),
            net.INTRANET_HOST: _client(f"http://{net.INTRANET_HOST}:8000"),
        }
    )
    trace = JsonlLog(Path(env.get("LAB_DATA", "runs")) / "agent_trace.jsonl")
    return Runtime(config, graph, credential, web, trace, lambda: make_llm(LLMSettings()), env)


def create_agent_app(runtime: Runtime, lab_key: str) -> FastAPI:
    app = FastAPI(title="HelpdeskCopilot", docs_url=None, redoc_url=None, openapi_url=None)

    def check_key(x_lab_key: str) -> None:
        if not hmac.compare_digest(x_lab_key.encode(), lab_key.encode()):
            raise HTTPException(403, "lab key required")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "mode": runtime.config.mode}

    @app.post("/chat")
    def chat(body: ChatRequest, authorization: str = Header(default="")) -> dict[str, str]:
        try:
            return {"reply": runtime.chat(authorization.removeprefix("Bearer "), body.message)}
        except GraphError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        except LLMError as exc:
            raise HTTPException(502, f"model error: {exc}") from exc

    @app.post("/tickets/process")
    def tickets(x_lab_key: str = Header(default="")) -> dict[str, Any]:
        check_key(x_lab_key)  # stands in for a scheduler
        try:
            return {"replies": runtime.process_tickets()}
        except LLMError as exc:
            raise HTTPException(502, f"model error: {exc}") from exc

    @app.post("/lab/configure")
    def configure(body: LabConfig, x_lab_key: str = Header(default="")) -> dict[str, str]:
        check_key(x_lab_key)
        settings = LLMSettings(
            body.backend, body.model, Path(body.script) if body.script else None, body.assume_compromised
        )
        runtime.llm_factory = lambda: make_llm(settings)
        runtime.approver = SimulatedApprover(body.approve)
        runtime.third_party = [Path(body.third_party)]
        runtime.trace_log.clear()
        return {"status": "configured"}

    return app


def _client(base_url: str) -> httpx.Client:
    return httpx.Client(base_url=base_url, timeout=30, trust_env=False)


def from_env() -> FastAPI:
    return create_agent_app(build_runtime(dict(os.environ)), os.environ["LAB_ADMIN_KEY"])
