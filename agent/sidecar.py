"""Token sidecar: holds the client secret so the agent process does not.

It accepts requests from the agent's address only, and in Docker Compose it also sits on a network that only the
agent shares. A caller who controls the agent can still obtain tokens through it. What it stops is the secret
leaving, to be reused from somewhere else for as long as it stays valid.
"""

from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from agent.graph import GraphError, Http, SecretCredential


class TokenRequest(BaseModel):
    kind: str
    assertion: str = ""
    correlation_id: str = ""


def create_sidecar(graph_http: Http, client_id: str, client_secret: str, allowed_ips: set[str]) -> FastAPI:
    credential = SecretCredential(graph_http, client_id, client_secret)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/token")
    def token(body: TokenRequest, request: Request) -> dict[str, str]:
        if request.client is None or request.client.host not in allowed_ips:
            raise HTTPException(403, "caller is not the agent")
        try:
            if body.kind == "app":
                return {"access_token": credential.app_token(body.correlation_id)}
            if body.kind == "obo":
                return {"access_token": credential.obo_token(body.assertion, body.correlation_id)}
        except GraphError as exc:
            raise HTTPException(502, "token endpoint refused the request") from exc
        raise HTTPException(400, "unknown token kind")

    return app


def from_env() -> FastAPI:
    graph = httpx.Client(base_url=os.environ["COPILOT_GRAPH_URL"], timeout=10, trust_env=False)
    return create_sidecar(
        graph,
        os.environ["COPILOT_CLIENT_ID"],
        os.environ["COPILOT_CLIENT_SECRET"],
        set(os.environ["SIDECAR_ALLOWED_IPS"].split(",")),
    )
