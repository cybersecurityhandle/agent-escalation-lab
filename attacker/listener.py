"""Attacker-controlled listener: records every request it receives, plus mail sent to attacker.example.

In Compose this is its own container on a fixed address. Scenarios read the hits to prove that data really left.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

from lab.jsonl import JsonlLog, utcnow

MAX_BODY = 64_000


class Listener:
    def __init__(self, path: Path) -> None:
        self.log = JsonlLog(path)

    def record(self, kind: str, **fields: Any) -> None:
        self.log.append({"timestamp": utcnow(), "kind": kind, **fields})

    def mail(self, message: dict[str, Any]) -> None:
        self.record("mail", **message)


def create_listener_app(listener: Listener, lab_key: str) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def check_key(x_lab_key: str) -> None:
        if not hmac.compare_digest(x_lab_key.encode(), lab_key.encode()):
            raise HTTPException(403, "lab key required")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/lab/hits")
    def hits(x_lab_key: str = Header(default="")) -> dict[str, Any]:
        check_key(x_lab_key)
        return {"value": listener.log.read()}

    @app.post("/lab/clear")
    def clear(x_lab_key: str = Header(default="")) -> dict[str, str]:
        check_key(x_lab_key)
        listener.log.clear()
        return {"status": "cleared"}

    @app.post("/smtp")
    async def smtp(request: Request) -> dict[str, str]:
        listener.mail(await request.json())
        return {"status": "accepted"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT"], response_class=PlainTextResponse)
    async def catch_all(path: str, request: Request) -> str:
        body = (await request.body())[:MAX_BODY].decode("utf-8", "replace")
        listener.record(
            "http",
            method=request.method,
            path=f"/{path}",
            query=dict(request.query_params),
            body=body,
            source=request.client.host if request.client else None,
        )
        return "ok"

    return app


def from_env() -> FastAPI:
    data = Path(os.environ.get("LAB_DATA", "runs"))
    return create_listener_app(Listener(data / "listener.jsonl"), os.environ["LAB_ADMIN_KEY"])
