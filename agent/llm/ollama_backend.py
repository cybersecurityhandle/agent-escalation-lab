"""Ollama backend for a local model. Point OLLAMA_URL at the server."""

from __future__ import annotations

import os
from typing import Any

import httpx

from agent.llm import LLMError, Message, Reply, ToolCall, ToolSpec

DEFAULT_MODEL = "qwen3:8b"


class OllamaLLM:
    name = "ollama"

    def __init__(self, model: str = "", client: httpx.Client | None = None) -> None:
        self.model = model or os.environ.get("LLM_MODEL") or DEFAULT_MODEL
        url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
        self._client = client or httpx.Client(base_url=url, timeout=300, trust_env=False)

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> Reply:
        body = {
            "model": self.model,
            "stream": False,
            "messages": [{"role": "system", "content": system}, *(m for msg in messages for m in _to_api(msg))],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
                }
                for t in tools
            ],
        }
        try:
            response = self._client.post("/api/chat", json=body)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMError(f"ollama request failed: {exc}") from exc
        message = response.json()["message"]
        calls = [
            ToolCall(f"call-{len(messages)}-{i}", c["function"]["name"], dict(c["function"]["arguments"] or {}))
            for i, c in enumerate(message.get("tool_calls") or [])
        ]
        return Reply(message.get("content", ""), calls, raw=message)


def _to_api(message: Message) -> list[dict[str, Any]]:
    if message.role == "assistant":
        return [message.raw]
    if message.role == "tool":
        return [{"role": "tool", "tool_name": r.name, "content": r.content} for r in message.results]
    return [{"role": "user", "content": message.text}]
