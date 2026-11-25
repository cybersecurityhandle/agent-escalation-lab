"""Anthropic API backend (optional extra). Credentials come from the SDK's normal resolution, e.g. ANTHROPIC_API_KEY.

No refusal fallback is configured on purpose: silently switching to another model would make a result say nothing
about the model under test. A refusal is recorded as a refusal.
"""

from __future__ import annotations

import os
from typing import Any

from agent.llm import LLMError, Message, Reply, ToolCall, ToolSpec

DEFAULT_MODEL = "claude-opus-5-5"
MAX_TOKENS = 16000


class AnthropicLLM:
    name = "anthropic"

    def __init__(self, model: str = "", client: Any = None) -> None:
        try:
            import anthropic
        except ImportError as exc:
            raise LLMError("install the 'anthropic' extra: uv sync --extra anthropic") from exc
        self._sdk = anthropic
        self.model = model or os.environ.get("LLM_MODEL") or DEFAULT_MODEL
        self._client = client or anthropic.Anthropic()

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> Reply:
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=[_to_api(m) for m in messages],
                tools=[{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools],
            )
        except self._sdk.AuthenticationError as exc:
            raise LLMError("the API rejected the credentials") from exc
        except self._sdk.NotFoundError as exc:
            raise LLMError(f"unknown model: {self.model}") from exc
        except self._sdk.APIStatusError as exc:
            raise LLMError(f"API error {exc.status_code}: {exc.message}") from exc
        except TypeError as exc:  # the SDK's way of saying that it found no credentials
            if "authentication" not in str(exc):
                raise
            raise LLMError("no API credentials: set ANTHROPIC_API_KEY in .env") from exc
        except self._sdk.APIConnectionError as exc:
            raise LLMError("could not reach the API") from exc
        if response.stop_reason == "refusal":
            return Reply("[model refused]", [], raw=response.content, refused=True)
        if response.stop_reason == "max_tokens":
            raise LLMError("reply was cut off at max_tokens")
        text = "\n".join(block.text for block in response.content if block.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in response.content if b.type == "tool_use"]
        return Reply(text, calls, raw=response.content)


def _to_api(message: Message) -> dict[str, Any]:
    if message.role == "assistant":
        return {"role": "assistant", "content": message.raw}  # unchanged, including thinking blocks
    if message.role == "tool":
        return {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": r.id, "content": r.content, "is_error": r.is_error}
                for r in message.results
            ],
        }
    return {"role": "user", "content": message.text}
