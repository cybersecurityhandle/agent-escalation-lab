"""agent_trace.jsonl: every LLM turn and tool call, for demos and detections."""

from __future__ import annotations

from typing import Any

from lab.jsonl import JsonlLog, utcnow

_MAX_TEXT = 2000


class Trace:
    def __init__(self, log: JsonlLog, session_id: str, mode: str, requester: dict[str, Any]) -> None:
        self._log = log
        self._common = {"product": "agent_trace", "correlationId": session_id, "mode": mode, "requester": requester}

    def event(self, event: str, **fields: Any) -> None:
        self._log.append({"timestamp": utcnow(), "event": event, **self._common, **_clip(fields)})


def _clip(value: Any) -> Any:
    if isinstance(value, str):
        return value if len(value) <= _MAX_TEXT else value[:_MAX_TEXT] + "...[clipped]"
    if isinstance(value, dict):
        return {key: _clip(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clip(item) for item in value]
    return value
