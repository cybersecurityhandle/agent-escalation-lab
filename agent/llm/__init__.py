"""Provider-neutral LLM interface with three backends: anthropic, ollama and scripted."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


class LLMError(Exception):
    pass


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    id: str
    name: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]


@dataclass
class Message:
    role: str  # user | assistant | tool
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    results: list[ToolResult] = field(default_factory=list)
    raw: Any = None  # provider content, replayed unchanged to the same provider


@dataclass
class Reply:
    text: str
    tool_calls: list[ToolCall]
    raw: Any = None
    refused: bool = False


class LLM(Protocol):
    name: str

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> Reply: ...


@dataclass(frozen=True)
class LLMSettings:
    backend: str = "scripted"
    model: str = ""
    script: Path | None = None
    assume_compromised: bool = False  # scripted only: follow the injection even when it is marked as data


def make_llm(settings: LLMSettings) -> LLM:
    """A new instance per session; backends may keep per-conversation state."""
    if settings.backend == "scripted":
        from agent.llm.scripted import ScriptedLLM

        if settings.script is None:
            raise LLMError("the scripted backend needs a script")
        return ScriptedLLM.from_file(settings.script, settings.assume_compromised)
    if settings.backend == "anthropic":
        from agent.llm.anthropic_backend import AnthropicLLM

        return AnthropicLLM(settings.model)
    if settings.backend == "ollama":
        from agent.llm.ollama_backend import OllamaLLM

        return OllamaLLM(settings.model)
    raise LLMError(f"unknown LLM backend: {settings.backend}")
