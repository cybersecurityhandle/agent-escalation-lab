"""Deterministic fake model for CI.

It behaves like a model that obeys whatever instructions reach it. The injected steps run only if the payload text is
really present in the model's context, so a test fails when the payload was never delivered. By default it honours
spotlighting (text inside a marked block is data). With `assume_compromised` it does not, which is how the hardened
tests prove that the other controls hold when the model is fully hijacked.

Script format (scripted_llm.yaml):
  trigger:  regex for the injected instruction, or null when the attack needs no injection
  benign:   steps before, or without, a hijack
  hijacked: steps once the trigger has been seen
A step is either {tool, args} or {final: text}.
A step with `if: REGEX` is skipped unless the context matches.
Strings may use {{find:REGEX}}, {{urlfind:REGEX}}, {{conversation}}.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

from agent.guards.spotlighting import without_marked_data
from agent.llm import Message, Reply, ToolCall, ToolSpec


def transcript(messages: list[Message]) -> str:
    lines = []
    for message in messages:
        if message.text:
            lines.append(f"[{message.role}] {message.text}")
        lines += [f"[tool {r.name}] {r.content}" for r in message.results]
    return "\n".join(lines)


class ScriptedLLM:
    name = "scripted"

    def __init__(self, script: dict[str, Any], assume_compromised: bool = False) -> None:
        self._trigger = script.get("trigger")
        self._benign, self._hijacked = script["benign"], script.get("hijacked", [])
        self._assume_compromised = assume_compromised
        self._is_hijacked = False
        self._position = 0

    @classmethod
    def from_file(cls, path: Path, assume_compromised: bool = False) -> ScriptedLLM:
        return cls(yaml.safe_load(path.read_text(encoding="utf-8")), assume_compromised)

    def complete(self, system: str, messages: list[Message], tools: list[ToolSpec]) -> Reply:
        context = transcript(messages)
        if self._trigger and not self._is_hijacked:
            descriptions = "\n".join(tool.description for tool in tools)
            visible = context if self._assume_compromised else without_marked_data(context)
            if re.search(self._trigger, f"{descriptions}\n{visible}", re.S):
                self._is_hijacked, self._position = True, 0
        steps = self._hijacked if self._is_hijacked else self._benign
        while self._position < len(steps) and not re.search(steps[self._position].get("if", ""), context):
            self._position += 1
        step = steps[self._position] if self._position < len(steps) else {"final": "Done."}
        self._position += 1
        if "final" in step:
            return Reply(_render(step["final"], context), [])
        args = {key: _render(value, context) for key, value in step.get("args", {}).items()}
        return Reply("", [ToolCall(f"call-{self._position}-{int(self._is_hijacked)}", step["tool"], args)])


def _render(text: str, context: str) -> str:
    def replace(match: re.Match[str]) -> str:
        kind, pattern = match.group(1), match.group(2)
        if kind == "conversation":
            return context
        found = ",".join(dict.fromkeys(re.findall(pattern, context)))
        return quote(found) if kind == "urlfind" else found

    return re.sub(r"\{\{(conversation|find|urlfind)(?::(.+?))?\}\}(?!\})", replace, text)
