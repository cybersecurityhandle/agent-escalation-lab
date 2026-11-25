"""Third-party tool definitions: loading, hashing and pinning.

A definition is data, not code. Its text goes into the model's context, which is why a changed description is an
attack even when the implementation is untouched. `implementation` picks from a fixed list of lab functions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from agent.guards.pipeline import PreparedCall
from agent.tools import BUILTIN_TOOLS, Tool

if TYPE_CHECKING:
    from agent.core import Session

THIRD_PARTY_DIR = Path(__file__).parent / "third_party"
DEFAULT_THIRD_PARTY = THIRD_PARTY_DIR / "timezone_helper.yaml"
PINS_FILE = THIRD_PARTY_DIR / "pins.yaml"

_OFFSETS = {"london": 0, "berlin": 1, "new york": -5, "tokyo": 9, "sydney": 11}


def _timezone(session: Session, call: PreparedCall) -> str:
    city = str(call.args.get("city", "")).lower()
    if city not in _OFFSETS:
        return "Unknown city."
    return f"Local time in {city.title()}: {datetime.now(UTC) + timedelta(hours=_OFFSETS[city]):%H:%M}"


_IMPLEMENTATIONS = {"timezone": _timezone}


@dataclass(frozen=True)
class LoadedTool:
    tool: Tool
    sha256: str
    pin_status: str  # pinned | mismatch | unpinned


def definition_hash(definition: dict[str, Any]) -> str:
    """Hash over everything the model sees plus the implementation name."""
    return hashlib.sha256(json.dumps(definition, sort_keys=True).encode()).hexdigest()


def load_third_party(path: Path) -> LoadedTool:
    definition = yaml.safe_load(path.read_text(encoding="utf-8"))
    pins = yaml.safe_load(PINS_FILE.read_text(encoding="utf-8"))
    digest, name = definition_hash(definition), definition["name"]
    if name in {tool.name for tool in BUILTIN_TOOLS}:
        raise ValueError(f"third-party tool may not shadow built-in {name!r}")
    status = "unpinned" if name not in pins else "pinned" if pins[name] == digest else "mismatch"
    tool = Tool(
        name,
        definition["description"],
        definition["parameters"],
        lambda session, args: PreparedCall(name, args, "Tool", name, third_party=True),
        _IMPLEMENTATIONS[definition["implementation"]],
    )
    return LoadedTool(tool, digest, status)
