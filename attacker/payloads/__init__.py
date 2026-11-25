"""Payload files. Each starts with a comment header, separated from the payload by a line of dashes."""

from pathlib import Path

HERE = Path(__file__).parent


def load(name: str) -> str:
    text = (HERE / name).read_text(encoding="utf-8")
    _, separator, payload = text.partition("\n-----\n")
    if not separator:
        raise ValueError(f"{name} has no header separator")
    return payload.strip()
