"""Destination parsing and the egress allowlist.

A URL is parsed once, into the host that will actually be contacted. The check and the request both use that value,
so a URL that two parsers would read differently cannot pass the check and then go somewhere else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_HOST = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")


class BadDestination(ValueError):
    pass


@dataclass(frozen=True)
class Destination:
    host: str
    path_and_query: str


def parse_url(url: str) -> Destination:
    if re.search(r"[\s\\\x00-\x1f]", url):
        raise BadDestination("URL contains whitespace, control characters or a backslash")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
        _ = parts.port
    except ValueError as exc:
        raise BadDestination("malformed URL") from exc
    if parts.scheme not in {"http", "https"} or "@" in parts.netloc or not _HOST.fullmatch(host):
        raise BadDestination("only plain http(s) URLs with a normal host name are supported")
    return Destination(host, (parts.path or "/") + (f"?{parts.query}" if parts.query else ""))


def parse_recipients(text: str) -> dict[str, str]:
    """Return {address: domain}. Any part that is not a plain address is an error, never ignored."""
    recipients = {}
    for part in (p.strip() for p in re.split(r"[;,]", text)):
        match = _EMAIL.fullmatch(part)
        if not match:
            raise BadDestination(f"not a plain e-mail address: {part!r}")
        recipients[part.lower()] = match.group(1).lower()
    return recipients
