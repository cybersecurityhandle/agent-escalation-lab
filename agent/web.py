"""Outbound web access for the agent.

LabWeb is a safety fence, separate from the `egress_allowlist` control: even in vulnerable mode the agent can only
reach hosts that are part of the lab. A model that invents a real URL gets a connection error, not the internet.
"""

from __future__ import annotations

from agent.graph import Http
from agent.guards.egress import Destination

_MAX_BODY = 4000


class WebError(Exception):
    pass


class LabWeb:
    def __init__(self, routes: dict[str, Http]) -> None:
        self._routes = routes

    def fetch(self, destination: Destination) -> str:
        client = self._routes.get(destination.host)
        if client is None:
            raise WebError(f"could not connect to {destination.host}")
        response = client.request("GET", destination.path_and_query, follow_redirects=False)
        return response.text[:_MAX_BODY]
