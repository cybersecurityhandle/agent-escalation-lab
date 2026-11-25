"""How the agent gets tokens and calls fake-graph."""

from __future__ import annotations

from typing import Any, Protocol

OBO_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class Http(Protocol):
    """Satisfied by httpx.Client and by starlette's TestClient (in-process runs)."""

    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...


class GraphError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class Credential(Protocol):
    def app_token(self, correlation_id: str) -> str: ...

    def obo_token(self, assertion: str, correlation_id: str) -> str: ...


class SecretCredential:
    """Holds the client secret in this process. Convenient, and the root cause of scenario S05."""

    def __init__(self, http: Http, client_id: str, client_secret: str) -> None:
        self._http, self._client_id, self._secret = http, client_id, client_secret

    def _token(self, correlation_id: str, **form: str) -> str:
        data = {"client_id": self._client_id, "client_secret": self._secret, **form}
        response = self._http.request(
            "POST", "/oauth2/v2.0/token", data=data, headers={"client-request-id": correlation_id}
        )
        if response.status_code != 200:
            raise GraphError(response.status_code, f"token request failed: {response.json().get('error_description')}")
        return response.json()["access_token"]

    def app_token(self, correlation_id: str) -> str:
        return self._token(correlation_id, grant_type="client_credentials", scope=".default")

    def obo_token(self, assertion: str, correlation_id: str) -> str:
        return self._token(
            correlation_id,
            grant_type=OBO_GRANT,
            requested_token_use="on_behalf_of",
            assertion=assertion,
            scope=".default",
        )


class SidecarCredential:
    """Asks the token sidecar. The agent process never holds the secret."""

    def __init__(self, http: Http) -> None:
        self._http = http

    def _token(self, body: dict[str, str]) -> str:
        response = self._http.request("POST", "/token", json=body)
        if response.status_code != 200:
            raise GraphError(response.status_code, "token sidecar refused the request")
        return response.json()["access_token"]

    def app_token(self, correlation_id: str) -> str:
        return self._token({"kind": "app", "correlation_id": correlation_id})

    def obo_token(self, assertion: str, correlation_id: str) -> str:
        return self._token({"kind": "obo", "assertion": assertion, "correlation_id": correlation_id})


class GraphClient:
    def __init__(self, http: Http, token: str, correlation_id: str) -> None:
        self._http, self._token, self._correlation_id = http, token, correlation_id

    def call(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = {"Authorization": f"Bearer {self._token}", "client-request-id": self._correlation_id}
        response = self._http.request(method, path, headers=headers, **kwargs)
        if response.status_code >= 400:
            detail = response.json()
            message = detail.get("error", {}).get("message") or detail.get("detail") or "request failed"
            raise GraphError(response.status_code, str(message))
        return response.json() if response.content else None
