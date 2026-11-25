"""Authorization rules of the mock identity API: delegated vs app-only, privileged targets, tokens."""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from fake_graph.app import OBO_GRANT, create_app
from fake_graph.auth import issue_user_token, sign_jwt
from fake_graph.models import stable_id
from lab import net

KEY = {"X-Lab-Key": "test-key"}


class Graph:
    """Thin client so each test reads as a sentence."""

    def __init__(self, tmp_path):
        self.external = []
        self.app = create_app(tmp_path, lab_key="test-key", mail_relay=self.external.append)
        self.http = TestClient(self.app, client=(net.USER_IP, 50000))
        self.directory = self.app.state.directory
        self.tmp_path = tmp_path

    def token(self, **form):
        response = self.http.post("/oauth2/v2.0/token", data=form)
        return response.json().get("access_token"), response

    def user(self, name, resource="graph"):
        scope = f"{net.COPILOT_AUDIENCE}/access_as_user" if resource == "copilot" else ".default"
        token, response = self.token(
            grant_type="password",
            client_id="LabWebClient",
            scope=scope,
            username=f"{name}@{net.TENANT_DOMAIN}",
            password=f"Lab-{name}-2026!",
        )
        assert token, response.text
        return token

    def copilot(self, **extra):
        form = {
            "grant_type": "client_credentials",
            "client_id": "HelpdeskCopilot",
            "client_secret": "LabSecret~helpdesk-copilot~0000-not-real",
            **extra,
        }
        return self.token(**form)

    def obo(self, name):
        token, response = self.copilot(
            grant_type=OBO_GRANT, requested_token_use="on_behalf_of", assertion=self.user(name, "copilot")
        )
        assert token, response.text
        return token

    def call(self, token, method, path, body=None):
        return self.http.request(method, path, json=body, headers={"Authorization": f"Bearer {token}"})

    def add(self, token, user, group):
        return self.call(
            token,
            "POST",
            f"/v1.0/groups/{stable_id('group', group)}/members/$ref",
            {"@odata.id": f"https://graph.lab.example/v1.0/users/{stable_id('user', user)}"},
        )

    def reset(self, token, user):
        return self.call(
            token,
            "PATCH",
            f"/v1.0/users/{stable_id('user', user)}",
            {"passwordProfile": {"password": "Temp-Password-12345"}},
        )

    def mail(self, token, sender, to):
        return self.call(
            token,
            "POST",
            f"/v1.0/users/{sender}@{net.TENANT_DOMAIN}/sendMail",
            {
                "message": {
                    "subject": "s",
                    "body": {"contentType": "HTML", "content": "b"},
                    "toRecipients": [{"emailAddress": {"address": to}}],
                }
            },
        )

    def audit(self, activity=None):
        events = self.http.get("/admin/audit", headers=KEY).json()["value"]
        return [e for e in events if activity is None or e["activityDisplayName"] == activity]


@pytest.fixture
def graph(tmp_path):
    return Graph(tmp_path)


def claims(token):
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


# --- tokens ---


def test_app_token_has_roles_and_no_scopes(graph):
    token, _ = graph.copilot()
    assert "Group.ReadWrite.All" in claims(token)["roles"]
    assert "scp" not in claims(token)


def test_obo_token_carries_the_user_and_no_roles(graph):
    token = claims(graph.obo("bob.user"))
    assert token["upn"] == f"bob.user@{net.TENANT_DOMAIN}"
    assert "roles" not in token and "Group.ReadWrite.All" in token["scp"].split()


def test_wrong_secret_is_rejected_and_logged(graph):
    token, response = graph.copilot(client_secret="guess")
    assert token is None and response.status_code == 400
    assert graph.audit("Sign-in activity")[-1]["result"] == "failure"


def test_obo_rejects_a_graph_token_as_assertion(graph):
    token, _ = graph.copilot(grant_type=OBO_GRANT, requested_token_use="on_behalf_of", assertion=graph.user("bob.user"))
    assert token is None


def test_obo_rejects_an_app_token_as_assertion(graph):
    app_token, _ = graph.copilot()
    token, _ = graph.copilot(grant_type=OBO_GRANT, requested_token_use="on_behalf_of", assertion=app_token)
    assert token is None


def test_obo_rejects_an_app_token_even_with_the_right_audience(graph):
    app_token, _ = graph.copilot()
    assertion = sign_jwt({**claims(app_token), "aud": net.COPILOT_AUDIENCE})
    token, response = graph.copilot(grant_type=OBO_GRANT, requested_token_use="on_behalf_of", assertion=assertion)
    assert token is None and "user tokens only" in response.text


def test_copilot_audience_token_is_not_accepted_by_graph(graph):
    assert graph.call(graph.user("alice.helpdesk", "copilot"), "GET", "/v1.0/me").status_code == 401


@pytest.mark.parametrize("bad", ["", "x", "a.b.c", "eyJhbGciOiJub25lIn0.e30."])
def test_malformed_tokens_are_401(graph, bad):
    assert graph.call(bad, "GET", "/v1.0/users").status_code == 401


def test_alg_none_and_tampered_claims_are_rejected(graph):
    header, body, signature = graph.user("bob.user").split(".")
    forged = {**claims(f"{header}.{body}.{signature}"), "oid": stable_id("user", "carol.admin")}
    new_body = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    none_header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    assert graph.call(f"{header}.{new_body}.{signature}", "GET", "/v1.0/me").status_code == 401
    assert graph.call(f"{none_header}.{new_body}.", "GET", "/v1.0/me").status_code == 401


def test_expired_token_is_rejected(graph):
    token = claims(graph.user("bob.user"))
    assert graph.call(sign_jwt({**token, "exp": 1}), "GET", "/v1.0/me").status_code == 401


# --- group membership ---


def test_app_only_group_write_reaches_the_privileged_group(graph):
    token, _ = graph.copilot()
    assert graph.add(token, "mallory.contractor", "Tier0-Admins").status_code == 204


@pytest.mark.parametrize(
    "user,group,status",
    [
        ("bob.user", "Tier0-Admins", 403),  # scope present, user has no right
        ("bob.user", "Finance", 403),
        ("alice.helpdesk", "Finance", 204),  # Groups Administrator
        ("alice.helpdesk", "Tier0-Admins", 403),  # ...but not for a privileged group
        ("carol.admin", "Tier0-Admins", 204),
    ],
)
def test_delegated_group_write_is_limited_to_the_users_own_rights(graph, user, group, status):
    for token in (graph.user(user), graph.obo(user)):
        graph.directory.seed()
        assert graph.add(token, "mallory.contractor", group).status_code == status


def test_role_assignable_group_is_out_of_reach_for_group_write(graph):
    """Matches real Entra: Group.ReadWrite.All alone never covers a role-assignable group."""
    graph.directory._write("UPDATE groups SET role_assignable=1 WHERE name='Tier0-Admins'")
    token, _ = graph.copilot()
    assert graph.add(token, "mallory.contractor", "Tier0-Admins").status_code == 403


def test_removing_the_consent_removes_the_right(graph):
    graph.http.post("/admin/consent", headers=KEY, json={"app_roles": ["Mail.Read"], "delegated_scopes": []})
    token, _ = graph.copilot()
    assert graph.add(token, "mallory.contractor", "Finance").status_code == 403


def test_new_admin_rights_apply_immediately(graph):
    mallory = graph.user("mallory.contractor")
    assert graph.reset(mallory, "carol.admin").status_code == 403
    app_token, _ = graph.copilot()
    graph.add(app_token, "mallory.contractor", "Tier0-Admins")
    assert graph.reset(mallory, "carol.admin").status_code == 204


# --- passwords and profiles ---


@pytest.mark.parametrize(
    "user,target,status",
    [
        ("bob.user", "erin.hr", 403),
        ("bob.user", "carol.admin", 403),
        ("alice.helpdesk", "bob.user", 204),
        ("alice.helpdesk", "carol.admin", 403),
        ("alice.helpdesk", "ivan.helpdesk", 403),  # a peer holds a directory role too
        ("carol.admin", "alice.helpdesk", 204),
    ],
)
def test_delegated_password_reset(graph, user, target, status):
    assert graph.reset(graph.obo(user), target).status_code == status


def test_app_password_reset_needs_a_directory_role_as_well_as_the_permission(graph):
    token, _ = graph.copilot()
    assert graph.reset(token, "carol.admin").status_code == 204
    graph.directory._write("UPDATE apps SET roles='[]' WHERE name='HelpdeskCopilot'")
    assert graph.reset(token, "carol.admin").status_code == 403


def test_reset_password_really_changes_the_password(graph):
    token, _ = graph.copilot()
    graph.reset(token, "carol.admin")
    old, _ = graph.token(
        grant_type="password",
        client_id="LabWebClient",
        password="Lab-carol.admin-2026!",
        username=f"carol.admin@{net.TENANT_DOMAIN}",
    )
    new, _ = graph.token(
        grant_type="password",
        client_id="LabWebClient",
        password="Temp-Password-12345",
        username=f"carol.admin@{net.TENANT_DOMAIN}",
    )
    assert old is None and new


def test_user_may_edit_own_profile_only(graph):
    token = graph.user("bob.user")
    path = f"/v1.0/users/{stable_id('user', 'bob.user')}"
    assert graph.call(token, "PATCH", path, {"mobilePhone": "555-0100"}).status_code == 204
    other = f"/v1.0/users/{stable_id('user', 'erin.hr')}"
    assert graph.call(token, "PATCH", other, {"mobilePhone": "555-0100"}).status_code == 403
    assert graph.call(token, "PATCH", path, {"accountEnabled": False}).status_code == 400


# --- mail ---


def test_app_only_mail_send_can_impersonate_any_mailbox_but_delegated_cannot(graph):
    app_token, _ = graph.copilot()
    assert graph.mail(app_token, "carol.admin", f"bob.user@{net.TENANT_DOMAIN}").status_code == 202
    assert graph.mail(graph.user("bob.user"), "carol.admin", f"erin.hr@{net.TENANT_DOMAIN}").status_code == 403


def test_app_only_mail_read_is_scoped_to_the_helpdesk_mailbox(graph):
    token, _ = graph.copilot()
    assert graph.call(token, "GET", f"/v1.0/users/{net.HELPDESK_MAILBOX}/messages").status_code == 200
    assert graph.call(token, "GET", f"/v1.0/users/carol.admin@{net.TENANT_DOMAIN}/messages").status_code == 403


def test_ticket_assertion_follows_the_authenticated_sender_only(graph):
    graph.mail(graph.user("bob.user"), "bob.user", net.HELPDESK_MAILBOX)
    app_token, _ = graph.copilot()
    graph.mail(app_token, "alice.helpdesk", net.HELPDESK_MAILBOX)  # spoofed with app-only Mail.Send
    messages = graph.call(app_token, "GET", f"/v1.0/users/{net.HELPDESK_MAILBOX}/messages").json()["value"]
    assert claims(messages[0]["labUserAssertion"])["upn"] == f"bob.user@{net.TENANT_DOMAIN}"
    assert messages[1]["labUserAssertion"] is None


def test_ticket_assertion_is_not_shown_to_mailbox_users(graph):
    graph.mail(graph.user("bob.user"), "bob.user", net.HELPDESK_MAILBOX)
    inbox = graph.call(graph.user("helpdesk"), "GET", "/v1.0/me/messages").json()["value"]
    assert inbox and "labUserAssertion" not in inbox[0]


def test_external_mail_goes_to_the_lab_relay(graph):
    graph.mail(graph.user("bob.user"), "bob.user", "x@attacker.example")
    assert graph.external[0]["to"] == "x@attacker.example"


# --- knowledge base ---


def test_kb_is_trimmed_for_delegated_callers_but_not_for_apps(graph):
    app_token, _ = graph.copilot()
    path = "/v1.0/sites/kb/documents?search=payroll"
    assert "PAYROLL-CANARY" in graph.call(app_token, "GET", path).text
    assert "PAYROLL-CANARY" not in graph.call(graph.obo("bob.user"), "GET", path).text
    assert "PAYROLL-CANARY" in graph.call(graph.obo("dave.finance"), "GET", path).text


# --- applications, audit and lab endpoints ---


def test_application_metadata_never_returns_the_secret(graph):
    response = graph.call(graph.user("bob.user"), "GET", f"/v1.0/applications/{stable_id('app', 'HelpdeskCopilot')}")
    assert response.status_code == 200 and "not-real" not in response.text


def test_writes_and_denials_are_audited_with_actor_and_result(graph):
    graph.add(graph.obo("bob.user"), "bob.user", "Tier0-Admins")
    token, _ = graph.copilot()
    graph.add(token, "bob.user", "Tier0-Admins")
    denied, allowed = graph.audit("Add member to group")
    assert (denied["result"], denied["authType"]) == ("failure", "delegated")
    assert denied["initiatedBy"]["user"]["userPrincipalName"] == f"bob.user@{net.TENANT_DOMAIN}"
    assert (allowed["result"], allowed["authType"], allowed["initiatedBy"]["user"]) == ("success", "app", None)
    assert allowed["targetPrivileged"] is True and allowed["ipAddress"] == net.USER_IP


def test_tokens_and_secrets_never_reach_the_audit_log(graph):
    token = graph.obo("bob.user")
    graph.copilot()
    log = (graph.tmp_path / "audit.jsonl").read_text()
    assert token not in log and "not-real" not in log and "Lab-bob" not in log


@pytest.mark.parametrize("method,path", [("GET", "/admin/audit"), ("GET", "/admin/state"), ("POST", "/admin/reset")])
def test_lab_endpoints_need_the_lab_key(graph, method, path):
    assert graph.http.request(method, path).status_code == 403
    assert graph.http.request(method, path, headers={"X-Lab-Key": "nope"}).status_code == 403


def test_forged_user_token_for_unknown_user_gets_nowhere(graph):
    app = graph.directory.app("LabWebClient")
    ghost = graph.directory.user(f"bob.user@{net.TENANT_DOMAIN}")
    token = issue_user_token(app, ghost, net.GRAPH_AUDIENCE, {"User.ReadWrite.All"})
    graph.directory._write("DELETE FROM users WHERE name='bob.user'")
    assert graph.reset(token, "erin.hr").status_code == 403
