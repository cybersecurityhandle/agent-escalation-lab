"""Detections fire on every attack, stay quiet on ordinary work, and the evaluator fails loudly."""

import pytest

from agent.config import Controls
from detections.evaluate import RuleError, _Condition, evaluate_events, load_rules, lookup
from lab import net
from scenarios.harness import SCENARIOS
from tests.conftest import HARDENED

EXPECTED_RULES = {
    "s01": {"lab-s01-priv-group-add-by-sp"},
    "s02": {"lab-s02-exfil-after-sensitive-read"},
    "s03": {"lab-s03-confused-deputy-reset", "lab-s03-reset-for-non-it"},
    "s04": {"lab-s04-unpinned-tool", "lab-s04-agent-external-mail"},
    # S05 ends in a tier 0 group change made with the stolen app identity, so the S01 rule is right to fire as well.
    "s05": {"lab-s05-sp-signin-unexpected-source", "lab-s01-priv-group-add-by-sp"},
}


def rules_hit(lab):
    return {hit.rule_id for hit in evaluate_events(lab.audit(), lab.trace())}


def user_tool(tool, **args):
    return [{"tool": tool, "args": args}, {"final": "Done."}]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_vulnerable_attack_triggers_its_own_rules_and_no_others(run, scenario):
    """Exact match: a rule that fires on another scenario's traffic would be too broad."""
    assert {hit.rule_id for hit in run(scenario, "vulnerable").detections} == EXPECTED_RULES[scenario]


def test_s02_fetch_variant_is_detected_too(run):
    assert EXPECTED_RULES["s02"] <= {h.rule_id for h in run("s02", "vulnerable", variant="fetch").detections}


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_hardened_attempt_is_visible(run, scenario):
    assert "lab-agent-control-denied" in {hit.rule_id for hit in run(scenario, "hardened").detections}


# --- false positives: ordinary work in the vulnerable deployment, where nothing is blocked ---

BENIGN = {
    "helpdesk resets a normal password": ("alice.helpdesk", user_tool("reset_password", user="bob.user")),
    "helpdesk adds someone to a normal group": (
        "alice.helpdesk",
        user_tool("add_to_group", user="bob.user", group="Finance"),
    ),
    "admin added to a normal group": ("alice.helpdesk", user_tool("add_to_group", user="carol.admin", group="Finance")),
    "VPN question reads a confidential guide": ("bob.user", user_tool("search_kb", query="vpn setup")),
    "confidential guide then intranet page": (
        "bob.user",
        [
            {"tool": "search_kb", "args": {"query": "vpn"}},
            {"tool": "fetch_url", "args": {"url": f"http://{net.INTRANET_HOST}/intranet/status"}},
            {"final": "ok"},
        ],
    ),
    "internal mail": ("bob.user", user_tool("send_email", to=f"erin.hr@{net.TENANT_DOMAIN}", subject="s", body="b")),
    "mail to a listed partner": (
        "bob.user",
        user_tool("send_email", to=f"desk@{net.PARTNER_DOMAIN}", subject="s", body="b"),
    ),
    "pinned third-party tool": ("bob.user", user_tool("timezone_helper", city="Tokyo")),
    "helpdesk runs diagnostics": ("alice.helpdesk", user_tool("run_diagnostics")),
}


@pytest.mark.parametrize("name", BENIGN)
def test_benign_traffic_triggers_nothing(make_lab, name):
    user, steps = BENIGN[name]
    lab = make_lab(Controls(), steps)
    lab.chat(user, "Please help.")
    tools = [e for e in lab.trace() if e["event"] == "tool_call"]
    assert tools and all(e["outcome"] == "ok" for e in tools), tools
    assert rules_hit(lab) == set()


@pytest.mark.parametrize(
    "requester,target,expected",
    [
        ("alice.helpdesk", "carol.admin", {"lab-s03-confused-deputy-reset"}),  # Helpdesk may not reset administrators
        ("bob.user", "erin.hr", {"lab-s03-reset-for-non-it"}),  # ordinary target, still not Bob's to reset
        ("carol.admin", "carol.admin", set()),  # tier 0 acting on tier 0
    ],
)
def test_reset_rules_depend_on_both_requester_and_target(make_lab, requester, target, expected):
    lab = make_lab(Controls(), user_tool("reset_password", user=target))
    lab.chat(requester, "Please reset the password.")
    assert rules_hit(lab) == expected


def test_off_allowlist_fetch_without_a_sensitive_read_is_not_exfiltration(make_lab):
    lab = make_lab(
        Controls(),
        [
            {"tool": "search_kb", "args": {"query": "printer"}},
            {"tool": "fetch_url", "args": {"url": f"http://{net.EXFIL_HOST}/x"}},
            {"final": "ok"},
        ],
    )
    lab.chat("bob.user", "Printer help")
    assert lab.hits() and rules_hit(lab) == set()


def test_admin_managing_tier0_by_hand_triggers_nothing(make_lab):
    from fake_graph.models import stable_id

    lab = make_lab(Controls(), [{"final": "x"}])
    response = lab.must_sign_in("carol.admin").call(
        "POST",
        f"/v1.0/groups/{stable_id('group', 'Tier0-Admins')}/members/$ref",
        json={"@odata.id": f"/v1.0/users/{stable_id('user', 'ivan.helpdesk')}"},
    )
    assert response.status_code == 204 and rules_hit(lab) == set()


def test_benign_ticket_triggers_nothing_in_either_mode(make_lab):
    for controls in (Controls(), HARDENED):
        lab = make_lab(controls, [{"tool": "read_tickets", "args": {}}, {"final": "ok"}])
        lab.must_sign_in("bob.user").send_mail("bob.user", net.HELPDESK_MAILBOX, "Printer", "Printer is jammed")
        lab.process_tickets()
        assert rules_hit(lab) == set()


# --- the rules and the evaluator ---


def test_rules_are_well_formed():
    rules = load_rules()
    assert len({r["id"] for r in rules}) == len({r["name"] for r in rules}) == len(rules)
    for rule in rules:
        assert {"title", "status", "level", "description"} <= set(rule)
        assert ("detection" in rule and "logsource" in rule) or "correlation" in rule


def test_lookup_walks_lists():
    event = {"targetResources": [{"id": "a"}, {"id": "b"}], "requester": {"groups": ["x", "y"]}}
    assert lookup(event, "targetResources.id") == ["a", "b"]
    assert lookup(event, "requester.groups") == ["x", "y"]
    assert lookup(event, "missing.path") == []


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("a", True),
        ("not a", False),
        ("a and b", False),
        ("a or b", True),
        ("a and not b", True),
        ("not (a and b)", True),
        ("1 of *", True),
        ("all of *", False),
        ("b or (a and not b)", True),
    ],
)
def test_conditions(condition, expected):
    detection = {"a": {"x": 1}, "b": {"x": 2}, "condition": condition}
    assert _Condition(condition, detection).evaluate({"x": 1}) is expected


@pytest.mark.parametrize(
    "field,value,event,expected",
    [
        ("ip|cidr", "10.0.0.0/8", {"ip": "10.1.2.3"}, True),
        ("ip|cidr", "10.0.0.0/8", {"ip": "bogus"}, False),
        ("t|contains|all", ["a", "b"], {"t": "xaxb"}, True),
        ("t|contains|all", ["a", "z"], {"t": "xaxb"}, False),
        ("t|startswith", "Ab", {"t": "abc"}, True),
        ("t|re", "^a.c$", {"t": "abc"}, True),
        ("t", "a*", {"t": "abc"}, True),
        ("flag", True, {"flag": "true"}, False),
        ("flag", False, {}, False),
        ("gone", None, {}, True),
    ],
)
def test_field_modifiers(field, value, event, expected):
    assert _Condition("s", {"s": {field: value}}).evaluate(event) is expected


@pytest.mark.parametrize("bad", ["missing", "a and", "(a", "a b", "1 of zzz*"])
def test_bad_conditions_raise_instead_of_passing_quietly(bad):
    with pytest.raises(RuleError):
        _Condition(bad, {"a": {"x": 1}}).evaluate({"x": 1})


def test_unknown_logsource_and_modifier_raise():
    base = {"name": "n", "title": "t", "level": "low", "_file": "f"}
    detection = {"s": {"x|base64": "y"}, "condition": "s"}
    event = {"product": "agent_trace", "x": "z", "timestamp": "2026-01-01T00:00:00Z", "event": "e"}
    with pytest.raises(RuleError):
        evaluate_events([], [event], [{**base, "logsource": {"product": "windows"}, "detection": detection}])
    with pytest.raises(RuleError):
        evaluate_events([], [event], [{**base, "logsource": {"product": "agent_trace"}, "detection": detection}])


def _correlation(kind, events):
    def rule(name, value):
        return {
            "name": name,
            "title": name,
            "level": "informational",
            "_file": "f",
            "logsource": {"product": "agent_trace"},
            "detection": {"s": {"event": value}, "condition": "s"},
        }

    correlation = {
        "name": "c",
        "title": "c",
        "level": "high",
        "_file": "f",
        "correlation": {"type": kind, "rules": ["r1", "r2"], "group-by": ["correlationId"], "timespan": "5m"},
    }
    trace = [
        {"product": "agent_trace", "event": e, "correlationId": c, "timestamp": f"2026-01-01T00:{m:02}:00Z"}
        for e, c, m in events
    ]
    return [h.rule_id for h in evaluate_events([], trace, [rule("r1", "one"), rule("r2", "two"), correlation])]


@pytest.mark.parametrize(
    "kind,events,expected",
    [
        ("temporal_ordered", [("one", "a", 0), ("two", "a", 1)], ["c"]),
        ("temporal_ordered", [("two", "a", 0), ("one", "a", 1)], []),  # wrong order
        ("temporal", [("two", "a", 0), ("one", "a", 1)], ["c"]),
        ("temporal", [("one", "a", 0), ("two", "b", 1)], []),  # different session
        ("temporal", [("one", "a", 0), ("two", "a", 9)], []),  # outside the time span
        ("temporal", [("one", "a", 0)], []),
    ],
)
def test_correlation(kind, events, expected):
    assert _correlation(kind, events) == expected
