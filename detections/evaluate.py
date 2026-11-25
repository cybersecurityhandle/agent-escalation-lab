"""A small Sigma evaluator, so the rules can run without a SIEM.

Supported: field matching on dotted paths, lists (any of), the modifiers contains, startswith, endswith, re, cidr and
all, `and`/`or`/`not`/parentheses, `1 of x*`, `all of x*`, and the correlation types `temporal` and
`temporal_ordered`. Anything else raises an error. A rule this evaluator cannot read must not pass as "no hits".
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from lab.jsonl import read_jsonl

RULE_DIR = Path(__file__).parent / "sigma"
Event = dict[str, Any]

# logsource -> which events a rule looks at
_SERVICES = {
    ("fake_graph", "audit"): lambda e: e.get("product") == "fake_graph" and e.get("category") == "AuditLogs",
    ("fake_graph", "signin"): lambda e: e.get("product") == "fake_graph" and "SignInLogs" in e.get("category", ""),
    ("agent_trace", None): lambda e: e.get("product") == "agent_trace",
}


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Hit:
    rule_id: str
    title: str
    level: str
    timestamp: str
    summary: str


# --- field matching --------------------------------------------------------------------------------------


def lookup(event: Any, path: str) -> list[Any]:
    """All values at a dotted path. Lists are searched element by element."""
    values = [event]
    for key in path.split("."):
        found = []
        for value in values:
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, dict) and key in item:
                    found.append(item[key])
        values = found
    return [v for value in values for v in (value if isinstance(value, list) else [value])]


def _compare(actual: Any, expected: Any, modifier: str | None) -> bool:
    if modifier == "cidr":
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(expected)
        except ValueError:
            return False
    if modifier == "re":
        return re.search(expected, str(actual)) is not None
    if expected is None or isinstance(expected, bool):
        return actual is expected
    left, right = str(actual).lower(), str(expected).lower()
    match modifier:
        case None:
            return fnmatch.fnmatchcase(left, right) if "*" in right else left == right
        case "contains":
            return right in left
        case "startswith":
            return left.startswith(right)
        case "endswith":
            return left.endswith(right)
    raise RuleError(f"unsupported modifier: {modifier}")


def _match_field(event: Event, spec: str, expected: Any) -> bool:
    path, *modifiers = spec.split("|")
    need_all = "all" in modifiers
    rest = [m for m in modifiers if m != "all"]
    if len(rest) > 1:
        raise RuleError(f"unsupported modifier chain: {spec}")
    modifier = rest[0] if rest else None
    wanted = expected if isinstance(expected, list) else [expected]
    actual = lookup(event, path) or ([None] if None in wanted else [])
    checks = [any(_compare(value, item, modifier) for value in actual) for item in wanted]
    return all(checks) if need_all else any(checks)


def _match_selection(event: Event, selection: Any) -> bool:
    if isinstance(selection, list):
        return any(_match_selection(event, item) for item in selection)
    if not isinstance(selection, dict):
        raise RuleError("keyword selections are not supported")
    return all(_match_field(event, spec, expected) for spec, expected in selection.items())


# --- conditions --------------------------------------------------------------------------------------------


class _Condition:
    """Recursive descent parser for the condition string."""

    def __init__(self, text: str, detection: dict[str, Any]) -> None:
        self._tokens = re.findall(r"\(|\)|[\w*]+", text)
        self._names = {key: value for key, value in detection.items() if key != "condition"}
        self._position = 0

    def evaluate(self, event: Event) -> bool:
        self._position = 0
        value = self._or(event)
        if self._position != len(self._tokens):
            raise RuleError(f"cannot parse condition near {self._peek()!r}")
        return value

    def _peek(self) -> str:
        return self._tokens[self._position] if self._position < len(self._tokens) else ""

    def _next(self) -> str:
        token = self._peek()
        self._position += 1
        return token

    def _or(self, event: Event) -> bool:
        value = self._and(event)
        while self._peek() == "or":
            self._next()
            right = self._and(event)
            value = value or right
        return value

    def _and(self, event: Event) -> bool:
        value = self._not(event)
        while self._peek() == "and":
            self._next()
            right = self._not(event)
            value = value and right
        return value

    def _not(self, event: Event) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not(event)
        return self._atom(event)

    def _atom(self, event: Event) -> bool:
        token = self._next()
        if token == "(":
            value = self._or(event)
            if self._next() != ")":
                raise RuleError("missing closing parenthesis")
            return value
        if token in {"1", "all"} and self._peek() == "of":
            self._next()
            pattern = self._next()
            names = [n for n in self._names if pattern == "them" or fnmatch.fnmatchcase(n, pattern)]
            if not names:
                raise RuleError(f"no selection matches {pattern!r}")
            results = [_match_selection(event, self._names[n]) for n in names]
            return any(results) if token == "1" else all(results)
        if token not in self._names:
            raise RuleError(f"unknown selection: {token!r}")
        return _match_selection(event, self._names[token])


# --- rules -------------------------------------------------------------------------------------------------


def load_rules(directory: Path = RULE_DIR) -> list[dict[str, Any]]:
    rules = []
    for path in sorted(directory.glob("*.yml")):
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if document:
                rules.append({**document, "_file": path.name})
    return rules


def _matches(rule: dict[str, Any], events: list[Event]) -> list[Event]:
    source = rule["logsource"]
    key = (source.get("product"), source.get("service"))
    if key not in _SERVICES:
        raise RuleError(f"{rule['_file']}: unknown logsource {key}")
    condition = _Condition(rule["detection"]["condition"], rule["detection"])
    return [event for event in events if _SERVICES[key](event) and condition.evaluate(event)]


def _time(event: Event) -> datetime:
    return datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))


def _timespan(text: str) -> timedelta:
    match = re.fullmatch(r"(\d+)([smh])", text)
    if not match:
        raise RuleError(f"bad timespan: {text}")
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours"}[match[2]]: int(match[1])})


def _correlate(spec: dict[str, Any], by_name: dict[str, list[Event]]) -> list[Event]:
    if spec["type"] not in {"temporal", "temporal_ordered"}:
        raise RuleError(f"unsupported correlation type: {spec['type']}")
    missing = [name for name in spec["rules"] if name not in by_name]
    if missing:
        raise RuleError(f"correlation refers to unknown rules: {missing}")
    ordered, span, fields = spec["type"] == "temporal_ordered", _timespan(spec["timespan"]), spec["group-by"]

    def group(event: Event) -> tuple[str, ...]:
        return tuple(str((lookup(event, f) or [""])[0]) for f in fields)

    def chain(start: Event, names: list[str]) -> Event | None:
        """Find one event per remaining rule, in the same group and inside the time span."""
        last = start
        for name in names:
            candidates = [
                e
                for e in by_name[name]
                if group(e) == group(start)
                and e is not start
                and abs(_time(e) - _time(start)) <= span
                and (not ordered or _time(e) >= _time(last))
            ]
            if not candidates:
                return None
            last = min(candidates, key=_time) if ordered else max([last, candidates[0]], key=_time)
        return last

    first, *rest = spec["rules"]
    found = [chain(event, rest) for event in by_name[first] if all(group(event))]
    return [event for event in found if event is not None]


def _summary(event: Event) -> str:
    if event["product"] == "agent_trace":
        return f"{event['event']} {event.get('tool', '')} {event.get('outcome', '')}".strip()
    actor = event.get("appDisplayName") or event["initiatedBy"]["app"]["displayName"]
    targets = ", ".join(t["displayName"] for t in event.get("targetResources", []))
    return f"{event['activityDisplayName']} by {actor} from {event['ipAddress']} {targets}".strip()


def evaluate_events(audit: list[Event], trace: list[Event], rules: list[dict[str, Any]] | None = None) -> list[Hit]:
    rules = load_rules() if rules is None else rules
    events = audit + trace
    by_name = {rule["name"]: _matches(rule, events) for rule in rules if "detection" in rule}
    hits = []
    for rule in rules:
        if "correlation" in rule:
            matched = _correlate(rule["correlation"], by_name)
        elif rule.get("level") == "informational":
            continue  # building block for a correlation, not an alert by itself
        else:
            matched = by_name[rule["name"]]
        hits += [Hit(rule["name"], rule["title"], rule["level"], e["timestamp"], _summary(e)) for e in matched]
    return sorted(hits, key=lambda hit: (hit.timestamp, hit.rule_id))


# --- command line --------------------------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Sigma rules over the current lab logs.")
    parser.add_argument("--data", type=Path, default=Path(os.environ.get("LAB_DATA", "runs")))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    logs = {name: args.data / name for name in ("audit.jsonl", "agent_trace.jsonl")}
    if not any(path.exists() for path in logs.values()):
        sys.exit(f"no logs in {args.data}: run an attack first")
    audit, trace = (read_jsonl(path) for path in logs.values())
    hits = evaluate_events(audit, trace)
    if args.json:
        print(json.dumps([hit.__dict__ for hit in hits], indent=2))
        return
    print(f"{len(load_rules())} rule documents over {len(audit)} audit and {len(trace)} agent events")
    if not hits:
        print("No detections.")
    for hit in hits:
        print(f"{hit.timestamp}  {hit.level:<8}  {hit.rule_id:<32}  {hit.summary}")


if __name__ == "__main__":
    main()
