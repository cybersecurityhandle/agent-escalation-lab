"""Runs one scenario in one configuration and works out the verdict.

Success is always a side effect that can be checked in the lab: a group membership, a password that signs in, data on
the attacker's listener. No model judges the result.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from agent.config import AgentConfig, Controls, load_config
from agent.llm import LLMError, LLMSettings
from agent.tools.registry import DEFAULT_THIRD_PARTY
from detections.evaluate import Hit, evaluate_events
from scenarios.lab_env import ComposeLab, InProcessLab, Lab, RunOptions

ROOT = Path(__file__).parent
SCENARIOS = {
    "s01": "s01_ticket_injection",
    "s02": "s02_rag_exfil",
    "s03": "s03_confused_deputy",
    "s04": "s04_tool_poisoning",
    "s05": "s05_secret_leak",
}


@dataclass
class AttackResult:
    succeeded: bool
    steps: list[str]
    stopped_by: list[str] = field(default_factory=list)  # controls that leave no denial in the trace


class Scenario(Protocol):
    TITLE: str

    def attack(self, lab: Lab) -> AttackResult: ...


@dataclass
class Report:
    scenario: str
    title: str
    mode: str
    controls: list[str]
    result: AttackResult
    blocked_by: list[str]
    detections: list[Hit]
    trace: list[dict[str, Any]]

    @property
    def verdicts(self) -> list[str]:
        if self.result.succeeded:
            lines = ["ATTACK SUCCEEDED"]
        else:
            lines = [f"ATTACK BLOCKED (by {', '.join(self.blocked_by)})"]
        rules = list(dict.fromkeys(hit.rule_id for hit in self.detections))
        return lines + ([f"ATTACK DETECTED (rule {', '.join(rules)})"] if rules else [])


def scenario_module(scenario: str) -> Any:
    return importlib.import_module(f"scenarios.{SCENARIOS[scenario]}.run")


def script_path(scenario: str) -> Path:
    return ROOT / SCENARIOS[scenario] / "scripted_llm.yaml"


def execute(
    scenario: str,
    config: AgentConfig,
    data_dir: Path,
    *,
    backend: str = "scripted",
    model: str = "",
    assume_compromised: bool = False,
    target: str = "inprocess",
    variant: str | None = None,
) -> Report:
    module = scenario_module(scenario)
    script = script_path(scenario) if backend == "scripted" else None
    options = RunOptions(
        config,
        LLMSettings(backend, model, script, assume_compromised),
        third_party=getattr(module, "THIRD_PARTY", DEFAULT_THIRD_PARTY),
    )
    lab: Lab = ComposeLab(options) if target == "compose" else InProcessLab(data_dir, options)
    result = module.attack(lab, variant) if variant else module.attack(lab)
    blocked_by = [] if result.succeeded else _attribute(lab, config, result, backend)
    hits = evaluate_events(lab.audit(), lab.trace())
    return Report(scenario, module.TITLE, config.mode, config.controls.enabled(), result, blocked_by, hits, lab.trace())


def _attribute(lab: Lab, config: AgentConfig, result: AttackResult, backend: str) -> list[str]:
    denied = [event["control"] for event in lab.trace() if event.get("control")]
    blocked_by = list(dict.fromkeys(denied + result.stopped_by))
    if not blocked_by and config.controls.spotlighting:
        blocked_by = ["spotlighting"]  # nothing was denied: the injected text was not followed
    return blocked_by or ["model, no control fired" if backend != "scripted" else "unexplained"]


# --- command line --------------------------------------------------------------------------------------------


def print_report(report: Report) -> None:
    print(f"\n{report.scenario.upper()}  {report.title}")
    print(f"mode: {report.mode}   controls on: {', '.join(report.controls) or 'none'}")
    for number, step in enumerate(report.result.steps, 1):
        print(f"  {number}. {step}")
    calls = [
        e
        for e in report.trace
        if e["event"] in {"tool_call", "tool_loaded"} and (e["event"] == "tool_call" or e["outcome"] != "ok")
    ]
    if calls:
        print("  agent tool calls:")
    for event in calls:
        control = f"  [{event['control']}]" if event.get("control") else ""
        args = json.dumps(event.get("args", {}), ensure_ascii=False)
        print(f"    {event['outcome']:<7} {event['tool']} {args[:90]}{control}")
    for line in report.verdicts:
        print(f"==> {line}")


def main(scenario: str | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run an attack scenario against the local lab.")
    if scenario is None:
        parser.add_argument("scenario", choices=[*SCENARIOS, "all"])
    parser.add_argument("--mode", choices=["vulnerable", "hardened"], default="vulnerable")
    parser.add_argument(
        "--llm", choices=["scripted", "anthropic", "ollama"], default=os.environ.get("LLM_BACKEND", "scripted")
    )
    parser.add_argument("--model", default="")
    parser.add_argument("--target", choices=["inprocess", "compose"], default="inprocess")
    parser.add_argument("--only", nargs="+", metavar="CONTROL", help="turn on just these controls (in-process)")
    parser.add_argument("--disable", nargs="+", metavar="CONTROL", default=[], help="turn these off (in-process)")
    parser.add_argument(
        "--honour-marking",
        action="store_true",
        help="scripted model respects spotlighting (default: assume it is fully hijacked)",
    )
    parser.add_argument("--variant", help="scenario-specific payload variant")
    parser.add_argument("--repeat", type=int, default=1, metavar="N", help="run N times and print a success rate")
    args = parser.parse_args()
    if not 1 <= args.repeat <= 50:
        parser.error("--repeat must be between 1 and 50")
    if args.target == "compose" and (args.only or args.disable):
        parser.error("--only and --disable need the in-process target; Compose runs the two fixed modes")

    config = load_config(args.mode)
    if args.only:
        config = AgentConfig("custom", Controls.only(*args.only))
    if args.disable:
        config = AgentConfig("custom", config.controls.toggled(dict.fromkeys(args.disable, False)))

    chosen = scenario or args.scenario
    for name in SCENARIOS if chosen == "all" else [chosen]:
        outcomes = []
        for _ in range(args.repeat):
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    report = execute(
                        name,
                        config,
                        Path(tmp),
                        backend=args.llm,
                        model=args.model,
                        target=args.target,
                        assume_compromised=not args.honour_marking,
                        variant=args.variant,
                    )
                except (LLMError, RuntimeError) as exc:
                    sys.exit(f"error: {exc}")
            print_report(report)
            outcomes.append(report.result.succeeded)
        if args.repeat > 1:
            print(f"\n{name}: attack succeeded in {sum(outcomes)} of {len(outcomes)} runs")


if __name__ == "__main__":
    main()
