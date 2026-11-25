import pytest
import yaml

from agent.config import AgentConfig, Controls, load_config
from agent.llm import LLMSettings
from agent.tools.registry import DEFAULT_THIRD_PARTY
from scenarios.harness import execute
from scenarios.lab_env import InProcessLab, RunOptions

HARDENED = load_config("hardened").controls


@pytest.fixture
def run(tmp_path):
    """run("s01", "vulnerable"), run("s01", only=["human_approval"]), run("s01", "hardened", disable=[...])."""

    def _run(scenario, mode=None, *, only=None, disable=(), **kwargs):
        if only is not None:
            config = AgentConfig("custom", Controls.only(*only))
        else:
            config = load_config(mode)
            if disable:
                config = AgentConfig("custom", config.controls.toggled(dict.fromkeys(disable, False)))
        kwargs.setdefault("assume_compromised", True)
        number = len(list(tmp_path.iterdir()))
        return execute(scenario, config, tmp_path / f"run{number}", **kwargs)

    return _run


@pytest.fixture
def make_lab(tmp_path):
    """An in-process lab driven by a custom script, for traffic that is not one of the scenarios."""

    def _make(
        controls,
        steps,
        *,
        trigger=None,
        hijacked=(),
        approve=False,
        third_party=DEFAULT_THIRD_PARTY,
        assume_compromised=True,
    ):
        number = len(list(tmp_path.iterdir()))
        script = tmp_path / f"script{number}.yaml"
        script.write_text(yaml.safe_dump({"trigger": trigger, "benign": steps, "hijacked": list(hijacked)}))
        mode = "hardened" if controls == HARDENED else "vulnerable" if controls == Controls() else "custom"
        options = RunOptions(
            AgentConfig(mode, controls), LLMSettings("scripted", "", script, assume_compromised), approve, third_party
        )
        return InProcessLab(tmp_path / f"lab{number}", options)

    return _make
