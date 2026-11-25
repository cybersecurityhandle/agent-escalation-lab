"""Reseed the tenant and clear every log (Compose)."""

from agent.config import load_config
from agent.llm import LLMSettings
from scenarios.harness import script_path
from scenarios.lab_env import ComposeLab, RunOptions

if __name__ == "__main__":
    for mode in ("hardened", "vulnerable"):
        ComposeLab(RunOptions(load_config(mode), LLMSettings(script=script_path("s01"))))
    print("Tenant reseeded, audit log, agent trace and listener log cleared.")
