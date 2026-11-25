"""Human approval, simulated. The approver sees facts built by code, not a summary written by the model."""

from __future__ import annotations

from dataclasses import dataclass

NEEDS_APPROVAL = {"reset_password", "add_to_group"}


@dataclass(frozen=True)
class SimulatedApprover:
    approve: bool = False  # tests and attack runs use an approver who rejects

    def decide(self, summary: str) -> bool:
        return self.approve
