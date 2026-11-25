"""Runs every scenario against every control on its own and writes the control matrix into README.md."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from agent.config import AgentConfig, Controls
from scenarios.harness import SCENARIOS, execute

README = Path(__file__).parent.parent / "README.md"
START, END = "<!-- matrix:start -->", "<!-- matrix:end -->"
BLOCKS, MODEL_DEPENDENT, NONE = "**blocks**", "model*", "-"

Matrix = dict[str, dict[str, str]]


def _cell(scenario: str, control: str, data_dir: Path) -> str:
    config = AgentConfig("custom", Controls.only(control))
    hijacked = execute(scenario, config, data_dir / "hijacked", assume_compromised=True)
    if not hijacked.result.succeeded:
        return BLOCKS
    if control != "spotlighting":
        return NONE
    cooperative = execute(scenario, config, data_dir / "cooperative", assume_compromised=False)
    return NONE if cooperative.result.succeeded else MODEL_DEPENDENT


def build_matrix(data_dir: Path) -> Matrix:
    return {
        control: {scenario: _cell(scenario, control, data_dir / control / scenario) for scenario in SCENARIOS}
        for control in Controls.names()
    }


def render(matrix: Matrix) -> str:
    header = "| Control, alone | " + " | ".join(s.upper() for s in SCENARIOS) + " |"
    lines = [header, "|---" * (len(SCENARIOS) + 1) + "|"]
    lines += [f"| `{control}` | " + " | ".join(row.values()) + " |" for control, row in matrix.items()]
    return "\n".join(lines)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        table = render(build_matrix(Path(tmp)))
    text = README.read_text(encoding="utf-8")
    if START not in text or END not in text:
        sys.exit("README.md has no matrix markers")
    before, rest = text.split(START, 1)
    after = rest.split(END, 1)[1]
    README.write_text(f"{before}{START}\n{table}\n{END}{after}", encoding="utf-8")
    print(table)


if __name__ == "__main__":
    main()
