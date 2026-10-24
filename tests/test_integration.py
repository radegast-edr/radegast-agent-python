"""Opt-in local entrypoint for the backend-owned native integration runner.

CI calls the shared action with agent-source pointing to its checked-out commit.
Set RADEGAST_RUN_NATIVE_INTEGRATION=1 to run this test locally. It installs real
services and requires administrator access or passwordless sudo.
"""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(
    os.environ.get("RADEGAST_RUN_NATIVE_INTEGRATION") != "1",
    reason="Native service integration runs through the shared GitHub action; opt in explicitly for local runs",
)
def test_agent_integration():
    backend = Path(
        os.environ.get("RADEGAST_INTEGRATION_BACKEND_DIR", ROOT.parent / "radegast-console-backend")
    ).resolve()
    script = backend / ".github/tests/integration_test.py"
    if not script.is_file():
        pytest.fail("Shared integration runner missing; set RADEGAST_INTEGRATION_BACKEND_DIR to a backend checkout")
    command = [
        "uv",
        "run",
        "--project",
        str(backend),
        "python",
        str(script),
        "--backend-dir",
        str(backend),
        "--agent-source",
        str(ROOT),
        "--output-dir",
        str(ROOT / "test-output"),
    ]
    if os.name != "nt":
        command = ["sudo", "env", f"PATH={os.environ['PATH']}", *command]
    subprocess.run(command, check=True)
