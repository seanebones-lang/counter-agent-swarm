"""Opt-in native acceptance, separated from fast mocked regressions."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(not os.environ.get("COUNTER_SWARM_TEST_DEADBOLT"),
                    reason="Set COUNTER_SWARM_TEST_DEADBOLT to a reviewed external DeadBolt 2.0.0 executable")
def test_disposable_real_native_acceptance(tmp_path):
    script = Path(__file__).parents[1] / "scripts/acceptance.py"
    subprocess.run([sys.executable, str(script), "--deadbolt", os.environ["COUNTER_SWARM_TEST_DEADBOLT"],
                    "--out", str(tmp_path / "receipt.json")], check=True, timeout=150)
    import json
    receipt = json.loads((tmp_path / "receipt.json").read_text())
    assert receipt["status"] == "passed"
    assert receipt["mothership_native_deadbolt_admission_required"] is True
    assert receipt["disposable_stores_removed"] is True
    assert receipt["model_operated"] is False
