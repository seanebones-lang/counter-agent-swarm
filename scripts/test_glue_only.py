#!/usr/bin/env python3
"""Run the explicit public component suite without either private engine.

This is deliberately separate from native integration. It cannot certify the
Mothership dispatch/approval path, actual DeadBolt enforcement or deployment.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TESTS = [
    "tests/test_detection_gate.py", "tests/test_proxy.py", "tests/test_openai_analyst.py",
    "tests/test_release_resources.py", "tests/test_queue_cli.py", "tests/test_sandbox_intel.py",
    "tests/test_worker_commands.py",
    "tests/test_linux_lab.py", "tests/test_queue_recovery.py",
    "tests/test_runtime.py::test_queue_deduplicates_claims_and_requires_explicit_pending_resume",
    "tests/test_runtime.py::test_ingress_requires_private_token_and_rejects_payload_or_routing",
]

if __name__ == "__main__":
    print("Public glue component tests only; native engines and model judgment are not exercised.", flush=True)
    raise SystemExit(subprocess.run([sys.executable, "-m", "pytest", "-q", *TESTS], cwd=ROOT).returncode)
