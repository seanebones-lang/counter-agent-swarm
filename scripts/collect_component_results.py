#!/usr/bin/env python3
"""Run the public component suite and save a local, shareable result bundle.

No upload, model call, private engine or existing application state is used.
The report is self-reported test evidence, not a signature or certification.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import runpy
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New local output directory; never overwritten")
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    tests = runpy.run_path(str(ROOT / "scripts/test_glue_only.py"))["TESTS"]
    started = time.monotonic()
    timed_out = False
    # Use a direct pytest child so a timeout can stop only this test process group.
    with tempfile.TemporaryFile() as capture:
        child = subprocess.Popen([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *tests],
                                 cwd=ROOT, stdout=capture, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait(timeout=10)
        capture.seek(0)
        data = capture.read(1048577)
    truncated = len(data) > 1048576
    text = data[:1048576].decode("utf-8", errors="replace")
    text = text.replace(str(ROOT), "<TEST_COPY>").replace(str(Path.home()), "<HOME>")
    log = text.encode("utf-8")
    (output / "test-output.txt").write_bytes(log)
    import counter_swarm
    digest = hashlib.sha256()
    for source in sorted(Path(counter_swarm.__file__).resolve().parent.glob("*.py")):
        digest.update(source.name.encode() + b"\0" + source.read_bytes())
    deps = {}
    for name in ["n11-counter-agent-swarm", "pytest", "mcp", "fastapi", "starlette", "httpx", "pydantic", "uvicorn"]:
        try:
            deps[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            deps[name] = "not-installed"
    receipt = {"schema_version": 1, "scope": "public-components-only", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
               "platform": {"os": platform.system(), "os_release": platform.release(), "architecture": platform.machine(),
                            "python": platform.python_version()}, "dependencies": deps,
               "exit_code": code, "timed_out": timed_out, "seconds": round(time.monotonic()-started, 2),
               "status": "passed" if code == 0 and not timed_out and not truncated else "needs-review",
               "glue_source_sha256": digest.hexdigest(), "log_sha256": hashlib.sha256(log).hexdigest(),
               "log_truncated": truncated, "home_and_checkout_paths_redacted": True,
               "native_engines_tested": False, "live_model_judgment_tested": False,
               "independent_truth_or_identity_verification": False}
    (output / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (output / "feedback.md").write_text("""# Voluntary component-preview feedback

Name or preferred alias (optional):
OS / CPU / Python:
Date and approximate time of test:
Did you alter the source or tests? If yes, describe or attach a diff:

## Installation
Commands that failed, redacted error, and any workaround:

## Results
Paste the final test summary. Describe failures, unexpected behavior or network prompts:

## Understanding
What was unclear about detection, approvals, enforcement, mocked fixtures or the private runtime?

## Most useful improvement

## Witness provenance (optional)
Are you comfortable with NextEleven retaining your returned report and file hashes in a private local Witness record? Yes / No:
May we identify you by name in any later public acknowledgement? Yes / No (default No):

Before emailing: inspect results.json, test-output.txt and this file. Remove unrelated personal paths or sensitive content. Never attach your .env, API keys, tokens, real application logs or databases. If you redact a returned file, say which one; NextEleven will hash the actual received version. Nothing is uploaded by this script.
""")
    for file in output.iterdir():
        file.chmod(0o600)
    print(json.dumps({"status": receipt["status"], "exit_code": code, "output_directory": str(output),
                      "return_files": ["results.json", "test-output.txt", "feedback.md"]}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
