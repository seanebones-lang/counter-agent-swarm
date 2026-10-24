#!/usr/bin/env python3
"""Disposable actual-Mothership -> stdio MCP -> native DeadBolt acceptance.

The analyst is an explicit deterministic fixture. No model, production account,
vulnerability exploitation, real request replay, or paid service is used.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

import httpx
import uvicorn

from counter_swarm.gate import Gate
from counter_swarm.proxy import create_proxy
from counter_swarm.response import Gateway, Recommendation, respond
from mothership.sdk import Client


TTL = 300
CONTROL_TOOLS = ["swarm.kill", "swarm.revoke", "swarm.deny", "swarm.evidence",
                 "memory.put", "memory.get", "memory.checkpoint_save"]


def require(condition: Any, label: str) -> None:
    if not condition:
        raise AssertionError(label)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def private_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream)
    os.replace(temporary, path)


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def wait_http(origin: str, process: subprocess.Popen, *, health: bool = False) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Disposable service exited before readiness")
        try:
            if health:
                response = httpx.get(origin + "/health", timeout=0.5, trust_env=False)
                if response.status_code == 200:
                    return
            else:
                from urllib.parse import urlsplit
                port = urlsplit(origin).port
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return
        except (httpx.HTTPError, OSError):
            pass
        time.sleep(0.05)
    raise TimeoutError("Disposable service readiness deadline exceeded")


class FixtureAnalyst:
    """Test-only recommendation; never presented as frontier-model evidence."""

    def __init__(self, action: str):
        self.action = action
        self.calls = 0

    async def analyze(self, evidence: dict[str, Any]) -> Recommendation:
        self.calls += 1
        require(evidence.get("trust") == "external_untrusted", "Finding must remain untrusted")
        return Recommendation(action=self.action, reason="Deterministic acceptance fixture; fictional indicator")


class LiveProxy:
    def __init__(self, upstream: str, gate: Gate):
        self.findings: queue.SimpleQueue = queue.SimpleQueue()

        async def sink(finding):
            self.findings.put(finding)

        port = free_port()
        self.origin = f"http://127.0.0.1:{port}"
        self.server = uvicorn.Server(uvicorn.Config(create_proxy(upstream, gate, sink),
            host="127.0.0.1", port=port, log_level="error", access_log=False))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 5
        while not self.server.started:
            require(self.thread.is_alive(), "Proxy thread exited")
            if time.monotonic() > deadline:
                raise TimeoutError("Proxy readiness deadline exceeded")
            time.sleep(0.02)
        return self

    def __exit__(self, *_):
        self.server.should_exit = True
        self.thread.join(timeout=7)
        require(not self.thread.is_alive(), "Proxy did not terminate")


def run_acceptance(binary: str) -> dict[str, Any]:
    import counter_swarm
    source_root = Path(counter_swarm.__file__).resolve().parent
    source_digest = hashlib.sha256()
    for source in sorted(source_root.glob("*.py")):
        source_digest.update(source.name.encode() + b"\0" + source.read_bytes())
    binary_path = Path(binary).resolve(strict=True)
    require(binary_path.is_file() and os.access(binary_path, os.X_OK), "Native DeadBolt executable required")
    version = subprocess.run([str(binary_path), "--version"], capture_output=True, text=True, check=True,
                             timeout=5).stdout.strip()
    require("2.0.0" in version, "This acceptance pins native DeadBolt 2.0.0")
    import mothership as mothership_package
    dependency_revision = None
    dependency_clean = None
    dependency_root = Path(mothership_package.__file__).resolve().parents[1]
    if (dependency_root / ".git").exists():
        dependency_revision = subprocess.run(["git", "-C", str(dependency_root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=5).stdout.strip()
        status = subprocess.run(["git", "-C", str(dependency_root), "status", "--porcelain", "--untracked-files=no"],
            check=True, capture_output=True, text=True, timeout=5).stdout
        dependency_clean = not status.strip()
        require(dependency_clean, "Mothership tracked source must remain unmodified for this acceptance")
    child_processes: list[subprocess.Popen] = []
    upstream_server = None
    upstream_thread = None
    root_path = None
    results = []
    # Do not inherit provider credentials or an existing Mothership database.
    base_env = {key: value for key, value in os.environ.items()
                if key in {"PATH", "HOME", "TMPDIR", "LANG", "PYTHONPATH"}}
    with tempfile.TemporaryDirectory(prefix="counter-swarm-acceptance-") as temporary:
        root = Path(temporary)
        root_path = str(root)
        root.chmod(0o700)
        database = root / "deadbolt.sqlite3"
        events = root / "deadbolt.jsonl"
        native_env = {**base_env, "DEADBOLT_DB": str(database), "DEADBOLT_EVENTS": str(events)}

        def native(*arguments: str) -> bytes:
            outcome = subprocess.run([str(binary_path), "--lease-ttl-secs", str(TTL), *arguments],
                env=native_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
            if outcome.returncode:
                # Neither raw native output nor credential material enters receipts.
                raise RuntimeError("Disposable native setup/control command failed")
            return outcome.stdout

        deadline = int(time.time()) + TTL

        def provision(run: str, credential: str, tools: list[str]) -> Path:
            native("issue", "--agent", run, "--hard-deadline-at", str(deadline))
            native("policy", "--agent", run, "--tools", ",".join(tools),
                   "--offline-tools", ",".join(tools))
            token = root / (credential + ".token")
            native("credential", "issue", "--agent", run, "--id", credential,
                   "--ttl-secs", str(TTL), "--out", str(token))
            token.chmod(0o600)
            return token

        sidecar_port = free_port()
        sidecar_origin = f"http://127.0.0.1:{sidecar_port}"
        owner_key = "ms_owner_" + secrets.token_hex(24)
        sidecar_env = {**native_env, "DEADBOLT_TOKEN": secrets.token_hex(32)}
        mothership_port = free_port()
        mothership_origin = f"http://127.0.0.1:{mothership_port}"
        binding_file = root / "mothership-bindings.json"
        control_binding = root / "control-binding.json"
        mothership_env = {**base_env,
            "MS_DATA_DIR": str(root / "mothership"),
            "MS_DATABASE_URL": "sqlite:///" + str(root / "mothership.sqlite3"),
            "MS_BOOTSTRAP_OWNER_KEY": owner_key,
            "MS_SMTP_ENABLED": "false", "MS_SCHEDULER_ENABLED": "false",
            "MS_DEADBOLT_REQUIRED": "true", "MS_PRODUCT_BINDINGS_FILE": str(binding_file),
            "MS_DEFAULT_RATE_LIMIT_RPS": "1000", "MS_DEFAULT_RATE_LIMIT_BURST": "1000",
            "COUNTER_SWARM_CONTROL_BINDING": str(control_binding),
        }

        def start_mothership() -> subprocess.Popen:
            process = subprocess.Popen([sys.executable, "-m", "uvicorn",
                "counter_swarm.mothership_ext:create_app", "--factory", "--host", "127.0.0.1",
                "--port", str(mothership_port), "--log-level", "error", "--no-access-log"],
                env=mothership_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child_processes.append(process)
            wait_http(mothership_origin, process, health=True)
            return process

        try:
            control_token = provision("fixture-control-run", "fixture-control-credential", CONTROL_TOOLS)
            sidecar = subprocess.Popen([str(binary_path), "--lease-ttl-secs", str(TTL), "serve", "--bind",
                f"127.0.0.1:{sidecar_port}"], env=sidecar_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child_processes.append(sidecar)
            wait_http(sidecar_origin, sidecar)
            private_json(binding_file, {})
            mothership = start_mothership()
            owner_headers = {"Authorization": "Bearer " + owner_key}
            with httpx.Client(base_url=mothership_origin, headers=owner_headers, timeout=20,
                              trust_env=False) as owner:
                configuration = json.loads((Path(__file__).resolve().parents[1] /
                    "examples/mothership-agent.json").read_text())
                configuration["rate_limit_rps"] = 1000
                created = owner.post("/v1/admin/agents", json=configuration)
                require(created.status_code == 200, "Could not create disposable controller")
                agent = created.json()["data"]
                private_json(binding_file, {agent["agent_id"]: {"deadbolt": {
                    "url": sidecar_origin, "agent_id": "fixture-control-run",
                    "admission_token_file": str(control_token)}}})
                mothership_env["COUNTER_SWARM_MOTHERSHIP_AGENT_ID"] = agent["agent_id"]
                stop(mothership)
                mothership = start_mothership()

                counter = {"requests": 0}
                counter_lock = threading.Lock()

                class Upstream(BaseHTTPRequestHandler):
                    def do_GET(self):
                        with counter_lock:
                            counter["requests"] += 1
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b"fictional upstream")

                    def log_message(self, *_):
                        pass

                upstream_server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
                upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
                upstream_thread.start()
                upstream_origin = f"http://127.0.0.1:{upstream_server.server_port}"

                def evidence(client: Client) -> dict:
                    return client.call("swarm.evidence", {})["receipt"]

                with Client(mothership_origin, api_key=agent["api_key"], max_retries=0, timeout=20) as client:
                    gate_status = client.call("deadbolt.status", {})
                    require(gate_status["required"] is True and gate_status["bound"] is True,
                            "Native Mothership admission must be required and bound")
                    for action in ("kill", "deny", "revoke"):
                        run = "fixture-target-" + action
                        credential = "fixture-credential-" + action
                        token = provision(run, credential, ["web.forward"])
                        private_json(control_binding, {
                            "deadbolt_binary": str(binary_path), "database": str(database),
                            "events": str(events), "target_run": run,
                            "credential_id": credential, "lease_ttl_seconds": TTL,
                        })
                        initial_count = counter["requests"]
                        gate = Gate(sidecar_origin, run, token)
                        with LiveProxy(upstream_origin, gate) as proxy:
                            with httpx.Client(base_url=proxy.origin, timeout=10, trust_env=False) as edge:
                                healthy = edge.get("/fictional-health")
                                require(healthy.status_code == 200, "Healthy request was not forwarded")
                                require(counter["requests"] == initial_count + 1, "Independent upstream count wrong")
                                # Inert text indicator only. No target executes this request.
                                blocked = edge.post("/fictional-indicator-" + action,
                                    content=b"<?php system('FICTIONAL_INERT_INDICATOR'); ?>")
                                require(blocked.status_code == 403, "Deterministic detection did not block")
                                require(counter["requests"] == initial_count + 1, "Indicator reached upstream")
                                finding = proxy.findings.get(timeout=2)
                                analyst = FixtureAnalyst(action)
                                recommendation = asyncio.run(Gateway(analyst, run).analyze(finding))
                                response = respond(client, finding, recommendation)
                                require(response["error"]["code"] == "APPROVAL_PENDING",
                                        "Defensive effect did not require native owner approval")
                                recorded = client.call("memory.get", {"key": "incident." + finding.event_id,
                                                       "namespace": "swarm"})
                                require(recorded["value"]["fingerprint"] == finding.fingerprint,
                                        "Detection evidence missing from Mothership memory")
                                require(asyncio.run(gate.admitted()), "Effect happened before approval")
                                approval_id = response["error"]["details"]["approval_id"]
                                decision = owner.post("/v1/admin/approvals/" + approval_id + "/decide",
                                                       json={"approve": True}).json()["data"]
                                require(decision["status"] == "executed", "Approved real MCP action failed")
                                require(decision["result"]["data"]["receipt"]["action"] == action,
                                        "Wrong native MCP action receipt")
                                after_action = evidence(client)
                                replay = client.call("swarm." + action,
                                    {"event_id": finding.event_id, "reason": recommendation.reason},
                                    idempotency_key=response["idempotency_key"])
                                require(client.last_meta.get("replayed") is True, "Original-key receipt did not replay")
                                require(replay["receipt"]["action"] == action, "Replay returned wrong receipt")
                                after_replay = evidence(client)
                                require(after_replay == after_action, "Receipt replay generated another native event")
                                denied = edge.get("/fictional-after-control")
                                require(denied.status_code == 503, "Next benign dispatch survived native control")
                                require(counter["requests"] == initial_count + 1, "Denied request reached upstream")
                                results.append({"action": action, "healthy_status": healthy.status_code,
                                    "indicator_status": blocked.status_code, "approval_required": True,
                                    "mothership_memory_verified": True, "native_mcp_action_verified": True,
                                    "same_key_replayed_without_native_event": True, "next_request_status": denied.status_code,
                                    "upstream_requests_during_scenario": 1, "control_evidence_accessible_after_action": True,
                                    "fixture_analyst_calls": analyst.calls})

                    # An intact target used solely to prove unavailability/missing admission fails closed.
                    token = provision("fixture-unavailable", "fixture-unavailable-credential", ["web.forward"])
                    intact_gate = Gate(sidecar_origin, "fixture-unavailable", token)
                    initial_count = counter["requests"]
                    with LiveProxy(upstream_origin, intact_gate) as proxy:
                        with httpx.Client(base_url=proxy.origin, timeout=10, trust_env=False) as edge:
                            missing = token.with_suffix(".missing")
                            os.replace(token, missing)
                            no_credential = edge.get("/missing-credential")
                            require(no_credential.status_code == 503, "Missing credential was admitted")
                            os.replace(missing, token)
                            require(asyncio.run(intact_gate.admitted()), "Fresh intact target not admitted")
                            # Break only the disposable store after all effect tests.
                            # An HTTP200 or automatic replacement lease must not admit.
                            with sqlite3.connect(database, timeout=5) as broken_store:
                                broken_store.execute("DROP TABLE leases")
                            broken = edge.get("/unavailable-store")
                            require(broken.status_code == 503, "Unavailable native store was admitted")
                            with sqlite3.connect(database, timeout=5) as inspected_store:
                                require(inspected_store.execute(
                                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='leases'"
                                ).fetchone()[0] == 0, "Failed store was silently recreated")
                            stop(sidecar)
                            unavailable = edge.get("/unavailable-gate")
                            require(unavailable.status_code == 503, "Unavailable gate was admitted")
                            require(counter["requests"] == initial_count, "Unavailable gate reached upstream")
                    results.append({"case": "gate_unavailable_store_unavailable_and_missing_credential",
                                    "missing_credential_status": 503, "unavailable_store_status": 503,
                                    "failed_store_not_recreated": True, "unavailable_gate_status": 503,
                                    "upstream_requests_during_scenario": 0})
        finally:
            for process in reversed(child_processes):
                stop(process)
            if upstream_server is not None:
                upstream_server.shutdown()
                upstream_server.server_close()
            if upstream_thread is not None:
                upstream_thread.join(timeout=5)
            require(all(process.poll() is not None for process in child_processes), "Child process cleanup incomplete")
    require(root_path is not None and not Path(root_path).exists(), "Disposable stores remain")
    return {"status": "passed", "schema_version": 1, "checked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "glue_source_sha256": source_digest.hexdigest(),
        "deadbolt_version": version, "deadbolt_binary_sha256": hashlib.sha256(binary_path.read_bytes()).hexdigest(),
        "mothership_version": mothership_package.__version__, "mothership_unmodified_external_dependency": True,
        "mothership_source_revision": dependency_revision, "mothership_tracked_source_clean": dependency_clean,
        "mothership_native_deadbolt_admission_required": True, "control_run_separate_from_protected_targets": True,
        "processes_stopped": True, "disposable_stores_removed": True, "scenarios": results,
        "model_operated": False, "live_model_calls": 0, "real_accounts_or_services": False,
        "exploit_detonation": False, "limits": ["Synthetic same-team protocol acceptance; no live frontier model trial",
            "Kill/clip/revocation stop the next admission, not already-running effects",
            "Indicators are conservative examples, not comprehensive exploit coverage",
            "No deployment, OS sandbox, live WAF rollout or public-origin bypass verification"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deadbolt", default=shutil.which("deadbolt"))
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "docs/acceptance.json")
    args = parser.parse_args()
    if not args.deadbolt:
        parser.error("A reviewed external DeadBolt 2.0.0 executable is required")
    receipt = run_acceptance(args.deadbolt)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "scenario_count": len(receipt["scenarios"]),
                      "model_operated": False, "receipt": str(args.out)}))


if __name__ == "__main__":
    main()
