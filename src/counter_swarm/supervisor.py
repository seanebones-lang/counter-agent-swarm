"""Single-system colocated staging profile; operator provisions all authority first.

Stops every child when any required service exits. It never issues, renews or
reopens a DeadBolt lease and never approves Mothership actions.
"""
from __future__ import annotations
import os
import re
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit
from .config import ControlBinding
from .runtime import RuntimeConfig


def _bounded_resource(name: str, default: int, minimum: int, maximum: int) -> int:
    value = os.environ.get(name, str(default))
    if not re.fullmatch(r"[1-9][0-9]*", value) or not minimum <= int(value) <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return int(value)


def public_server_args() -> list[str]:
    """Trusted deployment bounds, never selected by requests or model output.

    Force h11 so its incomplete-header buffer setting actually applies. This
    option does not establish a universal total-header or total-memory limit.
    """
    return ["--workers", "1", "--http", "h11", "--ws", "none", "--no-proxy-headers",
            "--limit-concurrency", str(_bounded_resource("COUNTER_SWARM_EDGE_CONCURRENCY", 32, 1, 128)),
            "--backlog", str(_bounded_resource("COUNTER_SWARM_EDGE_BACKLOG", 128, 16, 512)),
            "--timeout-keep-alive", str(_bounded_resource("COUNTER_SWARM_EDGE_KEEP_ALIVE_SECONDS", 5, 1, 15)),
            "--h11-max-incomplete-event-size", str(_bounded_resource("COUNTER_SWARM_EDGE_HEADER_BYTES", 16384, 1024, 16384))]


def main():
    config = RuntimeConfig.load()
    binding = ControlBinding.load()
    if binding.target_run != config.target_run or binding.forward_tool != "web.forward":
        raise ValueError("Proxy and MCP control target must be identical")
    if not os.environ.get("DEADBOLT_TOKEN") or os.environ.get("MS_DEADBOLT_REQUIRED") != "true":
        raise ValueError("Required private sidecar authentication and Mothership admission are missing")
    ports = [urlsplit(origin).port for origin in (config.gate_origin, config.mothership_origin, config.ingress_origin)]
    if any(urlsplit(origin).hostname != "127.0.0.1" for origin in
           (config.gate_origin, config.mothership_origin, config.ingress_origin)):
        raise ValueError("The colocated supervisor profile requires explicit IPv4 loopback origins")
    edge_port = int(os.environ.get("PORT", "8080"))
    if not 1024 <= edge_port <= 65535 or len(set([*ports, edge_port])) != 4:
        raise ValueError("Distinct unprivileged service ports are required")
    native_env = binding.child_env()
    native_env["DEADBOLT_TOKEN"] = os.environ["DEADBOLT_TOKEN"]
    edge_limits = public_server_args()
    commands = [
        ([binding.deadbolt_binary, "--lease-ttl-secs", str(binding.lease_ttl_seconds), "serve", "--bind", f"127.0.0.1:{ports[0]}"], native_env),
        ([sys.executable, "-m", "uvicorn", "counter_swarm.mothership_ext:create_app", "--factory", "--host", "127.0.0.1", "--port", str(ports[1]), "--no-access-log"], None),
        ([sys.executable, "-m", "uvicorn", "counter_swarm.runtime:configured_ingress", "--factory", "--host", "127.0.0.1", "--port", str(ports[2]), "--no-access-log"], None),
    ]
    edge_command = [sys.executable, "-m", "uvicorn", "counter_swarm.runtime:configured_proxy", "--factory",
                    "--host", "0.0.0.0", "--port", str(edge_port), "--no-access-log", *edge_limits]
    children = []
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for argv, env in commands:
            children.append(subprocess.Popen(argv, env=env))
        # Start only private services first. The public listener is absent until
        # fresh target admission and Mothership store readiness both succeed.
        from .gate import Gate
        import asyncio
        gate = Gate(config.gate_origin, config.target_run, config.admission_token_file)
        deadline = time.monotonic() + 20
        while not asyncio.run(gate.admitted()):
            if stopping or any(child.poll() is not None for child in children) or time.monotonic() >= deadline:
                raise RuntimeError("Required gate did not become available")
            time.sleep(0.2)
        import httpx
        deadline = time.monotonic() + 20
        while True:
            if stopping or any(child.poll() is not None for child in children) or time.monotonic() >= deadline:
                raise RuntimeError("Required control plane did not become available")
            try:
                if httpx.get(config.mothership_origin + "/health", timeout=0.5, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        if stopping or any(child.poll() is not None for child in children):
            raise RuntimeError("Required service stopped before public edge startup")
        children.append(subprocess.Popen(edge_command))
        worker = None
        while not stopping:
            if any(child.poll() is not None for child in children):
                raise RuntimeError("Required service exited; stopping protected edge")
            if worker is None or worker.poll() is not None:
                if worker is not None and worker.returncode:
                    raise RuntimeError("Worker failed; operator reconciliation required")
                worker = subprocess.Popen([sys.executable, "-m", "counter_swarm.runtime", "work"])
                children.append(worker)
                # Finished one-shot workers are not required long-lived services.
                children.remove(worker)
            time.sleep(2)
    finally:
        if 'worker' in locals() and worker is not None:
            children.append(worker)
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


if __name__ == "__main__":
    main()
