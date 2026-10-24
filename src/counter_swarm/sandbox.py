"""Opt-in, dedicated gVisor host adapter. Observations never activate rules.

This is infrastructure wiring, not a supplied payload-analysis image. The image
contract and host isolation must be independently validated before deployment.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable


class SandboxError(RuntimeError):
    pass


async def bounded_process(argv: list[str], data: bytes = b"", *, timeout: float = 15,
                          stdout_limit: int = 65_536, stderr_limit: int = 8_192) -> bytes:
    """Terminate on either output overflow or wall time; never invoke a shell."""
    proc = await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def read(stream: asyncio.StreamReader, limit: int) -> bytes:
        result = bytearray()
        while block := await stream.read(min(4096, limit + 1)):
            result.extend(block)
            if len(result) > limit:
                raise SandboxError("Process output budget exceeded")
        return bytes(result)

    async def feed() -> None:
        assert proc.stdin
        try:
            proc.stdin.write(data)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    tasks = [asyncio.create_task(feed()),
             asyncio.create_task(read(proc.stdout, stdout_limit)),
             asyncio.create_task(read(proc.stderr, stderr_limit)),
             asyncio.create_task(proc.wait())]
    try:
        _, out, _, code = await asyncio.wait_for(asyncio.gather(*tasks), timeout)
        if code:
            raise SandboxError("Sandbox process failed; output is not trusted")
        return out
    except (TimeoutError, asyncio.TimeoutError) as exc:
        raise SandboxError("Sandbox process wall time exceeded") from exc
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        await proc.wait()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@dataclass(frozen=True)
class SandboxConfig:
    image: str
    expected_daemon_id: str
    dedicated_host_confirmed: bool = False
    docker_host: str = "unix:///var/run/docker.sock"
    wall_seconds: float = 15
    payload_limit: int = 65_536

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[a-f0-9]{64}", self.image):
            raise SandboxError("An operator-pinned image digest is required")
        if not self.dedicated_host_confirmed or not self.expected_daemon_id:
            raise SandboxError("A dedicated isolated host and pinned daemon ID are required")
        if not re.fullmatch(r"unix:///[a-zA-Z0-9_./\-]+", self.docker_host):
            raise SandboxError("Only a fixed local dedicated-host Unix socket is supported")
        if not 1 <= self.wall_seconds <= 30 or not 1 <= self.payload_limit <= 65_536:
            raise SandboxError("Sandbox resource limits are outside the approved bounds")


Runner = Callable[..., Awaitable[bytes]]


class SandboxWorker:
    def __init__(self, config: SandboxConfig, runner: Runner = bounded_process):
        self.config, self.runner = config, runner

    async def _docker(self, *args: str, data: bytes = b"", timeout: float = 10) -> bytes:
        return await self.runner(["docker", "--host", self.config.docker_host, *args],
                                 data, timeout=timeout)

    async def inspect(self, payload: bytes) -> dict[str, Any]:
        if not isinstance(payload, bytes) or not payload or len(payload) > self.config.payload_limit:
            raise SandboxError("Payload must be nonempty bytes within its budget")
        try:
            info = json.loads(await self._docker("info", "--format", "{{json .}}"))
            if info.get("ID") != self.config.expected_daemon_id or "runsc" not in info.get("Runtimes", {}):
                raise SandboxError("Dedicated daemon identity or gVisor runtime verification failed")
            images = json.loads(await self._docker("image", "inspect", self.config.image))
            if not isinstance(images, list) or len(images) != 1 or images[0].get("Config", {}).get("Volumes"):
                raise SandboxError("Analysis image must not declare volumes")
        except (ValueError, TypeError, AttributeError, KeyError) as exc:
            raise SandboxError("Cannot verify sandbox prerequisites") from exc
        name = "counter-swarm-" + uuid.uuid4().hex
        try:
            raw = await self._docker(
                "run", "--name", name, "--rm", "--pull", "never", "--runtime", "runsc",
                "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt",
                "no-new-privileges=true", "--user", "65534:65534", "--pids-limit", "64",
                "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5", "--ipc", "none",
                "--ulimit", "nofile=64:64", "--ulimit", "fsize=1048576:1048576",
                "--log-driver", "none", "--entrypoint", "/counter-swarm/analyze", "-i",
                self.config.image, data=payload, timeout=self.config.wall_seconds,
            )
            observation = validate_observation(raw)
            return {"schema_version": 1, "trust": "untrusted_sandbox_observation",
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "image": self.config.image, "observation": observation,
                    "automatic_promotion": False}
        finally:
            # Killing the Docker CLI does not necessarily stop the container.
            # Cleanup is unconditional and failure is surfaced, never hidden.
            try:
                await self._docker("rm", "--force", name, timeout=10)
            except Exception as exc:
                # --rm may have already removed a successful container. Verify
                # absence via a bounded, exact-name filtered list before success.
                try:
                    left = await self._docker("ps", "-aq", "--filter", f"name=^/{name}$")
                except Exception as verify_exc:
                    raise SandboxError("Cannot verify sandbox container cleanup; isolate host") from verify_exc
                if left.strip():
                    raise SandboxError("Sandbox container remains; isolate host") from exc


def validate_observation(raw: bytes) -> dict[str, Any]:
    if len(raw) > 65_536:
        raise SandboxError("Oversized observation")
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise SandboxError("Duplicate observation key")
            result[key] = item
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, RecursionError) as exc:
        raise SandboxError("Invalid observation JSON") from exc
    if not isinstance(value, dict) or set(value) != {"summary", "findings", "candidate_literals"}:
        raise SandboxError("Unexpected observation schema")
    if not isinstance(value["summary"], str) or len(value["summary"]) > 2048:
        raise SandboxError("Invalid observation summary")
    for key, count, length in (("findings", 32, 512), ("candidate_literals", 16, 256)):
        items = value[key]
        if (not isinstance(items, list) or len(items) > count
                or any(not isinstance(x, str) or not 1 <= len(x) <= length for x in items)):
            raise SandboxError("Invalid bounded observation entries")
    return value


def write_rule_proposal(observation: dict[str, Any], directory: Path) -> Path:
    """Content-addressed, exclusive immutable JSON artifact; never an active rule.

    The caller supplies a trusted operator-owned directory, not a request path.
    Human review and a separate activation pipeline are deliberately required.
    """
    if observation.get("trust") != "untrusted_sandbox_observation":
        raise SandboxError("Expected a sandbox observation")
    content = validate_observation(json.dumps(observation.get("observation")).encode())
    digest = observation.get("payload_sha256", "")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise SandboxError("Invalid payload evidence digest")
    proposal = {"schema_version": 1, "status": "human_review_required",
                "trust": "untrusted_candidate", "payload_sha256": digest,
                "match_kind": "literal_only", "candidate_literals": content["candidate_literals"],
                "automatic_promotion": False}
    encoded = json.dumps(proposal, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    path = directory / (hashlib.sha256(encoded).hexdigest() + ".proposal.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as target:
        target.write(encoded)
        target.flush()
        os.fsync(target.fileno())
    return path
