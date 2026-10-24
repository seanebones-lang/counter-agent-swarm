"""One-shot operator workers; no scheduler, model calls, or rule activation."""
from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import private_file
from .intel import memory_handoff, poll_kev
from .sandbox import SandboxConfig, SandboxWorker, write_rule_proposal


class WorkerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IntelCommandConfig(WorkerConfig):
    system_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    mothership_origin: str
    api_key_file: str
    state_directory: str
    cve_ids: list[str] = Field(min_length=1, max_length=50)
    namespace: str = Field(default="swarm.intel", pattern=r"^[A-Za-z0-9_.-]{1,64}$")

    @field_validator("mothership_origin")
    @classmethod
    def fixed_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/") or parsed.scheme not in ("http", "https")
                or parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1")):
            raise ValueError("Use a fixed HTTPS Mothership origin or literal HTTP loopback")
        _ = parsed.port
        return value.rstrip("/")


class SandboxCommandConfig(WorkerConfig):
    image: str
    expected_daemon_id: str
    dedicated_host_confirmed: bool = False
    docker_host: str = "unix:///var/run/docker.sock"
    wall_seconds: int = Field(default=15, ge=1, le=30)
    payload_limit: int = Field(default=65536, ge=1, le=65536)
    proposal_directory: str


def load_config(path: str, model: type[WorkerConfig]) -> WorkerConfig:
    if not Path(path).is_absolute():
        raise ValueError("Worker configuration must have an absolute private path")
    return model.model_validate_json(private_file(path).read_bytes())


def _directory(path: str) -> Path:
    directory = Path(path)
    info = directory.lstat()
    if (not directory.is_absolute() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("Expected an existing owner-only directory, without a symlink")
    return directory


def _json_bytes(value: Any) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > 65536:
        raise ValueError("Worker record exceeded its byte budget")
    return encoded


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextmanager
def _exclusive_worker(directory: Path):
    lock = directory / "intel.lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        private_file(lock)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def mothership_client(config: IntelCommandConfig):
    """Existing SDK, fixed endpoint/credential, no retries or approval auto-wait."""
    import httpx
    from mothership.sdk import Client
    key = private_file(config.api_key_file).read_text().strip()
    if not key or len(key) > 4096:
        raise ValueError("Invalid private Mothership credential")
    return Client(config.mothership_origin, api_key=key, timeout=15, max_retries=0,
                  auto_wait_approvals=False, transport=httpx.HTTPTransport(trust_env=False))


def _save_outcome(directory: Path, key: str, state: str, approval_id: str | None = None) -> None:
    target = directory / "intel.pending.status.json"
    if target.exists() or target.is_symlink():
        private_file(target)
    temporary = directory / (".intel.status." + uuid.uuid4().hex)
    _write_new(temporary, _json_bytes({"idempotency_key": key, "state": state, "approval_id": approval_id}))
    os.replace(temporary, target)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_outcome(directory: Path, key: str) -> dict[str, Any]:
    path = directory / "intel.pending.status.json"
    if not path.exists() and not path.is_symlink():
        return {"idempotency_key": key, "state": "unclassified", "approval_id": None}
    marker = json.loads(private_file(path).read_bytes())
    if (not isinstance(marker, dict) or set(marker) != {"idempotency_key", "state", "approval_id"}
            or marker["idempotency_key"] != key
            or marker["state"] not in {"dispatching", "unclassified", "approval_pending", "transport_uncertain", "outcome_unknown", "blocked"}
            or marker["approval_id"] is not None and (not isinstance(marker["approval_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", marker["approval_id"]))):
        raise ValueError("Invalid pending outcome marker")
    return marker


async def intel_once(config: IntelCommandConfig, *, reconcile: bool = False, fetch: Callable = poll_kev,
                     client_factory: Callable = mothership_client) -> dict[str, Any]:
    """Persist immutable input/key, then hold unresolved outcomes by default.

    Explicit reconciliation polls an existing approval ID, or asks the native
    receipt/idempotency path using identical input/key only after transport
    uncertainty. Native unknown/blocked outcomes cannot be reexecuted here.
    """
    directory = _directory(config.state_directory)
    with _exclusive_worker(directory):
        pending = directory / "intel.pending.json"
        approval_id = None
        waiting_approval = False
        if pending.exists() or pending.is_symlink():
            record = json.loads(private_file(pending).read_bytes())
            if (not isinstance(record, dict) or set(record) != {"key", "input", "system_id", "origin"}
                    or record["system_id"] != config.system_id or record["origin"] != config.mothership_origin):
                raise ValueError("Pending record binding differs; reconcile before changing configuration")
            call_input = record["input"]
            if (not isinstance(call_input, dict) or set(call_input) != {"key", "value", "namespace"}
                    or call_input["namespace"] != config.namespace):
                raise ValueError("Invalid pending memory call")
            digest = hashlib.sha256(_json_bytes([config.system_id, call_input["value"], config.namespace])).hexdigest()
            if record["key"] != "intel:" + digest or call_input["key"] != "intel." + digest:
                raise ValueError("Pending record key does not match its immutable input")
            marker = _read_outcome(directory, record["key"])
            approval_id = marker["approval_id"]
            if not reconcile or marker["state"] not in {"approval_pending", "transport_uncertain"}:
                return {"status": "pending_reconciliation", "outcome": marker["state"],
                        "idempotency_key": record["key"], "approval_id": approval_id,
                        "automatic_retry": False, "automatic_promotion": False}
            waiting_approval = marker["state"] == "approval_pending" or approval_id is not None
            if waiting_approval and not approval_id:
                raise ValueError("Original approval ID is required; original call must not be resubmitted")
        else:
            if reconcile:
                return {"status": "no_pending_reconciliation", "automatic_retry": False,
                        "automatic_promotion": False}
            catalog = await fetch()
            handoff = memory_handoff(catalog, config.cve_ids)
            digest = hashlib.sha256(_json_bytes([config.system_id, handoff, config.namespace])).hexdigest()
            call_input = {"key": "intel." + digest, "namespace": config.namespace, "value": handoff}
            record = {"key": "intel:" + digest, "input": call_input,
                      "system_id": config.system_id, "origin": config.mothership_origin}
            _write_new(pending, _json_bytes(record))
        _save_outcome(directory, record["key"], "approval_pending" if waiting_approval else "dispatching", approval_id)
        try:
            with client_factory(config) as client:
                if waiting_approval:
                    receipt = client.wait_for_approval(approval_id, timeout=1)
                else:
                    receipt = client.call("memory.put", call_input, idempotency_key=record["key"])
            if (not isinstance(receipt, dict) or receipt.get("key") != call_input["key"]
                    or receipt.get("namespace") != config.namespace or type(receipt.get("version")) is not int):
                raise ValueError("Unverified memory receipt")
            receipt_hash = hashlib.sha256(_json_bytes(receipt)).hexdigest()
            completed = directory / (digest + ".receipt.json")
            completion = {"idempotency_key": record["key"], "receipt_sha256": receipt_hash}
            if completed.exists() or completed.is_symlink():
                if json.loads(private_file(completed).read_bytes()) != completion:
                    raise ValueError("Existing receipt does not match; reconciliation required")
            else:
                _write_new(completed, _json_bytes(completion))
            pending.unlink()
            (directory / "intel.pending.status.json").unlink()
            return {"status": "memory_recorded", "idempotency_key": record["key"],
                    "receipt_sha256": receipt_hash, "automatic_promotion": False}
        except Exception as error:
            code = getattr(error, "code", None)
            details = getattr(error, "details", {})
            supplied_id = details.get("approval_id") if isinstance(details, dict) else None
            valid_id = isinstance(supplied_id, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", supplied_id)
            if code == "APPROVAL_PENDING" and valid_id and (not waiting_approval or supplied_id == approval_id):
                state, approval_id = "approval_pending", supplied_id
            elif waiting_approval and code == "WAIT_TIMEOUT":
                state = "approval_pending"
            elif code == "OUTCOME_UNKNOWN":
                # SDK status 0 denotes transport/envelope uncertainty. A native
                # unknown outcome is held for operator evidence reconciliation.
                state = "outcome_unknown" if waiting_approval or getattr(error, "status", None) != 0 else "transport_uncertain"
            else:
                state = "blocked"
            _save_outcome(directory, record["key"], state, approval_id)
            return {"status": "pending_reconciliation", "outcome": state,
                    "idempotency_key": record["key"], "approval_id": approval_id,
                    "automatic_retry": False, "automatic_promotion": False}


async def sandbox_once(config: SandboxCommandConfig, payload: bytes, *, worker_factory: Callable = SandboxWorker) -> dict[str, Any]:
    directory = _directory(config.proposal_directory)
    settings = config.model_dump(exclude={"proposal_directory"})
    observation = await worker_factory(SandboxConfig(**settings)).inspect(payload)
    try:
        proposal = write_rule_proposal(observation, directory)
    except FileExistsError:
        # An existing proposal is never overwritten or assumed valid. Reconcile
        # it manually; this invocation makes no promotion or success claim.
        return {"status": "proposal_already_exists", "payload_sha256": observation["payload_sha256"],
                "automatic_promotion": False}
    return {"status": "proposal_created", "payload_sha256": observation["payload_sha256"],
            "proposal_file": proposal.name, "automatic_promotion": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", choices=("intel", "sandbox"))
    parser.add_argument("--config", required=True, help="Absolute path to owner-only operator JSON")
    parser.add_argument("--payload", default="-", help="Sandbox: private regular file or '-' for bounded stdin")
    parser.add_argument("--reconcile", action="store_true", help="Intel: explicitly reconcile eligible pending receipt/approval")
    args = parser.parse_args(argv)
    try:
        if args.worker == "intel":
            if args.payload != "-":
                raise ValueError("Intel worker does not accept payload files")
            result = asyncio.run(intel_once(load_config(args.config, IntelCommandConfig), reconcile=args.reconcile))
        else:
            if args.reconcile:
                raise ValueError("Sandbox worker has no approval/receipt reconciliation operation")
            config = load_config(args.config, SandboxCommandConfig)
            if args.payload == "-":
                payload = sys.stdin.buffer.read(config.payload_limit + 1)
            else:
                with private_file(args.payload).open("rb") as source:
                    payload = source.read(config.payload_limit + 1)
            result = asyncio.run(sandbox_once(config, payload))
        print(_json_bytes(result).decode())
        return 0 if result["status"] in {"memory_recorded", "proposal_created"} else 2
    except Exception:
        # Provider errors and validation details can contain credentials or
        # captured payload data. Operators receive only a bounded failure code.
        print('{"status":"worker_failed","automatic_promotion":false}', file=sys.stderr)
        return 1


def intel_main() -> None:
    raise SystemExit(main(["intel", *sys.argv[1:]]))


def sandbox_main() -> None:
    raise SystemExit(main(["sandbox", *sys.argv[1:]]))


if __name__ == "__main__":
    raise SystemExit(main())
