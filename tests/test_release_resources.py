"""Disposable queue capacity/archival and supervisor resource regressions."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
from types import SimpleNamespace

import pytest

from counter_swarm.incident_queue import IncidentQueue
from counter_swarm import supervisor


def record(number: int) -> dict:
    fingerprint = hashlib.sha256(str(number).encode()).hexdigest()
    return {"event_id": "evt_" + fingerprint[:24], "fingerprint": fingerprint,
            "rules": ["unsupported-compressed-body"], "severity": "high", "source": "proxy",
            "trust": "external_untrusted", "policy_revision": "builtin-1"}


def count(queue: IncidentQueue) -> int:
    with queue.connect() as db:
        return db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]


@pytest.mark.parametrize("unsettled", [False, True])
def test_full_queue_dedup_and_completed_archive_reclaims_capacity(tmp_path, unsettled):
    queue = IncidentQueue(tmp_path / "queue" / "incidents.sqlite")
    for number in range(2048):
        assert queue.put(record(number)) is True
    assert queue.put(record(0)) is False
    with pytest.raises(RuntimeError, match="queue full"):
        queue.put(record(2048))
    # A conflicting record must not be accepted merely because the queue is full.
    conflicting = {**record(0), "rules": ["request-budget"]}
    with pytest.raises(ValueError, match="Conflicting"):
        queue.put(conflicting)
    with queue.connect() as db:
        db.execute("UPDATE incidents SET state='completed',phase='checkpoint',code='ESCALATED'")
    if unsettled:
        queue.mark(record(0)["event_id"], "pending", phase="analysis", approval="apr_fiction")
        queue.mark(record(1)["event_id"], "held", phase="action", code="OUTCOME_UNKNOWN")
        with queue.connect() as db:
            db.execute("UPDATE incidents SET state='queued' WHERE id=?", (record(2)["event_id"],))
    directory = tmp_path / "archives"
    directory.mkdir(mode=0o700)
    destination = directory / "completed.jsonl"
    receipt = queue.archive_completed(destination)
    expected = 2045 if unsettled else 2048
    assert receipt["archived"] == expected
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert receipt["sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()
    exported = [json.loads(line) for line in destination.read_text().splitlines()]
    assert len(exported) == expected
    assert all(item["state"] == "completed" for item in exported)
    assert all(item["record"]["trust"] == "external_untrusted" for item in exported)
    assert count(queue) == (3 if unsettled else 0)
    assert {row["state"] for row in queue.status()} == ({"pending", "held", "queued"} if unsettled else set())
    assert queue.put(record(2048)) is True


def test_archive_destination_conflict_preserves_queue_and_existing_file(tmp_path):
    queue = IncidentQueue(tmp_path / "queue" / "incidents.sqlite")
    queue.put(record(0))
    queue.mark(record(0)["event_id"], "completed")
    directory = tmp_path / "archives"
    directory.mkdir(mode=0o700)
    destination = directory / "exists.jsonl"
    destination.write_bytes(b"existing operator archive")
    with pytest.raises(FileExistsError):
        queue.archive_completed(destination)
    assert destination.read_bytes() == b"existing operator archive"
    assert count(queue) == 1 and queue.status()[0]["state"] == "completed"
    link = directory / "symlink.jsonl"
    link.symlink_to(destination)
    with pytest.raises(FileExistsError):
        queue.archive_completed(link)
    assert count(queue) == 1


def test_archive_rejects_shared_or_nonexistent_directory(tmp_path):
    queue = IncidentQueue(tmp_path / "queue" / "incidents.sqlite")
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o755)
    # The parent process may enforce umask 077; set the deliberately unsafe mode
    # explicitly so this fixture actually exercises the shared-directory case.
    directory.chmod(0o755)
    with pytest.raises(ValueError, match="owner-only"):
        queue.archive_completed(directory / "archive.jsonl")
    with pytest.raises(FileNotFoundError):
        queue.archive_completed(tmp_path / "absent" / "archive.jsonl")
    with pytest.raises(ValueError, match="absolute"):
        queue.archive_completed(Path("relative.jsonl"))


@pytest.mark.parametrize("failed_call", [1, 2])
def test_archive_fsync_failure_cannot_remove_completed_rows(tmp_path, monkeypatch, failed_call):
    queue = IncidentQueue(tmp_path / "queue" / "incidents.sqlite")
    queue.put(record(0))
    queue.mark(record(0)["event_id"], "completed")
    directory = tmp_path / "archives"
    directory.mkdir(mode=0o700)

    fsync = os.fsync
    calls = []

    def unavailable(fd):
        calls.append(fd)
        if len(calls) == failed_call:
            raise OSError("Fictional archive durability failure")
        return fsync(fd)

    monkeypatch.setattr(os, "fsync", unavailable)
    with pytest.raises(OSError, match="durability"):
        queue.archive_completed(directory / "unconfirmed.jsonl")
    assert count(queue) == 1 and queue.status()[0]["state"] == "completed"


def test_archive_delete_failure_rolls_back_all_rows_after_durable_export(tmp_path):
    queue = IncidentQueue(tmp_path / "queue" / "incidents.sqlite")
    for number in range(2):
        queue.put(record(number))
        queue.mark(record(number)["event_id"], "completed")
    with queue.connect() as db:
        # A real SQLite failure on the second row must also preserve the first.
        db.execute("CREATE TRIGGER deny_second_delete BEFORE DELETE ON incidents "
                   "WHEN OLD.id='" + record(1)["event_id"] + "' BEGIN SELECT RAISE(ABORT,'fictional storage failure'); END")
    directory = tmp_path / "archives"
    directory.mkdir(mode=0o700)
    import sqlite3
    with pytest.raises(sqlite3.DatabaseError, match="storage failure"):
        queue.archive_completed(directory / "retained-duplicate.jsonl")
    assert count(queue) == 2
    assert len((directory / "retained-duplicate.jsonl").read_text().splitlines()) == 2


def test_archive_fsyncs_file_and_directory_before_deleting(tmp_path, monkeypatch):
    queue = IncidentQueue(tmp_path / "queue" / "incidents.sqlite")
    queue.put(record(0))
    queue.mark(record(0)["event_id"], "completed")
    directory = tmp_path / "archives"
    directory.mkdir(mode=0o700)
    seen = []
    original = os.fsync

    def inspected(fd):
        seen.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        assert count(queue) == 1
        return original(fd)

    monkeypatch.setattr(os, "fsync", inspected)
    assert queue.archive_completed(directory / "durable.jsonl")["archived"] == 1
    assert seen == ["file", "directory"]
    assert count(queue) == 0


def test_concurrent_claims_never_claim_same_incident_twice(tmp_path):
    queue = IncidentQueue(tmp_path / "queue" / "incidents.sqlite")
    for number in range(40):
        queue.put(record(number))
    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = list(pool.map(lambda _: queue.claim(), range(48)))
    ids = [row["id"] for row in claims if row is not None]
    assert len(ids) == len(set(ids)) == 40
    assert all(row["state"] == "held" for row in queue.status())


RESOURCE_DEFAULTS = {
    "COUNTER_SWARM_EDGE_CONCURRENCY": ("--limit-concurrency", "32"),
    "COUNTER_SWARM_EDGE_BACKLOG": ("--backlog", "128"),
    "COUNTER_SWARM_EDGE_KEEP_ALIVE_SECONDS": ("--timeout-keep-alive", "5"),
    "COUNTER_SWARM_EDGE_HEADER_BYTES": ("--h11-max-incomplete-event-size", "16384"),
}


def clear_resources(monkeypatch):
    for name in RESOURCE_DEFAULTS:
        monkeypatch.delenv(name, raising=False)


def test_public_uvicorn_has_explicit_protocol_and_resource_limits(monkeypatch):
    clear_resources(monkeypatch)
    args = supervisor.public_server_args()
    for flag, value in RESOURCE_DEFAULTS.values():
        assert args[args.index(flag) + 1] == value
    for flag, value in (("--workers", "1"), ("--http", "h11"), ("--ws", "none")):
        assert args[args.index(flag) + 1] == value
    assert "--no-proxy-headers" in args
    monkeypatch.setenv("COUNTER_SWARM_EDGE_CONCURRENCY", "16")
    assert supervisor.public_server_args()[supervisor.public_server_args().index("--limit-concurrency") + 1] == "16"


@pytest.mark.parametrize("name,value", [
    ("COUNTER_SWARM_EDGE_CONCURRENCY", "129"), ("COUNTER_SWARM_EDGE_CONCURRENCY", "0"),
    ("COUNTER_SWARM_EDGE_CONCURRENCY", "32 --workers 99"), ("COUNTER_SWARM_EDGE_BACKLOG", "513"),
    ("COUNTER_SWARM_EDGE_KEEP_ALIVE_SECONDS", "16"), ("COUNTER_SWARM_EDGE_KEEP_ALIVE_SECONDS", " 5"),
    ("COUNTER_SWARM_EDGE_HEADER_BYTES", "65536"), ("COUNTER_SWARM_EDGE_HEADER_BYTES", "16.5"),
])
def test_unclean_or_unbounded_resource_configuration_rejected(monkeypatch, name, value):
    clear_resources(monkeypatch)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        supervisor.public_server_args()


def supervisor_fixture(monkeypatch, *, gate_ready=True, fail_service=False):
    config = SimpleNamespace(target_run="fixture", gate_origin="http://127.0.0.1:9782",
        mothership_origin="http://127.0.0.1:9783", ingress_origin="http://127.0.0.1:9784",
        admission_token_file="fictional-unused-token")
    binding = SimpleNamespace(target_run="fixture", forward_tool="web.forward", deadbolt_binary="fictional-deadbolt",
                              lease_ttl_seconds=300, child_env=lambda: {})
    monkeypatch.setattr(supervisor.RuntimeConfig, "load", lambda: config)
    monkeypatch.setattr(supervisor.ControlBinding, "load", lambda: binding)
    monkeypatch.setenv("DEADBOLT_TOKEN", "fictional-disposable-token")
    monkeypatch.setenv("MS_DEADBOLT_REQUIRED", "true")
    monkeypatch.setenv("PORT", "8080")
    clear_resources(monkeypatch)
    events, children, handlers = [], [], {}
    monkeypatch.setattr(supervisor.signal, "signal", lambda number, handler: handlers.update({number: handler}))

    class Child:
        def __init__(self, argv):
            self.argv = argv
            self.returncode = None
            self.terminated = False

        def poll(self):
            if fail_service and self is children[0]:
                return 1
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = 0

        def kill(self):
            self.terminated = True
            self.returncode = -9

        def wait(self, timeout):
            return self.returncode

    def launch(argv, **_):
        if "counter_swarm.runtime:configured_proxy" in argv:
            assert events[-2:] == ["gate-ready", "mothership-ready"]
            events.append("public-edge")
        elif "work" in argv:
            events.append("worker")
            handlers[signal.SIGTERM]()
        else:
            events.append("private-service")
        child = Child(argv)
        children.append(child)
        return child

    monkeypatch.setattr(supervisor.subprocess, "Popen", launch)
    from counter_swarm.gate import Gate

    async def admission(_):
        events.append("gate-ready" if gate_ready else "gate-not-ready")
        return gate_ready

    monkeypatch.setattr(Gate, "admitted", admission)
    import httpx

    def health(*_, **__):
        events.append("mothership-ready")
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(httpx, "get", health)
    monkeypatch.setattr(supervisor.time, "sleep", lambda _: None)
    if not gate_ready:
        clock = iter([0.0, 21.0, 42.0, 63.0])
        # Keep asyncio's own global monotonic clock untouched.
        monkeypatch.setattr(supervisor, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None))
    return events, children


def test_supervisor_waits_for_gate_and_mothership_before_public_listener(monkeypatch):
    events, children = supervisor_fixture(monkeypatch)
    supervisor.main()
    assert events == ["private-service"] * 3 + ["gate-ready", "mothership-ready", "public-edge", "worker"]
    assert all(child.terminated for child in children)
    edge = next(child for child in children if "counter_swarm.runtime:configured_proxy" in child.argv)
    assert "--limit-concurrency" in edge.argv and "--h11-max-incomplete-event-size" in edge.argv


@pytest.mark.parametrize("gate_ready,fail_service", [(False, False), (True, True)])
def test_supervisor_failure_never_starts_public_edge_and_cleans_private_children(monkeypatch, gate_ready, fail_service):
    events, children = supervisor_fixture(monkeypatch, gate_ready=gate_ready, fail_service=fail_service)
    with pytest.raises(RuntimeError):
        supervisor.main()
    assert "public-edge" not in events
    assert all(child.terminated or child.poll() is not None for child in children)
