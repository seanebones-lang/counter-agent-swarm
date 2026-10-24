"""Inert process interruption, intake pressure and isolated queue recovery.

These are transport/glue checks, not native approval or production recovery.
"""
from contextlib import closing, contextmanager
import hashlib
import json
import os
import selectors
import signal
import sqlite3
import subprocess
import sys
import textwrap

from fastapi.testclient import TestClient
import httpx
import pytest

from counter_swarm.incident_queue import IncidentQueue
from counter_swarm.proxy import create_proxy
from counter_swarm.runtime import RuntimeConfig, create_ingress


def record(number):
    digest = hashlib.sha256(f"recovery-fixture-{number}".encode()).hexdigest()
    return {"event_id": "evt_" + digest[:24], "fingerprint": digest,
            "rules": ["unsupported-compressed-body"], "severity": "high", "source": "proxy",
            "trust": "external_untrusted", "policy_revision": "builtin-1"}


@contextmanager
def interrupted_child(source, *args):
    """Kill only our child after its bounded, explicit durability barrier."""
    child = subprocess.Popen([sys.executable, "-c", textwrap.dedent(source), *map(str, args)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=10), "Child did not reach the interruption barrier"
        assert child.stdout.readline() == b"barrier\n"
        child.kill()
        output, errors = child.communicate(timeout=10)
        assert child.returncode == -signal.SIGKILL, errors.decode()
        assert output == b"", "The interrupted caller must not return a success receipt"
        yield
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_killed_claim_remains_held_across_reopen_and_duplicate_intake(tmp_path):
    path = tmp_path / "queue" / "incidents.sqlite"
    queue = IncidentQueue(path)
    queue.put(record(0))
    marker = tmp_path / "fictional-effect.json"
    source = """
        import json, os, sys
        from pathlib import Path
        from counter_swarm.incident_queue import IncidentQueue
        row = IncidentQueue(Path(sys.argv[1])).claim()
        with open(sys.argv[2], "x") as output:
            json.dump({"id": row["id"], "key": row["id"] + ":evidence"}, output)
            output.flush()
            os.fsync(output.fileno())
        print("barrier", flush=True)
        sys.stdin.buffer.read(1)
    """
    with interrupted_child(source, path, marker):
        reopened = IncidentQueue(path)
        assert reopened.put(record(0)) is False
        assert reopened.claim() is None
        assert reopened.claim(record(0)["event_id"]) is None
        assert reopened.status() == [{"id": record(0)["event_id"], "state": "held",
                                     "phase": None, "approval": None, "code": "IN_PROGRESS"}]
        assert json.loads(marker.read_text())["key"] == record(0)["event_id"] + ":evidence"
        assert len(list(tmp_path.glob("fictional-effect*"))) == 1


@pytest.mark.parametrize("barrier", ["durable_export_before_commit", "committed_before_receipt"])
def test_archive_process_interruption_reconciles_without_losing_unsettled_rows(tmp_path, barrier):
    path = tmp_path / "queue" / "incidents.sqlite"
    queue = IncidentQueue(path)
    for number in range(4):
        queue.put(record(number))
    queue.mark(record(0)["event_id"], "completed", code="ESCALATED")
    queue.mark(record(1)["event_id"], "pending", phase="analysis", approval="apr_original")
    queue.mark(record(2)["event_id"], "held", phase="action", code="OUTCOME_UNKNOWN")
    original = queue.status()
    unsettled = queue.status()[1:]
    archives = tmp_path / "archives"
    archives.mkdir(mode=0o700)
    destination = archives / "interrupted.jsonl"
    source = """
        import os, stat, sys
        from pathlib import Path
        from counter_swarm.incident_queue import IncidentQueue
        def pause():
            print("barrier", flush=True)
            sys.stdin.buffer.read(1)
        if sys.argv[3] == "durable_export_before_commit":
            original_fsync = os.fsync
            def fsync(fd):
                original_fsync(fd)
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    pause()
            os.fsync = fsync
        receipt = IncidentQueue(Path(sys.argv[1])).archive_completed(Path(sys.argv[2]))
        pause()
        print(receipt, flush=True)
    """
    with interrupted_child(source, path, destination, barrier):
        reopened = IncidentQueue(path)
        exported = [json.loads(line) for line in destination.read_text().splitlines()]
        assert len(exported) == 1 and exported[0]["id"] == record(0)["event_id"]
        assert exported[0]["state"] == "completed"
        if barrier == "durable_export_before_commit":
            assert reopened.status() == original
            assert reopened.status()[0]["state"] == "completed"
        else:
            assert reopened.status() == unsettled
        assert [row for row in reopened.status() if row["state"] != "completed"] == unsettled
        before_retry = reopened.status()
        with pytest.raises(FileExistsError):
            reopened.archive_completed(destination)
        assert reopened.status() == before_retry
        with reopened.connect() as db:
            assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)


@pytest.fixture
def wal_queue(tmp_path):
    queue = IncidentQueue(tmp_path / "live" / "queue.sqlite")
    # Keep one connection open so committed records remain in the WAL during
    # backup. A main-database-only file copy would miss these records.
    with closing(queue.connect()) as anchor:
        assert anchor.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        yield queue


def test_sqlite_backup_restores_exact_queue_snapshot_without_requeueing(tmp_path, wal_queue):
    path = tmp_path / "live" / "queue.sqlite"
    queue = wal_queue
    for number in range(4):
        queue.put(record(number))
    queue.mark(record(1)["event_id"], "pending", phase="action", approval="apr_original", code="APPROVAL_PENDING")
    queue.mark(record(2)["event_id"], "held", phase="action", code="OUTCOME_UNKNOWN")
    queue.mark(record(3)["event_id"], "completed", code="ACTION_RECEIPT")
    snapshot = queue.status()
    with queue.connect() as db:
        expected_rows = db.execute("SELECT * FROM incidents ORDER BY rowid").fetchall()
    assert path.with_name(path.name + "-wal").stat().st_size > 0
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o700)
    backup = backups / "queue.sqlite"
    # Use SQLite's online backup API, never a live main-file-only copy.
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)
    with queue.connect() as source, sqlite3.connect(backup) as destination:
        source.backup(destination)
    # Later live state must not leak into the saved snapshot.
    queue.put(record(4))
    queue.claim()
    restored_path = tmp_path / "restored" / "queue.sqlite"
    restored_path.parent.mkdir(mode=0o700)
    with sqlite3.connect(backup) as source:
        fd = os.open(restored_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
        with sqlite3.connect(restored_path) as destination:
            source.backup(destination)
    restored = IncidentQueue(restored_path)
    assert restored.status() == snapshot
    with restored.connect() as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("SELECT * FROM incidents ORDER BY rowid").fetchall() == expected_rows
    assert restored.put(record(1)) is False
    pending = restored.claim(record(1)["event_id"])
    assert pending["approval"] == "apr_original" and pending["phase"] == "action"
    assert restored.claim(record(2)["event_id"]) is None
    assert restored.claim()["id"] == record(0)["event_id"]
    assert restored.claim() is None
    assert queue.status() != snapshot


def test_ingress_lock_and_capacity_pressure_keep_suspicious_requests_blocked(tmp_path):
    token = tmp_path / "ingress.token"
    token.write_text("inert-private-token-for-this-test")
    token.chmod(0o600)
    path = tmp_path / "queue" / "queue.sqlite"
    config = RuntimeConfig(upstream="http://127.0.0.1:8000", gate_origin="http://127.0.0.1:9782",
        target_run="fictional", admission_token_file=str(token), ingress_token_file=str(token),
        queue_file=str(path), mothership_origin="http://127.0.0.1:9783", mothership_agent_key_file=str(token))
    ingress = create_ingress(config)
    queue = IncidentQueue(path)
    headers = {"Authorization": "Bearer " + token.read_text()}
    class NeverGate:
        async def admitted(self):
            pytest.fail("Suspicious traffic must not reach admission or the upstream")
    outcomes = []
    async def sink(finding):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=ingress), base_url="http://fixture") as client:
            result = await client.post("/incidents", json=finding.record(), headers=headers)
            outcomes.append(result.status_code)
            if result.status_code != 202:
                raise RuntimeError("Fictional intake unavailable")
    with TestClient(ingress) as intake, TestClient(create_proxy(config.upstream, NeverGate(), sink)) as edge:
        with queue.connect() as lock:
            lock.execute("BEGIN IMMEDIATE")
            blocked = intake.post("/incidents", json=record(0), headers=headers)
            assert blocked.status_code == 503 and blocked.json()["code"] == "QUEUE_UNAVAILABLE"
        assert intake.post("/incidents", json=record(0), headers=headers).status_code == 202
        for number in range(1, 2048):
            queue.put(record(number))
        assert intake.post("/incidents", json=record(0), headers=headers).status_code == 202
        assert intake.post("/incidents", json=record(2048), headers=headers).status_code == 503
        result = edge.post("/", content=b"inert", headers={"content-encoding": "br"})
        assert result.status_code == 403 and outcomes == [503]
        assert len(queue.status()) == 2048
