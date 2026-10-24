"""Small bounded transport queue. Mothership owns decisions, approvals and receipts.

Claims become held before any remote call. A crash never silently retries an
external effect. Pending approvals retain their original identifier and phase.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import sqlite3
import stat
from .records import FindingRecord


class IncidentQueue:
    def __init__(self, path: Path):
        if not path.is_absolute():
            raise ValueError("Queue path must be absolute")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("Queue directory must be owner-only")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        os.close(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Queue file must be owner-only")
        self.path = path
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, record TEXT NOT NULL, state TEXT NOT NULL, phase TEXT, approval TEXT, code TEXT)")

    def connect(self):
        return sqlite3.connect(self.path, timeout=1)

    def put(self, record: dict) -> bool:
        value = FindingRecord.model_validate(record).model_dump()
        encoded = json.dumps(value, sort_keys=True)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            found = db.execute("SELECT record FROM incidents WHERE id=?", (value["event_id"],)).fetchone()
            if found:
                if found[0] != encoded:
                    raise ValueError("Conflicting incident identifier")
                return False
            if db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] >= 2048:
                raise RuntimeError("Incident queue full; operator archival required")
            db.execute("INSERT INTO incidents VALUES (?,?,'queued',NULL,NULL,NULL)", (value["event_id"], encoded))
            return True

    def claim(self, event_id: str | None = None) -> dict | None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.row_factory = sqlite3.Row
            if event_id is None:
                row = db.execute("SELECT * FROM incidents WHERE state='queued' ORDER BY rowid LIMIT 1").fetchone()
            else:
                row = db.execute("SELECT * FROM incidents WHERE id=? AND state='pending'", (event_id,)).fetchone()
            if not row:
                return None
            db.execute("UPDATE incidents SET state='held',code='IN_PROGRESS' WHERE id=?", (row["id"],))
            return {**dict(row), "record": json.loads(row["record"])}

    def mark(self, event_id: str, state: str, *, phase: str | None = None,
             approval: str | None = None, code: str | None = None):
        if state not in {"pending", "held", "completed"} or phase not in {None, "evidence", "analysis", "action", "checkpoint"}:
            raise ValueError("Unsupported queue transition")
        with self.connect() as db:
            db.execute("UPDATE incidents SET state=?,phase=?,approval=?,code=? WHERE id=?",
                       (state, phase, approval, code, event_id))

    def status(self):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT id,state,phase,approval,code FROM incidents ORDER BY rowid LIMIT 2048")]
