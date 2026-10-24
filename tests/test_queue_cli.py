import hashlib
import json
from types import SimpleNamespace

import pytest

from counter_swarm import runtime
from counter_swarm.incident_queue import IncidentQueue


def test_operator_archive_cli_needs_no_remote_credentials(tmp_path, monkeypatch, capsys):
    directory = tmp_path / "queue"
    path = directory / "incidents.sqlite"
    queue = IncidentQueue(path)
    digest = hashlib.sha256(b"fictional").hexdigest()
    event_id = "evt_" + digest[:24]
    queue.put({"event_id": event_id, "fingerprint": digest,
               "rules": ["unsupported-compressed-body"], "severity": "high", "source": "proxy",
               "trust": "external_untrusted", "policy_revision": "builtin-1"})
    queue.mark(event_id, "completed", code="ESCALATED")
    archives = tmp_path / "archives"
    archives.mkdir(mode=0o700)
    destination = archives / "new.jsonl"
    monkeypatch.setattr(runtime.RuntimeConfig, "load", lambda: SimpleNamespace(queue_file=str(path)))
    monkeypatch.setattr(runtime, "credential", lambda _: pytest.fail("Archival must not access engine credentials"))
    monkeypatch.setattr(runtime.sys, "argv", ["counter-swarm", "archive-completed", "--destination", str(destination)])
    runtime.main()
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["archived"] == 1 and not queue.status()
    assert json.loads(destination.read_text())["id"] == event_id
