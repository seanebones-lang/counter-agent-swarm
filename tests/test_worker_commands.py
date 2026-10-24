import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from counter_swarm.intel import KEV_URL
from counter_swarm.worker_commands import (IntelCommandConfig, SandboxCommandConfig,
                                           intel_once, sandbox_once, load_config, main)


def catalog():
    return {"source": KEV_URL, "source_sha256": "b" * 64,
            "candidates": [{"cve_id": "CVE-2026-12345", "trust": "untrusted_public_advisory",
                            "status": "review_candidate", "product": "Fictional fixture"}]}


class FakeNativeError(Exception):
    def __init__(self, code, status, approval_id=None):
        super().__init__("secret-in-error-must-not-be-printed")
        self.code, self.status = code, status
        self.details = {"approval_id": approval_id} if approval_id else {}


class FakeClient:
    def __init__(self, calls, fail=False, bad=False, error=None, approval_receipt=None):
        self.calls, self.fail, self.bad = calls, fail, bad
        self.error, self.approval_receipt = error, approval_receipt

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def call(self, tool, inp, *, idempotency_key):
        self.calls.append((tool, inp, idempotency_key))
        if self.error:
            raise self.error
        if self.fail:
            raise RuntimeError("secret-in-error-must-not-be-printed")
        if self.bad:
            return {"message": "not a confirmed memory write"}
        return {"key": inp["key"], "namespace": inp["namespace"], "version": 1, "created": True}

    def wait_for_approval(self, approval_id, timeout):
        self.calls.append(("wait_for_approval", approval_id, timeout))
        if self.error:
            raise self.error
        return self.approval_receipt


class WorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.directory.chmod(0o700)
        self.config = IntelCommandConfig(system_id="fixture", mothership_origin="http://127.0.0.1:8787",
            api_key_file=str(self.directory / "unused.key"), state_directory=str(self.directory),
            cve_ids=["CVE-2026-12345"])

    def tearDown(self):
        self.temp.cleanup()

    async def test_intel_one_memory_write_with_durable_stable_key(self):
        calls = []
        async def fetch():
            return catalog()
        result = await intel_once(self.config, fetch=fetch, client_factory=lambda _: FakeClient(calls))
        self.assertEqual(result["status"], "memory_recorded")
        self.assertEqual(calls[0][0], "memory.put")
        self.assertEqual(calls[0][1]["value"]["instruction_authority"], False)
        self.assertEqual(calls[0][2], result["idempotency_key"])
        self.assertFalse((self.directory / "intel.pending.json").exists())
        self.assertEqual(len(list(self.directory.glob("*.receipt.json"))), 1)
        again = await intel_once(self.config, fetch=fetch, client_factory=lambda _: FakeClient(calls))
        self.assertEqual(result["idempotency_key"], again["idempotency_key"])

    async def test_transport_uncertainty_halts_then_explicit_reconcile_uses_same_key(self):
        calls = []
        async def fetch():
            return catalog()
        first = await intel_once(self.config, fetch=fetch,
            client_factory=lambda _: FakeClient(calls, error=FakeNativeError("OUTCOME_UNKNOWN", 0)))
        original = (self.directory / "intel.pending.json").read_bytes()
        self.assertEqual(first["status"], "pending_reconciliation")
        async def forbidden_fetch():
            raise AssertionError("Pending work must be reconciled before fetching a different feed")
        held = await intel_once(self.config, fetch=forbidden_fetch,
            client_factory=lambda _: self.fail("Pending outcomes must halt by default"))
        self.assertEqual(held["outcome"], "transport_uncertain")
        self.assertEqual(len(calls), 1)
        second = await intel_once(self.config, reconcile=True, fetch=forbidden_fetch,
                                  client_factory=lambda _: FakeClient(calls))
        self.assertEqual(calls[0], calls[1])
        self.assertEqual(first["idempotency_key"], second["idempotency_key"])
        self.assertNotIn("secret", json.dumps(first))
        self.assertIn(first["idempotency_key"].encode(), original)

    async def test_approval_pending_halts_then_polls_original_approval_never_resubmits(self):
        calls = []
        async def fetch():
            return catalog()
        first = await intel_once(self.config, fetch=fetch,
            client_factory=lambda _: FakeClient(calls, error=FakeNativeError("APPROVAL_PENDING", 200, "approval-original")))
        self.assertEqual(first["approval_id"], "approval-original")
        self.assertEqual(first["outcome"], "approval_pending")
        held = await intel_once(self.config, fetch=lambda: self.fail("Must not fetch"),
            client_factory=lambda _: self.fail("Must not initialize SDK by default"))
        self.assertEqual(held["approval_id"], "approval-original")
        original = (self.directory / "intel.pending.json").read_bytes()
        timed_out = await intel_once(self.config, reconcile=True,
            client_factory=lambda _: FakeClient(calls, error=FakeNativeError("WAIT_TIMEOUT", 408, "approval-original")))
        self.assertEqual(timed_out["outcome"], "approval_pending")
        self.assertEqual(calls[-1], ("wait_for_approval", "approval-original", 1))
        self.assertEqual((self.directory / "intel.pending.json").read_bytes(), original)
        call_input = json.loads(original)["input"]
        result = await intel_once(self.config, reconcile=True,
            client_factory=lambda _: FakeClient(calls, approval_receipt={"key": call_input["key"],
                "namespace": call_input["namespace"], "version": 1, "created": True}))
        self.assertEqual(result["status"], "memory_recorded")
        self.assertEqual(sum(call[0] == "memory.put" for call in calls), 1)

    async def test_native_unknown_remains_held_even_with_reconcile(self):
        calls = []
        async def fetch():
            return catalog()
        first = await intel_once(self.config, fetch=fetch,
            client_factory=lambda _: FakeClient(calls, error=FakeNativeError("OUTCOME_UNKNOWN", 200)))
        self.assertEqual(first["outcome"], "outcome_unknown")
        again = await intel_once(self.config, reconcile=True,
            fetch=lambda: self.fail("Must not fetch"), client_factory=lambda _: self.fail("Must not reexecute"))
        self.assertEqual(again["idempotency_key"], first["idempotency_key"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(again["outcome"], "outcome_unknown")

    async def test_reconcile_without_pending_cannot_start_a_new_job(self):
        result = await intel_once(self.config, reconcile=True,
            fetch=lambda: self.fail("Reconciliation must not fetch a new catalog"),
            client_factory=lambda _: self.fail("Reconciliation must not create a new SDK call"))
        self.assertEqual(result["status"], "no_pending_reconciliation")

    async def test_unverified_receipt_remains_pending(self):
        async def fetch():
            return catalog()
        result = await intel_once(self.config, fetch=fetch, client_factory=lambda _: FakeClient([], bad=True))
        self.assertEqual(result["status"], "pending_reconciliation")
        self.assertTrue((self.directory / "intel.pending.json").exists())

    async def test_different_binding_or_corrupted_pending_cannot_send(self):
        async def fetch():
            return catalog()
        await intel_once(self.config, fetch=fetch, client_factory=lambda _: FakeClient([], fail=True))
        changed = self.config.model_copy(update={"system_id": "other-system"})
        with self.assertRaises(ValueError):
            await intel_once(changed, fetch=fetch, client_factory=lambda _: self.fail("Must not call SDK"))
        path = self.directory / "intel.pending.json"
        record = json.loads(path.read_text())
        record["input"]["value"]["automatic_promotion"] = True
        path.write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            await intel_once(self.config, fetch=fetch, client_factory=lambda _: self.fail("Must not call SDK"))

    async def test_sandbox_adapter_uses_worker_and_creates_only_proposal(self):
        observations = []
        class FakeWorker:
            def __init__(self, settings):
                self.settings = settings
            async def inspect(self, payload):
                observations.append((self.settings, payload))
                return {"trust": "untrusted_sandbox_observation", "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "observation": {"summary": "fictional", "findings": [], "candidate_literals": ["fixture"]}}
        config = SandboxCommandConfig(image="example/analyzer@sha256:" + "a" * 64,
            expected_daemon_id="dedicated-fixture", dedicated_host_confirmed=True, proposal_directory=str(self.directory))
        result = await sandbox_once(config, b"fictional payload", worker_factory=FakeWorker)
        self.assertEqual(result["status"], "proposal_created")
        self.assertEqual(observations[0][1], b"fictional payload")
        self.assertEqual(json.loads((self.directory / result["proposal_file"]).read_text())["status"], "human_review_required")
        again = await sandbox_once(config, b"fictional payload", worker_factory=FakeWorker)
        self.assertEqual(again["status"], "proposal_already_exists")

    def test_private_config_unknown_fields_and_insecure_origin_rejected(self):
        path = self.directory / "config.json"
        path.write_text(self.config.model_dump_json())
        path.chmod(0o600)
        self.assertEqual(load_config(str(path), IntelCommandConfig), self.config)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            load_config(str(path), IntelCommandConfig)
        for origin in ("http://public.example", "https://user:secret@example.com", "https://example.com/other"):
            with self.assertRaises(ValueError):
                IntelCommandConfig(**{**self.config.model_dump(), "mothership_origin": origin})

    def test_cli_failure_does_not_print_sensitive_exception(self):
        stderr = io.StringIO()
        with patch("counter_swarm.worker_commands.load_config", side_effect=ValueError("credential-leak")):
            with contextlib.redirect_stderr(stderr):
                result = main(["intel", "--config", "/fictional/private.json"])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(stderr.getvalue())["status"], "worker_failed")
        self.assertNotIn("credential", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
