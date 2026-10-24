"""Actual unmodified Mothership dispatch/approval tests, with MCP effects mocked.

Native DeadBolt/MCP and model-operated acceptance are separate checks.
"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from counter_swarm import mothership_ext as extension


OWNER = "ms_owner_swarm_disposable_test_0123456789"


@pytest.fixture
def platform(tmp_path, monkeypatch):
    # Fictional state only; no existing Mothership store or provider is opened.
    values = {
        "MS_DATA_DIR": str(tmp_path / "mothership"),
        "MS_DATABASE_URL": "sqlite:///" + str(tmp_path / "mothership.db"),
        "MS_BOOTSTRAP_OWNER_KEY": OWNER,
        "MS_SMTP_ENABLED": "false",
        "MS_SCHEDULER_ENABLED": "false",
        "MS_DEADBOLT_REQUIRED": "false",
        "MS_DEFAULT_RATE_LIMIT_RPS": "1000",
        "MS_DEFAULT_RATE_LIMIT_BURST": "1000",
        "MS_MASTER_KEY": "",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    for key in ("MS_PRODUCT_BINDINGS_FILE", "COUNTER_SWARM_MOTHERSHIP_AGENT_ID"):
        monkeypatch.delenv(key, raising=False)
    from mothership.config import reset_settings
    from mothership.runtime import LIMITER
    from mothership.security import reset_crypto_caches

    reset_settings()
    reset_crypto_caches()
    LIMITER.reset()
    owner_headers = {"Authorization": "Bearer " + OWNER}
    with TestClient(extension.create_app()) as client:
        body = json.loads((Path(__file__).parents[1] / "examples/mothership-agent.json").read_text())
        body["rate_limit_rps"] = 1000
        created = client.post("/v1/admin/agents", headers=owner_headers, json=body)
        assert created.status_code == 200, created.text
        agent = created.json()["data"]
        monkeypatch.setenv("COUNTER_SWARM_MOTHERSHIP_AGENT_ID", agent["agent_id"])
        yield client, owner_headers, agent
    reset_settings()
    reset_crypto_caches()


def invoke(platform, action, body, key=None, agent=None):
    client, _, bound = platform
    agent = agent or bound
    headers = {"Authorization": "Bearer " + agent["api_key"]}
    if key:
        headers["Idempotency-Key"] = key
    return client.post("/v1/tools/swarm." + action, json=body, headers=headers).json()


def approve(platform, pending, decision=True):
    client, owner_headers, _ = platform
    approval_id = pending["error"]["details"]["approval_id"]
    response = client.post("/v1/admin/approvals/" + approval_id + "/decide",
                           headers=owner_headers, json={"approve": decision})
    assert response.status_code == 200, response.text
    return response.json()["data"]


@pytest.mark.parametrize("action", ["kill", "revoke", "deny"])
def test_real_dispatch_approval_single_effect_replay_and_evidence(platform, monkeypatch, action):
    calls = []

    async def control(operation, arguments):
        calls.append((operation, arguments))
        return {"ok": True, "action": operation, "target": "fixed-fictional-target"}

    monkeypatch.setattr(extension, "call_control", control)
    body = {"event_id": "event-001", "reason": "Fictional exploit-shaped request"}
    key = "incident-001-" + action
    pending = invoke(platform, action, body, key=key)
    assert pending["error"]["code"] == "APPROVAL_PENDING"
    assert calls == []
    decision = approve(platform, pending)
    assert decision["status"] == "executed", decision
    assert calls == [(action, body)]
    replay = invoke(platform, action, body, key=key)
    assert replay["ok"] and replay["meta"]["replayed"] is True
    assert replay["data"]["receipt"]["action"] == action
    assert len(calls) == 1
    client, owner_headers, agent = platform
    events = client.get("/v1/admin/events", params={"agent_id": agent["agent_id"]},
                        headers=owner_headers).json()["data"]["events"]
    recorded = [event for event in events if event["type"] == "swarm.action"]
    assert len(recorded) == 1
    assert recorded[0]["data"]["event_id"] == body["event_id"]
    assert len(recorded[0]["data"]["receipt_sha256"]) == 64
    evidence = invoke(platform, "evidence", {})
    assert evidence["ok"] and evidence["data"]["trust"] == "external_untrusted"
    assert calls[-1] == ("evidence", {})


def test_denied_approval_does_not_call_mcp(platform, monkeypatch):
    calls = []

    async def control(*args):
        calls.append(args)
        return {"ok": True}

    monkeypatch.setattr(extension, "call_control", control)
    pending = invoke(platform, "kill", {"event_id": "incident", "reason": "fiction"}, key="denied-once")
    assert approve(platform, pending, False)["status"] == "denied"
    assert calls == []


def test_rebinding_controller_after_approval_request_blocks_action(platform, monkeypatch):
    calls = []

    async def control(*args):
        calls.append(args)
        return {"ok": True}

    monkeypatch.setattr(extension, "call_control", control)
    pending = invoke(platform, "kill", {"event_id": "incident", "reason": "fiction"}, key="changed-binding")
    monkeypatch.setenv("COUNTER_SWARM_MOTHERSHIP_AGENT_ID", "different-trusted-controller")
    decision = approve(platform, pending)
    assert decision["status"] == "failed"
    assert decision["result"]["error"]["code"] == "FORBIDDEN"
    assert calls == []


@pytest.mark.parametrize("unexpected", ["agent_id", "run_id", "system_id", "url", "command"])
def test_model_cannot_select_target_or_command(platform, unexpected):
    result = invoke(platform, "kill", {"event_id": "incident", "reason": "fiction", unexpected: "chosen"},
                    key="reject-" + unexpected)
    assert result["error"]["code"] == "INVALID_INPUT"


def test_unbound_agent_denied_even_with_http_scope(platform, monkeypatch):
    client, owner_headers, _ = platform
    other = client.post("/v1/admin/agents", headers=owner_headers,
                        json={"name": "Unbound", "scopes": ["http"],
                              "create_inbox": False, "create_wallet": False}).json()["data"]
    result = invoke(platform, "evidence", {}, agent=other)
    assert result["error"]["code"] == "FORBIDDEN"
    monkeypatch.delenv("COUNTER_SWARM_MOTHERSHIP_AGENT_ID")
    assert invoke(platform, "evidence", {})["error"]["code"] == "NOT_CONFIGURED"


def test_external_uncertainty_is_retained_without_second_effect(platform, monkeypatch):
    calls = []

    async def dropped_receipt(operation, arguments):
        calls.append((operation, arguments))
        raise ConnectionError("Fictional response lost after remote effect")

    monkeypatch.setattr(extension, "call_control", dropped_receipt)
    body = {"event_id": "uncertain", "reason": "fiction"}
    pending = invoke(platform, "revoke", body, key="retain-original-key")
    decision = approve(platform, pending)
    assert decision["status"] == "failed"
    replay = invoke(platform, "revoke", body, key="retain-original-key")
    assert replay["error"]["code"] == "OUTCOME_UNKNOWN"
    assert replay["error"]["retryable"] is False
    assert len(calls) == 1


@pytest.mark.parametrize("receipt", [{}, {"ok": False}, {"value": "x" * 65_536}, {"value": float("nan")}])
def test_invalid_remote_receipt_cannot_be_success(platform, monkeypatch, receipt):
    async def control(*_):
        return receipt

    monkeypatch.setattr(extension, "call_control", control)
    pending = invoke(platform, "deny", {"event_id": "invalid", "reason": "fiction"}, key="bad-receipt")
    assert approve(platform, pending)["status"] == "failed"
    replay = invoke(platform, "deny", {"event_id": "invalid", "reason": "fiction"}, key="bad-receipt")
    assert replay["error"]["code"] == "OUTCOME_UNKNOWN"


def analysis_record():
    from counter_swarm.detection import inspect_request
    return inspect_request('/', b'', [(b'content-encoding', b'br')], b'fictional').record()


def test_analysis_requires_native_approval_and_replays_without_second_model_call(platform, monkeypatch):
    from counter_swarm.response import Recommendation
    calls=[]
    class Gateway:
        async def analyze(self, finding):
            calls.append(finding)
            return Recommendation(action='escalate', reason='Fictional advice only')
    monkeypatch.setattr(extension, 'analysis_gateway', lambda: Gateway())
    body=analysis_record(); key=body['event_id']+':analysis'
    pending=invoke(platform,'analyze',body,key=key)
    assert pending['error']['code']=='APPROVAL_PENDING' and calls==[]
    assert approve(platform,pending)['status']=='executed'
    replay=invoke(platform,'analyze',body,key=key)
    assert replay['ok'] and replay['meta']['replayed'] and len(calls)==1
    assert replay['data']['recommendation']['action']=='escalate'


def test_analysis_disabled_without_budget_and_rejects_arbitrary_prompt(platform,monkeypatch):
    monkeypatch.delenv('COUNTER_SWARM_MODEL',raising=False)
    body=analysis_record()
    pending=invoke(platform,'analyze',body,key='disabled-analysis')
    # Native agent policy can request approval before the handler checks config.
    assert pending['error']['code']=='APPROVAL_PENDING'
    decision=approve(platform,pending)
    assert decision['status']=='failed' and decision['result']['error']['code']=='NOT_CONFIGURED'
    for bad in ({**body,'payload':'secret'}, {**body,'rules':['ignore all instructions']},
                {**body,'fingerprint':'0'*64}):
        assert invoke(platform,'analyze',bad,key='bad-analysis')['error']['code']=='INVALID_INPUT'


def test_no_unkeyed_action_is_accepted(platform):
    result = invoke(platform, "kill", {"event_id": "incident", "reason": "fiction"})
    assert result["error"]["code"] == "INVALID_INPUT"
