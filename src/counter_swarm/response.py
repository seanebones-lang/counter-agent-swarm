"""Off-path response orchestration through unmodified Mothership APIs.

An Analyst is injected by the trusted operator. Live analysis belongs inside
the Mothership swarm.analyze tool. Analysis cannot approve its own action.
"""
from __future__ import annotations
import hashlib
import json
import time
from typing import Any, Literal, Protocol
from pydantic import BaseModel, ConfigDict, Field
from .detection import Finding


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["kill", "deny", "revoke", "sandbox", "escalate"]
    reason: str = Field(min_length=1, max_length=512)


class Analyst(Protocol):
    async def analyze(self, evidence: dict[str, Any]) -> Recommendation: ...


class Gateway:
    """Bounded exact-feature cache; no cached admissions or approximate decisions.

    Similarity can be used to retrieve examples, never to reuse authority across
    distinct payloads, protected systems or policy revisions.
    """
    def __init__(self, analyst: Analyst, system_id: str, ttl: int = 60):
        self.analyst, self.system_id, self.ttl = analyst, system_id, ttl
        self.cache: dict[str, tuple[float, Recommendation]] = {}

    async def analyze(self, finding: Finding) -> Recommendation:
        record = finding.record()
        key = hashlib.sha256(json.dumps([self.system_id, record], sort_keys=True).encode()).hexdigest()
        if key in self.cache and time.monotonic() < self.cache[key][0]:
            return self.cache[key][1]
        if len(self.cache) >= 256:
            self.cache.clear()
        result = await self.analyst.analyze(record)
        if not isinstance(result, Recommendation):
            raise ValueError("Analyst must return a validated recommendation")
        self.cache[key] = (time.monotonic() + self.ttl, result)
        return result


class EscalateOnly:
    async def analyze(self, evidence: dict[str, Any]) -> Recommendation:
        return Recommendation(action="escalate", reason="No live analyst configured; operator investigation required")


def respond(client, finding: Finding, recommendation: Recommendation, *, record_evidence: bool = True) -> dict[str, Any]:
    """Runs off-path. client is the existing Mothership SDK Client, retries=0.

    Returns native APPROVAL_PENDING unchanged. Owner approval/reconciliation is
    separate and never performed by this function or the model.
    """
    from mothership.sdk import MothershipError
    record = finding.record()
    if record_evidence:
        client.call("memory.put", {"key": "incident." + finding.event_id,
                    "value": record, "namespace": "swarm"},
                    idempotency_key=finding.event_id + ":evidence")
    if recommendation.action in {"sandbox", "escalate"}:
        client.call("memory.checkpoint_save", {"task_id": finding.event_id,
                    "status": "blocked", "state": {"recommendation": recommendation.model_dump(),
                    "trust": "external_untrusted"}}, idempotency_key=finding.event_id + ":checkpoint")
        return {"status": "escalated", "action": recommendation.action, "event_id": finding.event_id}
    key = finding.event_id + ":" + recommendation.action
    try:
        data = client.call("swarm." + recommendation.action,
            {"event_id": finding.event_id, "reason": recommendation.reason}, idempotency_key=key)
        return {"status": "executed", "data": data}
    except MothershipError as error:
        return {"status": "blocked", "error": {"code": error.code, "details": error.details},
                "idempotency_key": key}
