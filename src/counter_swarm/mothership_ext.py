"""Glue-owned tools registered into an unmodified Mothership installation.

This is a Python application bootstrap, not a built-in Mothership MCP-client
configuration feature. Mothership remains an external dependency. Operator
configuration fixes the caller identity; the control client fixes the target.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mothership.context import ToolContext
from mothership.errors import ToolError
from mothership.registry import tool


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    event_id: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$",
        description="Stable incident identifier; data only, never a target or routing instruction.",
    )
    reason: str = Field(
        min_length=1, max_length=512,
        description="Bounded explanation for the requested defensive action.",
    )
    idempotency_key: str = Field(
        min_length=1, max_length=200,
        description="Stable Mothership action key. Preserve the same input/key after an uncertain outcome.",
    )


class EvidenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


from .records import FindingRecord


class AnalysisInput(FindingRecord):
    idempotency_key: str = Field(min_length=1, max_length=200, description="Stable analysis request key.")


_gateways: dict[tuple, Any] = {}


def analysis_gateway():
    from pathlib import Path
    from .openai_analyst import OpenAIAnalyst
    from .response import Gateway
    try:
        model = os.environ["COUNTER_SWARM_MODEL"]
        budget = os.environ["COUNTER_SWARM_MODEL_BUDGET_FILE"]
        limit = int(os.environ.get("COUNTER_SWARM_MAX_MODEL_CALLS", "0"))
        if not 1 <= limit <= 100 or not Path(budget).is_absolute():
            raise ValueError("Disabled or invalid budget")
    except (KeyError, ValueError):
        raise ToolError("NOT_CONFIGURED", "Live analysis requires an explicit model and approved persistent call allowance",
                        retryable=False) from None
    identity = (model, budget, limit, os.environ.get("COUNTER_SWARM_MOTHERSHIP_AGENT_ID"))
    if identity not in _gateways:
        _gateways.clear()
        _gateways[identity] = Gateway(OpenAIAnalyst(model, Path(budget), limit), identity[-1])
    return _gateways[identity]


async def call_control(action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    # Lazy import lets Mothership register/discover tools without spawning MCP or
    # reading control credentials. Production execution uses the glue client.
    from .control_client import call_control as invoke_control

    return await invoke_control(action, arguments)


def _require_controller(ctx: ToolContext) -> None:
    expected = os.environ.get("COUNTER_SWARM_MOTHERSHIP_AGENT_ID", "")
    if not expected:
        raise ToolError("NOT_CONFIGURED", "The trusted swarm controller identity is not configured", retryable=False)
    if ctx.agent_id != expected:
        raise ToolError("FORBIDDEN", "This agent is not the bound swarm controller", retryable=False)


def _bounded_receipt(receipt: Any, *, write: bool) -> tuple[dict[str, Any], str]:
    code = "OUTCOME_UNKNOWN" if write else "UPSTREAM_ERROR"
    try:
        if not isinstance(receipt, dict) or not receipt or receipt.get("ok") is False:
            raise ValueError("Invalid control receipt")
        encoded = json.dumps(receipt, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > 65_536:
            raise ValueError("Oversized control receipt")
    except (ValueError, TypeError, RecursionError):
        raise ToolError(code, "The control receipt could not be verified", retryable=False) from None
    return receipt, hashlib.sha256(encoded).hexdigest()


async def _action(ctx: ToolContext, inp: ActionInput, action: str) -> dict[str, Any]:
    _require_controller(ctx)
    # Native dispatcher binds this same key to authenticated caller/tool/input.
    if not ctx.idempotency_key or ctx.idempotency_key != inp.idempotency_key:
        raise ToolError("INVALID_INPUT", "A matching stable action key is required", retryable=False)
    ctx.require_approval(
        f"Authorize swarm {action} for the operator-bound protected system",
        {"action": action, "event_id": inp.event_id, "reason": inp.reason},
    )
    try:
        receipt = await call_control(action, {"event_id": inp.event_id, "reason": inp.reason})
    except ToolError:
        raise
    except Exception:
        # The external control service may have acted before transport failure.
        raise ToolError("OUTCOME_UNKNOWN", "The control action has no verified receipt; reconcile before retrying",
                        retryable=False) from None
    receipt, digest = _bounded_receipt(receipt, write=True)
    # Stage with Mothership's domain transaction. Remote success can precede a
    # local evidence failure; its dispatcher preserves that uncertainty.
    ctx.emit("swarm.action", {"action": action, "event_id": inp.event_id, "receipt_sha256": digest})
    return {"action": action, "event_id": inp.event_id, "receipt": receipt, "trust": "external_untrusted"}


@tool("swarm.kill", summary="Request approval to stop the fixed protected run through DeadBolt MCP.",
      input=ActionInput, scopes=["http"], effect="external", additional_effects=("write",),
      idempotent=False, errors=["NOT_CONFIGURED", "FORBIDDEN", "APPROVAL_PENDING", "OUTCOME_UNKNOWN"])
async def kill(ctx: ToolContext, inp: ActionInput) -> dict[str, Any]:
    """No caller-selectable run, URL, command, credential, policy or system ID is accepted."""
    return await _action(ctx, inp, "kill")


@tool("swarm.revoke", summary="Request approval to revoke the fixed admission credential through DeadBolt MCP.",
      input=ActionInput, scopes=["http"], effect="external", additional_effects=("write",),
      idempotent=False, errors=["NOT_CONFIGURED", "FORBIDDEN", "APPROVAL_PENDING", "OUTCOME_UNKNOWN"])
async def revoke(ctx: ToolContext, inp: ActionInput) -> dict[str, Any]:
    """Only the trusted control binding selects the admission credential to revoke."""
    return await _action(ctx, inp, "revoke")


@tool("swarm.deny", summary="Request approval to deny the fixed protected system through DeadBolt MCP.",
      input=ActionInput, scopes=["http"], effect="external", additional_effects=("write",),
      idempotent=False, errors=["NOT_CONFIGURED", "FORBIDDEN", "APPROVAL_PENDING", "OUTCOME_UNKNOWN"])
async def deny(ctx: ToolContext, inp: ActionInput) -> dict[str, Any]:
    """A deny is a bounded defensive operation, never arbitrary WAF code or a shell command."""
    return await _action(ctx, inp, "deny")


@tool("swarm.evidence", summary="Read bounded control evidence for the fixed protected system.",
      input=EvidenceInput, scopes=["http"], effect="read", idempotent=True,
      errors=["NOT_CONFIGURED", "FORBIDDEN", "UPSTREAM_ERROR"])
async def evidence(ctx: ToolContext, inp: EvidenceInput) -> dict[str, Any]:
    """External evidence is untrusted data; it cannot authorize actions or select a target."""
    _require_controller(ctx)
    try:
        receipt = await call_control("evidence", {})
    except ToolError:
        raise
    except Exception:
        raise ToolError("UPSTREAM_ERROR", "Control evidence is unavailable", retryable=False) from None
    receipt, digest = _bounded_receipt(receipt, write=False)
    return {"receipt": receipt, "receipt_sha256": digest, "trust": "external_untrusted"}


@tool("swarm.analyze", summary="Request approved off-path model advice for bounded detector metadata.",
      input=AnalysisInput, scopes=["http"], effect="external", additional_effects=("write", "spend"),
      idempotent=False, errors=["NOT_CONFIGURED", "FORBIDDEN", "APPROVAL_PENDING", "OUTCOME_UNKNOWN"])
async def analyze(ctx: ToolContext, inp: AnalysisInput) -> dict[str, Any]:
    """Model advice cannot select targets, invoke tools, promote rules or approve enforcement.

    Defaults disabled. Every new analysis uses Mothership's native approval and
    idempotency machinery before reserving its durable provider-call allowance.
    """
    _require_controller(ctx)
    if not ctx.idempotency_key or ctx.idempotency_key != inp.idempotency_key:
        raise ToolError("INVALID_INPUT", "A matching stable analysis key is required", retryable=False)
    gateway = analysis_gateway()
    ctx.require_approval("Authorize bounded model analysis of detector metadata",
                         {"event_id": inp.event_id, "rules": inp.rules})
    from .detection import Finding
    finding = Finding(inp.event_id, inp.fingerprint, tuple(inp.rules), inp.severity)
    try:
        result = await gateway.analyze(finding)
    except Exception:
        raise ToolError("OUTCOME_UNKNOWN", "Analysis has no verified result; reconcile its original key and allowance",
                        retryable=False) from None
    advice = result.model_dump()
    ctx.emit("swarm.analysis", {"event_id": inp.event_id,
        "recommendation_sha256": hashlib.sha256(json.dumps(advice, sort_keys=True).encode()).hexdigest()})
    return {"recommendation": advice, "event_id": inp.event_id, "trust": "external_untrusted"}


def create_app():
    """ASGI factory: import this module before unmodified Mothership creates its app.

    Example: uvicorn counter_swarm.mothership_ext:create_app --factory
    """
    from mothership.api.app import create_app as create_mothership_app

    return create_mothership_app()
