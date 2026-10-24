"""Operator-only per-system process entry points. No automatic effect retries."""
from __future__ import annotations
import argparse
import asyncio
import hmac
import json
import os
from pathlib import Path
import sys
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .config import private_file, loopback_origin
from .detection import Finding
from .gate import Gate
from .incident_queue import IncidentQueue
from .proxy import create_proxy
from .records import FindingRecord
from .response import Recommendation, respond


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    upstream: str
    gate_origin: str
    target_run: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,100}$")
    admission_token_file: str
    ingress_origin: str = "http://127.0.0.1:9784"
    ingress_token_file: str
    queue_file: str
    mothership_origin: str
    mothership_agent_key_file: str
    live_analysis: bool = False

    @field_validator("gate_origin", "ingress_origin", "mothership_origin")
    @classmethod
    def fixed_loopback(cls, value):
        return loopback_origin(value)

    @classmethod
    def load(cls):
        value = cls.model_validate_json(private_file(os.environ["COUNTER_SWARM_RUNTIME_CONFIG"]).read_bytes())
        return value


def credential(path: str) -> str:
    value = private_file(path).read_text().strip()
    if not 16 <= len(value) <= 4096:
        raise ValueError("Missing or invalid private credential")
    return value


def create_ingress(config: RuntimeConfig) -> FastAPI:
    queue = IncidentQueue(Path(config.queue_file))
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/incidents")
    async def ingest(request: Request):
        if not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + credential(config.ingress_token_file)):
            return JSONResponse({"code": "FORBIDDEN"}, status_code=403)
        body = bytearray()
        try:
            async with asyncio.timeout(1):
                async for chunk in request.stream():
                    body.extend(chunk[:4097 - len(body)])
                    if len(body) > 4096:
                        return JSONResponse({"code": "INVALID_INPUT"}, status_code=413)
            value = FindingRecord.model_validate_json(body).model_dump()
            await asyncio.to_thread(queue.put, value)
            return JSONResponse({"accepted": True}, status_code=202)
        except (ValueError, TimeoutError):
            return JSONResponse({"code": "INVALID_INPUT"}, status_code=400)
        except Exception:
            return JSONResponse({"code": "QUEUE_UNAVAILABLE"}, status_code=503)
    return app


def configured_ingress():
    return create_ingress(RuntimeConfig.load())


def configured_proxy():
    config = RuntimeConfig.load()

    async def sink(finding):
        async with asyncio.timeout(0.9), httpx.AsyncClient(timeout=0.7, trust_env=False, follow_redirects=False) as client:
            async with client.stream("POST", config.ingress_origin + "/incidents",
                    headers={"Authorization": "Bearer " + credential(config.ingress_token_file)},
                    json=finding.record()) as result:
                if result.status_code != 202:
                    raise RuntimeError("Incident delivery failed")
    return create_proxy(config.upstream, Gate(config.gate_origin, config.target_run, config.admission_token_file), sink)


def process_one(queue: IncidentQueue, client, *, live_analysis=False, resume: str | None = None):
    from mothership.sdk import MothershipError
    row = queue.claim(resume)
    if row is None:
        return {"status": "idle"}
    event_id = row["id"]
    record = row["record"]
    finding = Finding(record["event_id"], record["fingerprint"], tuple(record["rules"]), record["severity"])
    phase = "evidence"
    try:
        recommendation = None
        if resume:
            phase = row["phase"]
            result = client.wait_for_approval(row["approval"], timeout=1)
            if phase == "action":
                if result.get("event_id") != event_id or result.get("action") not in {"kill", "deny", "revoke"}:
                    raise ValueError("Unverified control result")
                queue.mark(event_id, "completed", code="ACTION_RECEIPT")
                return {"status": "completed", "event_id": event_id}
            if phase == "checkpoint":
                if result.get("task_id") != event_id:
                    raise ValueError("Unverified checkpoint result")
                queue.mark(event_id, "completed", code="ESCALATED")
                return {"status": "escalated", "event_id": event_id}
            if phase == "evidence":
                if result.get("key") != "incident." + event_id or result.get("namespace") != "swarm":
                    raise ValueError("Unverified evidence result")
            elif phase == "analysis":
                if result.get("event_id") != event_id:
                    raise ValueError("Unverified analysis result")
                recommendation = Recommendation.model_validate(result["recommendation"])
            else:
                raise ValueError("Unrecognized approval phase")
        else:
            client.call("memory.put", {"key": "incident." + event_id, "value": record, "namespace": "swarm"},
                        idempotency_key=event_id + ":evidence")
        if recommendation is None and live_analysis:
            phase = "analysis"
            result = client.call("swarm.analyze", record, idempotency_key=event_id + ":analysis")
            if result.get("event_id") != event_id:
                raise ValueError("Unverified analysis result")
            recommendation = Recommendation.model_validate(result["recommendation"])
        elif recommendation is None:
            recommendation = Recommendation(action="escalate", reason="Live model analysis disabled; operator investigation required")
        phase = "checkpoint" if recommendation.action in {"sandbox", "escalate"} else "action"
        outcome = respond(client, finding, recommendation, record_evidence=False)
        if outcome["status"] == "blocked":
            error = outcome["error"]
            queue.mark(event_id, "pending" if error["code"] == "APPROVAL_PENDING" else "held", phase=phase,
                       approval=error.get("details", {}).get("approval_id"), code=error["code"])
        else:
            queue.mark(event_id, "completed", code=outcome["status"].upper())
        return {"status": outcome["status"], "event_id": event_id}
    except MothershipError as error:
        if error.code == "WAIT_TIMEOUT" and resume:
            queue.mark(event_id, "pending", phase=phase, approval=row["approval"], code=error.code)
        else:
            queue.mark(event_id, "pending" if error.code == "APPROVAL_PENDING" else "held", phase=phase,
                       approval=error.details.get("approval_id"), code=error.code)
        return {"status": "pending" if error.code in {"APPROVAL_PENDING", "WAIT_TIMEOUT"} else "held", "event_id": event_id, "code": error.code}
    except Exception:
        # No exception message/raw data in logs. Never automatically requeue.
        queue.mark(event_id, "held", phase=phase, code="OUTCOME_UNKNOWN")
        return {"status": "held", "event_id": event_id, "code": "OUTCOME_UNKNOWN"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["work", "resume", "status"])
    parser.add_argument("--event-id")
    args = parser.parse_args()
    try:
        config = RuntimeConfig.load()
        queue = IncidentQueue(Path(config.queue_file))
        if args.command == "status":
            result = queue.status()
        else:
            if args.command == "resume" and not args.event_id:
                parser.error("resume requires the original --event-id")
            from mothership.sdk import Client
            with Client(config.mothership_origin, credential(config.mothership_agent_key_file),
                        timeout=30, max_retries=0, auto_wait_approvals=False,
                        transport=httpx.HTTPTransport(trust_env=False)) as client:
                result = process_one(queue, client, live_analysis=config.live_analysis,
                                     resume=args.event_id if args.command == "resume" else None)
        print(json.dumps(result))
    except Exception:
        print(json.dumps({"status": "failed", "code": "CONFIG_OR_STORE_UNAVAILABLE"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
