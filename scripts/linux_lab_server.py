#!/usr/bin/env python3
"""Private operator-hosted, fixed-scenario integration lab; never a public service.

The tester chooses scenarios and advances observations. A separate operator
credential decides native approvals. No engine source, shell, paths, URLs or
credentials are accepted as tester input or returned as test output.
"""
from __future__ import annotations

import argparse
from contextlib import asynccontextmanager
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Literal
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
import uvicorn

from counter_swarm.config import private_file

Scenario = Literal["kill", "deny", "revoke", "reject_approval", "restart_pending", "unavailable"]
STEPS = {"ready", "healthy", "detected"}


def native_runner(*args, **kwargs):
    from acceptance import run_acceptance
    return run_acceptance(*args, **kwargs)


class Start(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scenario: Scenario


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    revision: int = Field(ge=0, le=100)


class Approval(Step):
    approve: bool


class LabStopped(Exception):
    pass


class Run:
    def __init__(self, scenario: str):
        self.id = str(uuid4())
        self.scenario = scenario
        self.phase = "starting"
        self.revision = 0
        self.command = None
        self.cancelled = False
        self.facts = {}
        self.history = []
        self.receipt = None
        self.condition = threading.Condition()

    def view(self):
        with self.condition:
            return {"run_id": self.id, "scenario": self.scenario, "phase": self.phase,
                    "revision": self.revision, "facts": self.facts,
                    "observations": list(self.history), "receipt": self.receipt,
                    "live_model_calls": 0, "private_runtime_download": False}

    def observe(self, phase, facts, timeout):
        with self.condition:
            self.phase, self.facts = phase, dict(facts)
            self.revision += 1
            self.command = None
            self.history.append({"phase": phase, "facts": dict(facts), "revision": self.revision})
            if not self.condition.wait_for(lambda: self.command is not None or self.cancelled,
                                           timeout=timeout):
                raise LabStopped("Timed out waiting for an explicit next step")
            if self.cancelled:
                raise LabStopped("Run cancelled")
            command = self.command
            self.command = None
            self.phase = "running"
            return command if phase == "approval_pending" else None

    def advance(self, revision, command, *, operator=False):
        with self.condition:
            if revision != self.revision or self.command is not None or self.cancelled:
                raise HTTPException(409, "Stale step or completed decision; refresh status")
            if operator:
                if self.phase != "approval_pending":
                    raise HTTPException(409, "No native approval is pending")
                if command != (self.scenario != "reject_approval"):
                    raise HTTPException(409, "Decision conflicts with this fixed test scenario")
            elif self.phase not in STEPS:
                raise HTTPException(409, "Tester cannot decide approvals or advance this phase")
            self.command = command
            self.phase = "advancing"
            self.condition.notify_all()

    def cancel(self):
        with self.condition:
            self.cancelled = True
            self.condition.notify_all()


class Lab:
    def __init__(self, binary, tester_token, operator_token, manifest, *, lifetime=1800,
                 step_timeout=45, run_limit=24, runner=native_runner, error_log=None):
        if (len(tester_token) < 32 or len(operator_token) < 32 or
                hmac.compare_digest(tester_token, operator_token)):
            raise ValueError("Distinct high-entropy tester and operator credentials required")
        self.binary, self.tester_token, self.operator_token = binary, tester_token, operator_token
        self.manifest, self.runner = manifest, runner
        self.deadline = time.monotonic() + lifetime
        self.step_timeout, self.run_limit = step_timeout, run_limit
        self.runs = {}
        self.lock = threading.Lock()
        self.active = None
        self.threads = []
        self.closed = False
        self.error_log = error_log

    def authenticate(self, request, operator=False):
        if self.closed or time.monotonic() >= self.deadline:
            raise HTTPException(410, "Lab session expired; ask the operator for a new session")
        supplied = request.headers.get("authorization", "")
        expected = self.operator_token if operator else self.tester_token
        if not hmac.compare_digest(supplied.encode(), ("Bearer " + expected).encode()):
            raise HTTPException(403, "Correct session role credential required")

    def get(self, run_id):
        with self.lock:
            run = self.runs.get(str(run_id))
        if run is None:
            raise HTTPException(404, "Unknown run")
        return run

    def start(self, scenario):
        with self.lock:
            if self.closed:
                raise HTTPException(410, "Lab closed")
            if self.active is not None:
                raise HTTPException(409, "One run at a time; finish or cancel the current run")
            if len(self.runs) >= self.run_limit:
                raise HTTPException(429, "Session run budget exhausted")
            run = Run(scenario)
            self.runs[run.id] = run
            self.active = run.id
            thread = threading.Thread(target=self.execute, args=(run,), daemon=True)
            self.threads.append(thread)
            thread.start()
        return run.view()

    def execute(self, run):
        try:
            receipt = self.runner(self.binary, scenario=run.scenario,
                observer=lambda phase, facts: run.observe(phase, facts, self.step_timeout))
            with run.condition:
                run.receipt = receipt
                run.phase = "passed"
        except LabStopped:
            with run.condition:
                run.phase = "cancelled" if run.cancelled else "timed_out"
        except Exception:
            if self.error_log is not None:
                import traceback
                try:
                    fd = os.open(self.error_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                    with os.fdopen(fd, "w") as stream:
                        stream.write(traceback.format_exc()[-8192:]+"\n")
                except OSError:
                    pass  # Evidence failure must not leave the run falsely active.
            # Do not expose exception strings, stack traces, engine paths or secrets.
            with run.condition:
                run.phase = "failed"
                run.facts = {"code": "INTEGRATION_FAILED", "next_action": "Operator reviews local lab"}
        finally:
            with self.lock:
                self.active = None

    def close(self):
        with self.lock:
            self.closed = True
            runs, threads = list(self.runs.values()), list(self.threads)
        for run in runs:
            run.cancel()
        for thread in threads:
            thread.join(timeout=35)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError("Lab worker did not stop; remove the disposable container")


def create_app(lab: Lab):
    @asynccontextmanager
    async def lifespan(_):
        yield
        lab.close()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def bounded(request: Request, call_next):
        from starlette.responses import JSONResponse
        if request.headers.get("origin"):
            return JSONResponse({"detail": "Browser-origin requests are not supported"}, status_code=403)
        role_operator = request.url.path.startswith("/operator/")
        try:
            lab.authenticate(request, operator=role_operator)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        if request.method == "POST":
            import asyncio
            body = bytearray()
            try:
                async with asyncio.timeout(2):
                    async for chunk in request.stream():
                        body.extend(chunk[:2049-len(body)])
                        if len(body) > 2048:
                            return JSONResponse({"detail": "Body too large"}, status_code=413)
            except TimeoutError:
                return JSONResponse({"detail": "Body deadline exceeded"}, status_code=408)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/plan")
    def plan():
        return {"scope": "native-engines-synthetic-integration", "manifest": lab.manifest,
                "scenarios": list(Scenario.__args__), "step_timeout_seconds": lab.step_timeout,
                "approval_role": "separate operator", "live_model_calls": 0,
                "private_runtime_download": False}

    @app.post("/runs", status_code=202)
    def start(value: Start):
        return lab.start(value.scenario)

    @app.get("/runs/{run_id}")
    def status(run_id: UUID):
        return lab.get(run_id).view()

    @app.post("/runs/{run_id}/step")
    def step(run_id: UUID, value: Step):
        run = lab.get(run_id)
        run.advance(value.revision, "step")
        return {"accepted": True}

    @app.post("/runs/{run_id}/cancel")
    def cancel(run_id: UUID):
        lab.get(run_id).cancel()
        return {"cancellation_requested": True}

    @app.get("/operator/runs/{run_id}")
    def operator_status(run_id: UUID):
        return lab.get(run_id).view()

    @app.post("/operator/runs/{run_id}/approval")
    def approval(run_id: UUID, value: Approval):
        run = lab.get(run_id)
        run.advance(value.revision, value.approve, operator=True)
        return {"decision_accepted": True}

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deadbolt", required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--container", action="store_true",
                        help="Bind container port; operator must publish it on host loopback only")
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error("Run the lab as an ordinary user")
    os.umask(0o077)
    Path(os.environ.get("HOME", "/tmp/home")).mkdir(mode=0o700, parents=True, exist_ok=True)
    credentials = json.loads(private_file(args.credentials).read_bytes())
    manifest = json.loads(args.manifest.read_bytes())
    lab = Lab(args.deadbolt, credentials["tester"], credentials["operator"], manifest,
              error_log=Path(os.environ["HOME"])/"lab-errors.log")
    uvicorn.run(create_app(lab), host="0.0.0.0" if args.container else "127.0.0.1", port=8765,
                access_log=False, log_level="error", limit_concurrency=16, timeout_keep_alive=2)


if __name__ == "__main__":
    main()
