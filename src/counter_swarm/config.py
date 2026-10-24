"""Trusted operator bindings. Never populated from model output or request data."""
from __future__ import annotations
import json
import os
import stat
from pathlib import Path
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field


def private_file(path: str | Path) -> Path:
    p = Path(path)
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Expected an owner-only regular private file")
    if info.st_size > 65536:
        raise ValueError("Private file too large")
    return p


def loopback_origin(value: str) -> str:
    u = urlsplit(value)
    if (u.scheme != "http" or u.hostname not in {"127.0.0.1", "::1"} or not u.port
            or u.username or u.password or u.path not in {"", "/"} or u.query or u.fragment):
        raise ValueError("DeadBolt requires an explicit literal loopback HTTP origin")
    return value.rstrip("/")


class ControlBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    deadbolt_binary: str
    database: str
    events: str
    target_run: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,100}$")
    credential_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,100}$")
    forward_tool: str = Field(default="web.forward", pattern=r"^[a-z][a-z0-9_.-]{0,100}$")
    lease_ttl_seconds: int = Field(default=300, ge=1, le=3600)

    @classmethod
    def load(cls) -> "ControlBinding":
        p = private_file(os.environ["COUNTER_SWARM_CONTROL_BINDING"])
        return cls.model_validate_json(p.read_bytes())

    def child_env(self) -> dict[str, str]:
        # No model/provider credentials or operator HTTP token enter this process.
        result = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "TMPDIR", "LANG"}}
        result.update(DEADBOLT_DB=self.database, DEADBOLT_EVENTS=self.events)
        return result
