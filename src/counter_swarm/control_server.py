"""A fixed-target stdio MCP control facade over the real external DeadBolt CLI.

Only the trusted Mothership process may launch this stdio server. Do not expose
it as an unauthenticated network server. It owns no lease provisioning tools.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
from typing import Annotated, Any
from pydantic import BaseModel, ConfigDict, Field
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from .config import ControlBinding

MAX_OUTPUT = 49152
Reason = Annotated[str, Field(min_length=1, max_length=512, description="Bounded rationale; data, not commands.")]
EventID = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$", description="Stable incident ID; never routing authority.")]


class Effect(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    reason: str = Field(min_length=1, max_length=512)
    event_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")


async def command(binding: ControlBinding, *args: str) -> bytes:
    process = await asyncio.create_subprocess_exec(
        binding.deadbolt_binary, "--lease-ttl-secs", str(binding.lease_ttl_seconds), *args,
        env=binding.child_env(), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        async with asyncio.timeout(5):
            output = bytearray()
            while chunk := await process.stdout.read(4096):
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise RuntimeError("DeadBolt output exceeded the bounded evidence limit")
            code = await process.wait()
            if code:
                raise RuntimeError("DeadBolt command failed; reconcile any uncertain effect")
            return bytes(output)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


def build_server() -> MCPServer:
    server = MCPServer("counter_deadbolt", version="0.1.0")

    async def act(action: str, reason: str, event_id: str) -> dict[str, Any]:
        effect = Effect(reason=reason, event_id=event_id)
        binding = ControlBinding.load()
        args = {"kill": ["kill", "--agent", binding.target_run],
                "revoke": ["credential", "revoke", "--id", binding.credential_id],
                "deny": ["clip", "--agent", binding.target_run, binding.forward_tool]}[action]
        await command(binding, *args)
        return {"ok": True, "action": action, "event_id": effect.event_id,
                "target_run": binding.target_run, "scope": "next-admission-only",
                "reason_sha256": hashlib.sha256(effect.reason.encode()).hexdigest()}

    annotations = ToolAnnotations(read_only_hint=False, destructive_hint=True,
                                  idempotent_hint=False, open_world_hint=False)

    @server.tool(name="deadbolt_kill", annotations=annotations)
    async def kill(reason: Reason, event_id: EventID) -> dict[str, Any]:
        """Kill only the operator-bound run. Does not stop already-running actions."""
        return await act("kill", reason, event_id)

    @server.tool(name="deadbolt_revoke", annotations=annotations)
    async def revoke(reason: Reason, event_id: EventID) -> dict[str, Any]:
        """Revoke the bound admission credential; no other run or credential can be selected."""
        return await act("revoke", reason, event_id)

    @server.tool(name="deadbolt_deny", annotations=annotations)
    async def deny(reason: Reason, event_id: EventID) -> dict[str, Any]:
        """Clip the bound forwarding tool. Reopening it requires a separate trusted operator."""
        return await act("deny", reason, event_id)

    @server.tool(name="deadbolt_evidence", annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False))
    async def evidence() -> dict[str, Any]:
        """Read bounded external DeadBolt evidence for the fixed run; not independent custody."""
        binding = ControlBinding.load()
        raw = await command(binding, "export", "--agent", binding.target_run)
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        return {"ok": True, "action": "evidence", "target_run": binding.target_run,
                "records": records[-50:], "trust": "external_untrusted", "truncated": len(records) > 50}

    return server


def main() -> None:
    # Validate before protocol startup; no host's default DeadBolt store fallback.
    ControlBinding.load()
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
