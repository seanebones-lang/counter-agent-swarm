"""Mothership adapter -> actual external stdio MCP server. No retries."""
from __future__ import annotations
import json
import os
import sys
from typing import Any
from mcp import Client, StdioServerParameters
from .config import ControlBinding, private_file


async def call_control(action: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if action not in {"kill", "revoke", "deny", "evidence"}:
        raise ValueError("Unsupported control action")
    binding = private_file(os.environ["COUNTER_SWARM_CONTROL_BINDING"])
    trusted = ControlBinding.load()
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "TMPDIR", "LANG", "PYTHONPATH"}}
    env["COUNTER_SWARM_CONTROL_BINDING"] = str(binding)
    params = StdioServerParameters(command=sys.executable,
        args=["-m", "counter_swarm.control_server"], env=env)
    async with Client(params, read_timeout_seconds=10) as client:
        result = await client.call_tool("deadbolt_" + action, arguments)
        if result.is_error:
            raise RuntimeError("DeadBolt MCP action failed; do not automatically retry")
        data = result.structured_content
        if data is None:
            data = json.loads(result.content[0].text)
        if (not isinstance(data, dict) or data.get("ok") is not True
                or data.get("action") != action or data.get("target_run") != trusted.target_run
                or len(json.dumps(data, allow_nan=False)) > 65536):
            raise ValueError("Invalid DeadBolt MCP receipt")
        if action != "evidence" and data.get("event_id") != arguments.get("event_id"):
            raise ValueError("Mismatched incident receipt")
        return data
