"""Fresh DeadBolt admission. No cached allows, fallback or automatic lease creation."""
from __future__ import annotations
import asyncio
from pathlib import Path
import httpx
from .config import private_file, loopback_origin


class Gate:
    def __init__(self, origin: str, target_run: str, token_file: str | Path):
        self.origin = loopback_origin(origin)
        self.target_run = target_run
        self.token_file = token_file

    async def admitted(self) -> bool:
        try:
            token = private_file(self.token_file).read_text().strip()
            if not token or len(token) > 4096:
                return False
            async with asyncio.timeout(2), httpx.AsyncClient(timeout=1, trust_env=False, follow_redirects=False) as client:
                async with client.stream("POST", self.origin + "/admit-mcp",
                    headers={"X-Deadbolt-Admission": token},
                    json={"agent_id": self.target_run, "tool": "web.forward"}) as result:
                    if result.status_code != 200:
                        return False
                    raw = bytearray()
                    async for chunk in result.aiter_bytes():
                        raw.extend(chunk[:1025 - len(raw)])
                        if len(raw) > 1024:
                            return False
            import json
            return json.loads(raw) == {"decision": "allow"}
        except (OSError, ValueError, TimeoutError, httpx.HTTPError):
            return False
