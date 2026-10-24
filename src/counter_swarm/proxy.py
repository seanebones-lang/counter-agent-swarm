"""Stateless edge proxy; detection/enforcement contain no model calls.

An event sink owns durable incident state outside the edge. It must be bound by
trusted deployment config, not a client-selected URL. Suspicious requests deny
even if the sink is down. Direct origin reachability bypasses this protection.
"""
from __future__ import annotations
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit
import asyncio
import json
import logging
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response
from .detection import MAX_BODY, Finding, inspect_request
from .gate import Gate

HOP = {"host", "connection", "proxy-connection", "keep-alive", "transfer-encoding",
       "te", "trailer", "upgrade", "proxy-authenticate", "proxy-authorization", "content-length"}


def create_proxy(upstream: str, gate: Gate,
                 sink: Callable[[Finding], Awaitable[None]]) -> FastAPI:
    parsed = urlsplit(upstream)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Configure one fixed upstream origin")
    fixed = httpx.URL(upstream.rstrip("/"))
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def forward(request: Request, path: str) -> Response:
        try:
            body = bytearray()
            async with asyncio.timeout(3):
                async for chunk in request.stream():
                    body.extend(chunk[:MAX_BODY + 1 - len(body)])
                    if len(body) > MAX_BODY:
                        break
            finding = inspect_request(request.url.path, request.scope.get("query_string", b""),
                                      request.headers.raw, bytes(body))
            if finding:
                try:
                    async with asyncio.timeout(1):
                        await sink(finding)
                except Exception:
                    # Fail closed regardless of telemetry availability.
                    logging.getLogger("counter_swarm").warning(json.dumps({
                        "event": "incident_delivery_failed", "event_id": finding.event_id,
                        "code": "INGRESS_UNAVAILABLE"}))
                return Response("Request blocked", status_code=403)
            if not await gate.admitted():
                return Response("Protection unavailable or access denied", status_code=503)
            raw_path = request.scope.get("raw_path", request.url.path.encode("utf8"))
            query = request.scope.get("query_string", b"")
            target = fixed.copy_with(raw_path=raw_path + (b"?" + query if query else b""))
            connection_headers = {v.strip().lower() for v in ",".join(request.headers.getlist("connection")).split(",")}
            headers = [(a, b) for a, b in request.headers.raw
                       if a.decode("latin1").lower() not in HOP | connection_headers | {"forwarded", "x-real-ip"}
                       and not a.decode("latin1").lower().startswith("x-forwarded-")]
            async with asyncio.timeout(10), httpx.AsyncClient(timeout=5, trust_env=False, follow_redirects=False) as client:
                async with client.stream(request.method, target, headers=headers, content=bytes(body)) as result:
                    output = bytearray()
                    async for chunk in result.aiter_raw():
                        output.extend(chunk[:2 * 1024 * 1024 + 1 - len(output)])
                        if len(output) > 2 * 1024 * 1024:
                            return Response("Upstream response exceeded limit", status_code=502)
                    response_connection = {v.strip().lower() for v in result.headers.get("connection", "").split(",")}
                    no_body = request.method == "HEAD" or result.status_code in {204, 304}
                    forwarded = Response(b"" if no_body else bytes(output), status_code=result.status_code)
                    # Preserve repeated Set-Cookie and other end-to-end headers.
                    forwarded.raw_headers = [(a, b) for a, b in result.headers.raw
                        if a.decode("latin1").lower() not in HOP | response_connection]
                    if no_body:
                        length = result.headers.get_list("content-length")
                        if result.status_code != 204 and len(length) == 1 and length[0].isascii() and length[0].isdigit():
                            forwarded.headers["content-length"] = length[0]
                    else:
                        forwarded.headers["content-length"] = str(len(output))
                    return forwarded
        except (TimeoutError, httpx.HTTPError, ValueError):
            return Response("Request could not be safely forwarded", status_code=503)

    return app
